package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
)

type Conn struct {
	udpConn  *net.UDPConn
	quicConn *quic.Conn
}

type Client struct {
	relayUrl      string
	authToken     string
	serverID      string
	cert          *tls.Certificate
	fingerprint   string
	punchInterval time.Duration
	punchAttempts int
	punchSleep    time.Duration
}

func NewClient(relayUrl string, authToken string, serverID string) (*Client, error) {
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	fingerprint := CertFingerprint(cert)

	return &Client{
		relayUrl:      relayUrl,
		authToken:     authToken,
		serverID:      serverID,
		cert:          cert,
		fingerprint:   fingerprint,
		punchInterval: 10 * time.Millisecond,
		punchAttempts: 300,
		punchSleep:    50 * time.Millisecond,
	}, nil
}

func (c *Client) connect(ctx context.Context) (*Conn, error) {
	slog.Info("requesting tunnel", "server_id", c.serverID, "fingerprint", c.fingerprint)

	url := c.relayUrl + "/client"
	header := http.Header{}
	if c.authToken != "" {
		header.Set("Authorization", "Token "+c.authToken)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	wsConn, _, err := dialer.Dial(url, header)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer wsConn.Close()

	reqValue, err := json.Marshal(&WSMessageTunnelRequest{
		ID:                c.serverID,
		ClientFingerprint: c.fingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tunnel request: %w", err)
	}

	err = wsConn.WriteJSON(WSMessage{
		Type:  WSMessageTypeTunnelRequest,
		Value: reqValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send tunnel request: %w", err)
	}

	msg := &WSMessage{}
	err = wsConn.ReadJSON(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}
	if msg.Type != WSMessageTypePunchRequest {
		return nil, fmt.Errorf("expected punch request, got: %s", msg.Type)
	}
	pReq := &WSMessagePunchRequest{}
	err = json.Unmarshal(msg.Value, pReq)
	if err != nil {
		return nil, fmt.Errorf("invalid punch request payload: %w", err)
	}
	slog.Info("received punch request", "token", pReq.Token, "punch_server_address", pReq.PunchServerAddress)

	udpConn, err := c.punchRequest(pReq)
	if err != nil {
		return nil, fmt.Errorf("failed to handle punch request: %w", err)
	}

	err = wsConn.ReadJSON(msg)
	if msg.Type != WSMessageTypeStartTunnel {
		return nil, fmt.Errorf("expected start tunnel message, got: %s", msg.Type)
	}
	startTunnel := &WSMessageStartTunnel{}
	err = json.Unmarshal(msg.Value, startTunnel)
	if err != nil {
		return nil, fmt.Errorf("invalid start tunnel payload: %w", err)
	}
	slog.Info("received start tunnel message", "peer_address", startTunnel.PeerAddress, "peer_fingerprint", startTunnel.PeerFingerprint)

	serverAddr, err := net.ResolveUDPAddr("udp", startTunnel.PeerAddress)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	go func() {
		err := startUDPPunch(udpConn, serverAddr, []byte("punch request"), c.punchAttempts, c.punchInterval)
		if err != nil {
			slog.Error("UDP punch failed", "error", err)
		}
	}()
	time.Sleep(c.punchSleep)

	slog.Info("dialing server via QUIC", "server_address", serverAddr.String())
	tlsConf := &tls.Config{
		Certificates:          []tls.Certificate{*c.cert},
		InsecureSkipVerify:    true, // We verify via fingerprint instead of CA chain
		NextProtos:            []string{"quic-link"},
		ServerName:            "quic-link",
		VerifyPeerCertificate: VerifyPeerCert(startTunnel.PeerFingerprint),
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 1 * time.Second,
	}
	transport := &quic.Transport{
		Conn: udpConn,
	}
	conn, err := transport.Dial(ctx, serverAddr, tlsConf, quicConf)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}

	slog.Info("QUIC connection established", "remote_addr", conn.RemoteAddr().String())

	return &Conn{
		udpConn:  udpConn,
		quicConn: conn,
	}, nil
}

func (c *Client) punchRequest(msg *WSMessagePunchRequest) (*net.UDPConn, error) {
	slog.Info("received punch request", "token", msg.Token, "punch_server_address", msg.PunchServerAddress)

	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set UDP read deadline: %w", err)
	}

	slog.Info("UDP listener started on", "address", conn.LocalAddr().String())

	addr, err := net.ResolveUDPAddr("udp", msg.PunchServerAddress)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	slog.Info("sending UDP punch", "token", msg.Token, "relay_address", addr.String())
	go func() {
		err := startUDPPunch(conn, addr, []byte(msg.Token), c.punchAttempts, c.punchInterval)
		if err != nil {
			slog.Error("UDP punch failed", "error", err)
		}
	}()

	return conn, nil
}

func (c *Client) Start(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.udpConn.Close()
	defer conn.quicConn.CloseWithError(0, "done")

	stream, err := conn.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	slog.Info("stream opened, reading from stdin and writing to stdout")

	syncCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Read from server and write to stdout
	go func() {
		defer cancel()

		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Error("error reading from stream", "error", err)
				}
				slog.Info("stream closed by server")
				return
			}

			b64 := base64.StdEncoding.EncodeToString(buf[:n])
			slog.Debug("received data from server", "size", n, "base64", b64)

			for written := 0; written < n; {
				m, err := os.Stdout.Write(buf[written:n])
				if err != nil {
					slog.Error("error writing to stdout", "error", err)
					return
				}
				written += m
			}
		}
	}()

	// Read from stdin and write to server
	go func() {
		defer cancel()

		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Error("error reading from stdin", "error", err)
				}
				slog.Info("stdin closed")
				return
			}

			b44 := base64.StdEncoding.EncodeToString(buf[:n])
			slog.Debug("read data from stdin", "size", n, "base64", b44)

			for written := 0; written < n; {
				m, err := stream.Write(buf[written:n])
				if err != nil {
					slog.Error("error writing to stream", "error", err)
					return
				}
				written += m
			}
		}
	}()

	<-syncCtx.Done()

	slog.Info("client shutting down")

	return nil
}
