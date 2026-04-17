package main

import (
	"bytes"
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

	quic "github.com/quic-go/quic-go"
)

type Conn struct {
	udpConn  *net.UDPConn
	quicConn *quic.Conn
}

type Client struct {
	relayUrl    string
	authToken   string
	serverID    string
	client      *http.Client
	cert        *tls.Certificate
	fingerprint string
}

func NewClient(relayUrl string, authToken string, serverID string) (*Client, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	fingerprint := CertFingerprint(cert)

	return &Client{
		relayUrl:    relayUrl,
		authToken:   authToken,
		serverID:    serverID,
		client:      client,
		cert:        cert,
		fingerprint: fingerprint,
	}, nil
}

func (c *Client) connect(ctx context.Context) (*Conn, error) {
	slog.Info("requesting tunnel", "server_id", c.serverID, "fingerprint", c.fingerprint)

	// Request tunnel from relay
	resp, err := c.requestTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to request tunnel: %w", err)
	}

	slog.Info("tunnel response received", "address", resp.Address, "server_fingerprint", resp.ServerFingerprint)

	slog.Info("connecting to server", "address", resp.Address)

	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	transport := &quic.Transport{
		Conn: udpConn,
	}

	serverAddr, err := net.ResolveUDPAddr("udp", resp.Address)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	tlsConf := &tls.Config{
		Certificates:          []tls.Certificate{*c.cert},
		InsecureSkipVerify:    true, // We verify via fingerprint instead of CA chain
		NextProtos:            []string{"quic-link"},
		ServerName:            "quic-link",
		VerifyPeerCertificate: VerifyPeerCert(resp.ServerFingerprint),
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 1 * time.Second,
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

func (c *Client) requestTunnel(ctx context.Context) (*WSMessageClientTunnelResponse, error) {
	reqValue, err := json.Marshal(&WSMessageClientTunnelRequest{
		ID:          c.serverID,
		Fingerprint: c.fingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tunnel request: %w", err)
	}

	reqBody, err := json.Marshal(&WSMessage{
		Type:  WSMessageTypeClientTunnelRequest,
		Value: reqValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	url := c.relayUrl + "/client"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Token "+c.authToken)

	httpResp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("relay returned status %d: %s", httpResp.StatusCode, string(body))
	}

	msg := &WSMessage{}
	err = json.NewDecoder(httpResp.Body).Decode(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if msg.Type != WSMessageTypeClientTunnelResponse {
		return nil, fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	resp := &WSMessageClientTunnelResponse{}
	err = json.Unmarshal(msg.Value, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tunnel response: %w", err)
	}

	return resp, nil
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
