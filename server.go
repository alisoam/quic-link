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
	"time"

	"github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
)

type Server struct {
	relayURL     string
	authToken    string
	id           string
	forwardAddr  *net.TCPAddr
	readWait     time.Duration
	writeWait    time.Duration
	pingInterval time.Duration
	connTimeout  time.Duration
	cert         *tls.Certificate
	fingerprint  string
	bufferSize   int
}

func NewServer(relayURL string, authToken string, id string, forwardAddr *net.TCPAddr) (*Server, error) {
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	fingerprint := CertFingerprint(cert)

	return &Server{
		relayURL:     relayURL,
		authToken:    authToken,
		id:           id,
		forwardAddr:  forwardAddr,
		readWait:     10 * time.Second,
		writeWait:    10 * time.Second,
		pingInterval: 1 * time.Second,
		connTimeout:  30 * time.Second,
		cert:         cert,
		fingerprint:  fingerprint,
		bufferSize:   32 * 1024, // 32KB buffer size for copying
	}, nil
}

func (s *Server) Start() error {
	slog.Info("connecting to relay", "fingerprint", s.fingerprint)

	header := http.Header{}
	if s.authToken != "" {
		header.Set("Authorization", "Token "+s.authToken)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.Dial(s.relayURL+"/server", header)
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.readWait))
	conn.SetPingHandler(func(appData string) error {
		slog.Info("received ping", "remote_addr", conn.RemoteAddr())
		conn.SetReadDeadline(time.Now().Add(s.readWait))
		conn.SetWriteDeadline(time.Now().Add(s.writeWait))
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(s.writeWait))
	})
	conn.SetPongHandler(func(string) error {
		slog.Info("received pong", "remote_addr", conn.RemoteAddr())
		conn.SetReadDeadline(time.Now().Add(s.readWait))
		return nil
	})

	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			slog.Info("sending ping", "remote_addr", conn.RemoteAddr())
			conn.SetWriteDeadline(time.Now().Add(s.writeWait))
			err := conn.WriteMessage(websocket.PingMessage, []byte{})
			if err != nil {
				slog.Error("failed to send ping", "error", err)
				return
			}
		}
	}()

	err = s.handleWSConnection(conn)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}

	return nil
}

func (s *Server) handleWSConnection(conn *websocket.Conn) error {
	v, err := json.Marshal(WSMessageServiceRequest{
		ID:          s.id,
		Fingerprint: s.fingerprint,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal service request: %w", err)
	}

	err = conn.WriteJSON(WSMessage{
		Type:  WSMessageTypeServiceRequest,
		Value: v,
	})
	if err != nil {
		return fmt.Errorf("failed to send service request: %w", err)
	}

	for {
		msg := &WSMessage{}
		err := conn.ReadJSON(msg)
		if err != nil {
			return err
		}

		slog.Info("received message", "type", msg.Type)
		switch msg.Type {
		case WSMessageTypePunchRequest:
			req := &WSMessagePunchRequest{}
			err := json.Unmarshal(msg.Value, req)
			if err != nil {
				return fmt.Errorf("invalid punch request payload: %w", err)
			}

			err = s.punchRequest(req)
			if err != nil {
				slog.Error("failed to handle punch request", "error", err)
				return fmt.Errorf("failed to handle punch request: %w", err)
			}
		default:
			slog.Error("unknown message type", "type", msg.Type)
			return fmt.Errorf("unknown message type: %s", msg.Type)
		}
	}
}

func (s *Server) punchRequest(msg *WSMessagePunchRequest) error {
	slog.Info("received punch request", "token", msg.Token, "client_fingerprint", msg.ClientFingerprint, "punch_server_address", msg.PunchServerAddress)

	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	slog.Info("UDP punch listener started on", "address", conn.LocalAddr().String())

	addr, err := net.ResolveUDPAddr("udp", msg.PunchServerAddress)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	slog.Info("sending UDP punch", "token", msg.Token, "relay_address", addr.String())

	_, err = conn.WriteTo([]byte(msg.Token), addr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send UDP punch: %w", err)
	}

	tlsConf := &tls.Config{
		Certificates:          []tls.Certificate{*s.cert},
		NextProtos:            []string{"quic-link"},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: VerifyPeerCert(msg.ClientFingerprint),
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:        10 * time.Second,
		KeepAlivePeriod:       1 * time.Second,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	}

	ln, err := quic.Listen(conn, tlsConf, quicConf)
	if err != nil {
		slog.Error("failed to start QUIC listener", "error", err)
		conn.Close()
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	go func() {
		defer conn.Close()
		defer ln.Close()

		s.handleListener(ln)
	}()

	return nil
}

func (s *Server) handleListener(ln *quic.Listener) {
	slog.Info("QUIC listener started on", "address", ln.Addr().String())

	acceptCtx, cancel := context.WithTimeout(context.Background(), s.connTimeout)
	defer cancel()
	q, err := ln.Accept(acceptCtx)
	if err != nil {
		slog.Error("failed to accept QUIC connection", "error", err)
		return
	}

	c, err := q.AcceptStream(acceptCtx)
	if err != nil {
		slog.Error("failed to accept QUIC stream", "error", err)
		return
	}
	defer c.Close()

	slog.Info("QUIC connection accepted", "remote_addr", q.RemoteAddr().String())

	// Connect to the forward address
	slog.Info("connecting to forward address", "address", s.forwardAddr)
	targetConn, err := net.DialTCP("tcp", nil, s.forwardAddr)
	if err != nil {
		slog.Error("failed to connect to forward address", "address", s.forwardAddr, "error", err)
		return
	}
	defer targetConn.Close()

	slog.Info("connected to forward address", "address", s.forwardAddr)

	syncCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Bidirectional copy between QUIC stream and target connection
	go func() {
		defer cancel()
		defer q.CloseWithError(0, "closing connection")

		buf := make([]byte, s.bufferSize)
		for {
			n, err := c.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Error("error reading from QUIC stream", "error", err)
				}
				slog.Info("QUIC stream closed by client")
				return
			}

			b64 := base64.StdEncoding.EncodeToString(buf[:n])
			slog.Debug("received data from QUIC stream", "size", n, "base64", b64)

			for written := 0; written < n; {
				m, err := targetConn.Write(buf[written:n])
				if err != nil {
					slog.Error("error writing to target connection", "error", err)
					return
				}
				written += m
			}
		}
	}()

	go func() {
		defer cancel()

		buf := make([]byte, s.bufferSize)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Error("error reading from target connection", "error", err)
				}
				slog.Info("read from target connection closed")
				return
			}

			b64 := base64.StdEncoding.EncodeToString(buf[:n])
			slog.Debug("received data from target", "size", n, "base64", b64)

			for written := 0; written < n; {
				m, err := c.Write(buf[written:n])
				if err != nil {
					slog.Error("error writing to QUIC stream", "error", err)
					return
				}
				written += m
			}
		}
	}()

	<-syncCtx.Done()

	slog.Info("closing QUIC connection", "remote_addr", q.RemoteAddr().String())
}
