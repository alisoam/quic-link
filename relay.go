package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

type Service struct {
	done        chan struct{}
	busy        bool
	conn        *websocket.Conn
	fingerprint string
}

func NewService(conn *websocket.Conn, fingerprint string) *Service {
	return &Service{
		done:        make(chan struct{}),
		conn:        conn,
		fingerprint: fingerprint,
	}
}

type Relay struct {
	authToken    string
	port         int
	services     map[string][]*Service
	punchEntrys  map[string]net.Addr
	mu           sync.Mutex
	pingInterval time.Duration
	readWait     time.Duration
	writeWait    time.Duration
}

func NewRelay(authToken string, port int) *Relay {
	return &Relay{
		authToken:    authToken,
		port:         port,
		services:     make(map[string][]*Service),
		punchEntrys:  make(map[string]net.Addr),
		pingInterval: 1 * time.Second,
		readWait:     10 * time.Second,
		writeWait:    10 * time.Second,
	}
}

func (re *Relay) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/server", re.serverHandler)
	mux.HandleFunc("/client", re.clientHandler)

	srv := &http.Server{
		Handler: mux,
	}

	go func() {
		ln, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(re.port))
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()

		slog.Info("relay http server started", "port", re.port)

		err = srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// punch handler
	go func() {
		ln, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(re.port))
		if err != nil {
			log.Fatal(err)
		}

		slog.Info("punch handler started", "port", re.port)
		defer ln.Close()

		re.punchHandler(ln)
	}()

	done := make(chan struct{})
	<-done

	srv.Shutdown(context.Background())
}

func (re *Relay) punchHandler(ln net.PacketConn) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			slog.Error("read punch request error", "error", err)
			continue
		}

		go func(token string, addr net.Addr) {
			slog.Info("new punch request", "token", token, "addr", addr)

			re.mu.Lock()
			en, ok := re.punchEntrys[token]
			if !ok || en != nil {
				re.mu.Unlock()
				slog.Info("punch entry not found", "token", token)
				return
			}
			re.punchEntrys[token] = addr
			re.mu.Unlock()

			slog.Info("new punch entry", "token", token, "addr", addr)
		}(string(buf[:n]), addr)
	}
}

func (re *Relay) punchRequest(ctx context.Context, conn *websocket.Conn, clientFingerprint string) (net.Addr, error) {
	token := uuid.New().String()

	slog.Info("new punch request", "token", token, "client_fingerprint", clientFingerprint)

	re.mu.Lock()
	_, ok := re.punchEntrys[token]
	if ok {
		re.mu.Unlock()
		return nil, errors.New("token already exists")
	}

	re.punchEntrys[token] = nil
	re.mu.Unlock()

	defer func() {
		re.mu.Lock()
		delete(re.punchEntrys, token)
		re.mu.Unlock()

		slog.Info("punch entry removed", "token", token)
	}()

	// send punch request to client
	value, err := json.Marshal(
		&WSMessagePunchRequest{
			Token:             token,
			ClientFingerprint: clientFingerprint,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal punch request: %w", err)
	}
	err = conn.WriteJSON(WSMessage{
		Type:  WSMessageTypePunchRequest,
		Value: value,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send punch request: %w", err)
	}

	// wait for punch entry
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			re.mu.Lock()
			addr, ok := re.punchEntrys[token]
			if ok && addr != nil {
				re.mu.Unlock()
				slog.Info("punch entry found", "token", token, "addr", addr)
				return addr, nil
			}
			re.mu.Unlock()
		}
	}
}

func (re *Relay) serverHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("new server connection", "remote_addr", r.RemoteAddr)

	err := re.authorize(r)
	if err != nil {
		slog.Error("authorization error", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "unauthorized", 401)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("upgrade error", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "upgrade failed", 500)
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(re.readWait))
	conn.SetPingHandler(func(appData string) error {
		slog.Info("received ping", "remote_addr", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(re.readWait))
		conn.SetWriteDeadline(time.Now().Add(re.writeWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(re.writeWait))
		if err != nil {
			slog.Info("pong error", "remote_addr", r.RemoteAddr, "error", err)
			return err
		}
		return nil

	})
	conn.SetPongHandler(func(string) error {
		slog.Info("received pong", "remote_addr", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(re.readWait))
		return nil
	})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go func() {
		defer cancel()

		ticker := time.NewTicker(re.pingInterval)
		defer ticker.Stop()

		for {
			<-ticker.C

			slog.Info("sending ping", "remote_addr", r.RemoteAddr)

			conn.SetWriteDeadline(time.Now().Add(re.writeWait))
			err := conn.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				slog.Info("ping error", "remote_addr", r.RemoteAddr, "error", err)
				return
			}
		}
	}()

	err = re.handleWSConnection(ctx, conn)
	if err != nil {
		slog.Error("connection error", "remote_addr", r.RemoteAddr, "error", err)
		return
	}
}

func (re *Relay) handleWSConnection(ctx context.Context, conn *websocket.Conn) error {
	id := ""
	fingerprint := ""
	for {
		msg := &WSMessage{}
		err := conn.ReadJSON(msg)
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}

		if msg.Type != WSMessageTypeServiceRequest {
			return fmt.Errorf("invalid message type: %d", msg.Type)
		}

		req := &WSMessageServiceRequest{}
		err = json.Unmarshal(msg.Value, req)
		if err != nil {
			return fmt.Errorf("failed to unmarshal service request: %w", err)
		}

		id = req.ID
		fingerprint = req.Fingerprint
		break
	}

	s := NewService(conn, fingerprint)

	re.mu.Lock()
	if re.services[id] == nil {
		re.services[id] = []*Service{}
	}
	re.services[id] = append(re.services[id], s)
	re.mu.Unlock()

	defer func() {
		slog.Info("service disconnected", "id", id, "remote_addr", conn.RemoteAddr())

		re.mu.Lock()
		defer re.mu.Unlock()

		services := re.services[id]
		for i, srv := range services {
			if srv == s {
				re.services[id] = append(services[:i], services[i+1:]...)
				break
			}
		}
	}()

	<-ctx.Done()

	return nil
}

func (re *Relay) clientHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("new client connection", "remote_addr", r.RemoteAddr)

	err := re.authorize(r)
	if err != nil {
		slog.Error("authorization error", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "unauthorized", 401)
		return
	}

	var msg WSMessage
	err = json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		slog.Error("failed to decode message", "remote_addr", r.RemoteAddr, "error", err)
		w.WriteHeader(400)
		return
	}
	if msg.Type != WSMessageTypeClientTunnelRequest {
		slog.Error("invalid message type", "remote_addr", r.RemoteAddr, "type", msg.Type)
		w.WriteHeader(400)
		return

	}
	req := &WSMessageClientTunnelRequest{}
	err = json.Unmarshal(msg.Value, req)
	if err != nil {
		slog.Error("failed to unmarshal tunnel request", "remote_addr", r.RemoteAddr, "error", err)
		w.WriteHeader(400)
		return
	}

	slog.Info("received tunnel request", "id", req.ID, "remote_addr", r.RemoteAddr, "client_fingerprint", req.Fingerprint)

	var s *Service
	re.mu.Lock()
	services := re.services[req.ID]
	for _, srv := range services {
		if !srv.busy {
			s = srv
			s.busy = true
			break
		}
	}
	re.mu.Unlock()

	if s == nil {
		slog.Info("no available service", "id", req.ID, "remote_addr", r.RemoteAddr)
		w.WriteHeader(503)
		return
	}
	slog.Info("service found for tunnel request", "id", req.ID, "remote_addr", r.RemoteAddr)

	defer func() {
		slog.Info("service released", "id", req.ID, "remote_addr", r.RemoteAddr)

		re.mu.Lock()
		s.busy = false
		re.mu.Unlock()
	}()

	addr, err := re.punchRequest(r.Context(), s.conn, req.Fingerprint)
	if err != nil {
		slog.Error("punch request error", "id", req.ID, "remote_addr", r.RemoteAddr, "error", err)
		w.WriteHeader(500)
		return
	}

	value, err := json.Marshal(
		&WSMessageClientTunnelResponse{
			Address:           addr.String(),
			ServerFingerprint: s.fingerprint,
		},
	)
	if err != nil {
		slog.Error("failed to marshal tunnel request", "id", req.ID, "remote_addr", r.RemoteAddr, "error", err)
		return
	}
	err = json.NewEncoder(w).Encode(WSMessage{
		Type:  WSMessageTypeClientTunnelResponse,
		Value: value,
	})
	if err != nil {
		slog.Error("failed to send tunnel response", "id", req.ID, "remote_addr", r.RemoteAddr, "error", err)
		return
	}
}

func (re *Relay) authorize(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && !strings.HasPrefix(authHeader, "Token ") {
		return errors.New("bad authorization header")
	}
	token := strings.TrimPrefix(authHeader, "Token ")

	if subtle.ConstantTimeCompare([]byte(token), []byte(re.authToken)) != 1 {
		return errors.New("unauthorized")
	}

	return nil
}
