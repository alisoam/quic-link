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
	mu          sync.Mutex
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
	authToken          string
	port               int
	punchServerAddress string
	services           map[string][]*Service
	punchEntrys        map[string]*net.UDPAddr
	mu                 sync.Mutex
	pingInterval       time.Duration
	readWait           time.Duration
	writeWait          time.Duration
	punchInterval      time.Duration
	punchAttempt       int
}

func NewRelay(authToken string, port int, punchServerAddress string) *Relay {
	return &Relay{
		authToken:          authToken,
		port:               port,
		punchServerAddress: punchServerAddress,
		services:           make(map[string][]*Service),
		punchEntrys:        make(map[string]*net.UDPAddr),
		pingInterval:       1 * time.Second,
		readWait:           10 * time.Second,
		writeWait:          10 * time.Second,
		punchInterval:      10 * time.Millisecond,
		punchAttempt:       300,
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
		addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:"+strconv.Itoa(re.port))
		if err != nil {
			log.Fatal(err)
		}

		ln, err := net.ListenUDP("udp", addr)
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

func (re *Relay) punchHandler(ln *net.UDPConn) {
	buf := make([]byte, 1024)
	for {
		n, peerAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			slog.Error("read punch request error", "error", err)
			continue
		}

		go func(token string, addr *net.UDPAddr) {
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

			go func(addr *net.UDPAddr) {
				err := startUDPPunch(ln, addr, []byte("punch response"), re.punchAttempt, re.punchInterval)
				if err != nil {
					slog.Error("failed to send punch response", "token", token, "addr", addr, "error", err)
				}
			}(peerAddr)
		}(string(buf[:n]), peerAddr)
	}
}

func (re *Relay) punchRequest(ctx context.Context, conn *websocket.Conn) (*net.UDPAddr, error) {
	token := uuid.New().String()

	slog.Info("new punch request", "token", token)

	re.mu.Lock()
	_, ok := re.punchEntrys[token]
	if ok {
		re.mu.Unlock()
		return nil, errors.New("token already exists")
	}

	re.punchEntrys[token] = nil
	re.mu.Unlock()

	slog.Info("punch entry created", "token", token)

	defer func() {
		re.mu.Lock()
		delete(re.punchEntrys, token)
		re.mu.Unlock()

		slog.Info("punch entry removed", "token", token)
	}()

	// send punch request to client
	value, err := json.Marshal(
		&WSMessagePunchRequest{
			Token:              token,
			PunchServerAddress: re.punchServerAddress,
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
	slog.Info("punch request sent", "token", token, "remote_addr", conn.RemoteAddr())

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

	msg := &WSMessage{}
	err = conn.ReadJSON(msg)
	if err != nil {
		slog.Error("failed to read message", "remote_addr", r.RemoteAddr, "error", err)
		return
	}
	if msg.Type != WSMessageTypeServiceRequest {
		slog.Error("invalid message type", "remote_addr", r.RemoteAddr, "type", msg.Type)
		return
	}
	req := &WSMessageServiceRequest{}
	err = json.Unmarshal(msg.Value, req)
	if err != nil {
		slog.Error("failed to unmarshal service request", "remote_addr", r.RemoteAddr, "error", err)
		return
	}

	id := req.ID
	fingerprint := req.ServerFingerprint
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

	conn.SetReadDeadline(time.Now().Add(re.readWait))

	conn.SetPingHandler(func(appData string) error {
		slog.Info("received ping", "remote_addr", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(re.readWait))
		conn.SetWriteDeadline(time.Now().Add(re.writeWait))
		s.mu.Lock()
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(re.writeWait))
		s.mu.Unlock()
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
			s.mu.Lock()
			err := conn.WriteMessage(websocket.PingMessage, nil)
			s.mu.Unlock()
			if err != nil {
				slog.Info("ping error", "remote_addr", r.RemoteAddr, "error", err)
				return
			}
		}
	}()

	slog.Info("new service registered", "id", id, "remote_addr", conn.RemoteAddr(), "fingerprint", fingerprint)

	<-ctx.Done()
}

func (re *Relay) clientHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("new client connection", "remote_addr", r.RemoteAddr)

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

	mu := sync.Mutex{}

	conn.SetPingHandler(func(appData string) error {
		slog.Info("received ping", "remote_addr", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(re.readWait))
		conn.SetWriteDeadline(time.Now().Add(re.writeWait))
		mu.Lock()
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(re.writeWait))
		mu.Unlock()
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

	go func() {
		ticker := time.NewTicker(re.pingInterval)
		defer ticker.Stop()

		for {
			<-ticker.C
			slog.Info("sending ping", "remote_addr", r.RemoteAddr)

			conn.SetWriteDeadline(time.Now().Add(re.writeWait))
			mu.Lock()
			err := conn.WriteMessage(websocket.PingMessage, nil)
			mu.Unlock()
			if err != nil {
				slog.Info("ping error", "remote_addr", r.RemoteAddr, "error", err)
				return
			}
		}
	}()

	var msg WSMessage
	err = conn.ReadJSON(&msg)
	if err != nil {
		slog.Error("failed to read message", "remote_addr", r.RemoteAddr, "error", err)
		return
	}
	if msg.Type != WSMessageTypeTunnelRequest {
		slog.Error("invalid message type", "remote_addr", r.RemoteAddr, "type", msg.Type)
		return
	}
	req := &WSMessageTunnelRequest{}
	err = json.Unmarshal(msg.Value, req)
	if err != nil {
		slog.Error("failed to unmarshal tunnel request", "remote_addr", r.RemoteAddr, "error", err)
		return
	}

	slog.Info("received tunnel request", "id", req.ID, "remote_addr", r.RemoteAddr, "client_fingerprint", req.ClientFingerprint)

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
		return
	}
	slog.Info("service found for tunnel request", "id", req.ID, "remote_addr", r.RemoteAddr)

	defer func() {
		slog.Info("service released", "id", req.ID, "remote_addr", r.RemoteAddr)

		re.mu.Lock()
		s.busy = false
		re.mu.Unlock()
	}()

	var srvAddr *net.UDPAddr
	var clientAddr *net.UDPAddr
	wg := sync.WaitGroup{}
	wg.Add(2)
	for _, peer := range []struct {
		conn *websocket.Conn
		addr **net.UDPAddr
		mu   *sync.Mutex
	}{
		{s.conn, &srvAddr, &s.mu},
		{conn, &clientAddr, &mu},
	} {
		go func(conn *websocket.Conn, addr **net.UDPAddr, mu *sync.Mutex) {
			defer wg.Done()

			slog.Info("starting punch request", "id", req.ID, "addr", conn.RemoteAddr())
			var err error
			mu.Lock()
			*addr, err = re.punchRequest(r.Context(), conn)
			mu.Unlock()
			if err != nil {
				slog.Error("punch request error", "id", req.ID, "addr", conn.RemoteAddr(), "error", err)
				return
			}
			slog.Info("punch request completed", "id", req.ID, "addr", conn.RemoteAddr(), "punch_addr", *addr)
		}(peer.conn, peer.addr, peer.mu)
	}

	wg.Wait()
	if srvAddr == nil || clientAddr == nil {
		slog.Error("failed to get punch address", "id", req.ID, "remote_addr", r.RemoteAddr)
		return
	}

	slog.Info("punch completed", "id", req.ID, "remote_addr", r.RemoteAddr, "srv_addr", srvAddr, "client_addr", clientAddr)

	wg.Add(2)
	for _, peer := range []struct {
		conn        *websocket.Conn
		addr        *net.UDPAddr
		fingerprint string
		mu          *sync.Mutex
	}{
		{s.conn, clientAddr, req.ClientFingerprint, &s.mu},
		{conn, srvAddr, s.fingerprint, &mu},
	} {
		go func(conn *websocket.Conn, addr *net.UDPAddr, fingerprint string, mu *sync.Mutex) {
			defer wg.Done()

			value, err := json.Marshal(WSMessageStartTunnel{
				PeerAddress:     addr.String(),
				PeerFingerprint: fingerprint,
			})
			if err != nil {
				slog.Error("failed to marshal start tunnel message", "id", req.ID, "remote_addr", r.RemoteAddr, "error", err)
				return
			}
			mu.Lock()
			err = conn.WriteJSON(WSMessage{
				Type:  WSMessageTypeStartTunnel,
				Value: value,
			})
			mu.Unlock()
			if err != nil {
				slog.Error("failed to send start tunnel message", "id", req.ID, "remote_addr", r.RemoteAddr, "error", err)
				return
			}
		}(peer.conn, peer.addr, peer.fingerprint, peer.mu)
	}
	wg.Wait()
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

func startUDPPunch(conn *net.UDPConn, addr *net.UDPAddr, payload []byte, attempts int, interval time.Duration) error {
	slog.Info("starting UDP punch", "address", addr.String(), "attempts", attempts, "interval_ms", interval.Milliseconds())
	if attempts <= 0 {
		return nil
	}
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}

	for i := 0; i < attempts; i++ {
		if _, err := conn.WriteToUDP(payload, addr); err != nil {
			return err
		}
		if i < attempts-1 {
			time.Sleep(interval)
		}
	}

	return nil
}
