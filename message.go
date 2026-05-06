package main

import "encoding/json"

type WSMessageType int

const (
	WSMessageTypeServiceRequest WSMessageType = iota
	WSMessageTypePunchRequest
	WSMessageTypeTunnelRequest
	WSMessageTypeStartTunnel
)

type WSMessage struct {
	Type  WSMessageType   `json:"type"`
	Value json.RawMessage `json:"value"`
}

type WSMessageServiceRequest struct {
	ID                string `json:"id"`
	ServerFingerprint string `json:"server_fingerprint,omitempty"`
}

type WSMessagePunchRequest struct {
	Token              string `json:"token"`
	PunchServerAddress string `json:"punch_server_address"`
}

type WSMessageTunnelRequest struct {
	ID                string `json:"id"`
	ClientFingerprint string `json:"client_fingerprint,omitempty"`
}

type WSMessageStartTunnel struct {
	PeerAddress     string `json:"peer_address"`
	PeerFingerprint string `json:"peer_fingerprint,omitempty"`
}
