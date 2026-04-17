package main

import "encoding/json"

type WSMessageType int

const (
	WSMessageTypeServiceRequest WSMessageType = iota
	WSMessageTypePunchRequest
	WSMessageTypeClientTunnelRequest
	WSMessageTypeClientTunnelResponse
)

type WSMessage struct {
	Type  WSMessageType   `json:"type"`
	Value json.RawMessage `json:"value"`
}

type WSMessageServiceRequest struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type WSMessagePunchRequest struct {
	Token             string `json:"token"`
	ClientFingerprint string `json:"client_fingerprint,omitempty"`
}

type WSMessageClientTunnelRequest struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type WSMessageClientTunnelResponse struct {
	Address           string `json:"address"`
	ServerFingerprint string `json:"server_fingerprint,omitempty"`
}
