package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

// GenerateSelfSignedCert generates a self-signed TLS certificate for QUIC connections.
// The certificate is valid for 1 year and uses ECDSA P-256.
func GenerateSelfSignedCert() (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"quic-link"},
			CommonName:   "quic-link",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"quic-link", "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return cert, nil
}

// CertFingerprint computes the SHA-256 fingerprint of a TLS certificate.
// Returns the fingerprint as a hex-encoded string.
func CertFingerprint(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	hash := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(hash[:])
}

func VerifyPeerCert(fingerprint string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificate provided by client")
		}
		hash := sha256.Sum256(rawCerts[0])
		actualFingerprint := hex.EncodeToString(hash[:])
		if actualFingerprint != fingerprint {
			return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", fingerprint, actualFingerprint)
		}
		slog.Info("client certificate fingerprint verified", "fingerprint", actualFingerprint)
		return nil
	}
}
