package endpointmanifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	Version      = 1
	MaxDocument  = 128 * 1024
	MaxEndpoints = 128
	MaxValidity  = 31 * 24 * time.Hour
)

type Endpoint struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname"`
}

type Document struct {
	Version     int        `json:"version"`
	GeneratedAt time.Time  `json:"generated_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Endpoints   []Endpoint `json:"endpoints"`
	Signature   string     `json:"signature"`
}

type payload struct {
	Version     int        `json:"version"`
	GeneratedAt time.Time  `json:"generated_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Endpoints   []Endpoint `json:"endpoints"`
}

func ParseEndpoint(value string) (Endpoint, error) {
	separator := strings.LastIndex(value, ",")
	if separator < 1 || separator == len(value)-1 {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: expected ADDRESS,HOSTNAME", value)
	}
	return NormalizeEndpoint(Endpoint{
		Address:  value[:separator],
		Hostname: value[separator+1:],
	})
}

func NormalizeEndpoint(item Endpoint) (Endpoint, error) {
	address := strings.TrimSpace(item.Address)
	hostname := strings.TrimSpace(item.Hostname)
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return Endpoint{}, fmt.Errorf("invalid endpoint address %q: expected HOST:PORT", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid endpoint port %q", portText)
	}
	if hostname == "" || strings.ContainsAny(hostname, "/, \t\r\n") {
		return Endpoint{}, fmt.Errorf("invalid TLS hostname %q", hostname)
	}
	return Endpoint{Address: net.JoinHostPort(host, portText), Hostname: hostname}, nil
}

func Sign(document *Document, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	if err := validate(document, document.GeneratedAt); err != nil {
		return err
	}
	encoded, err := signingPayload(*document)
	if err != nil {
		return err
	}
	document.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, encoded))
	return nil
}

func Verify(data []byte, publicKey ed25519.PublicKey, now time.Time) (Document, error) {
	if len(data) == 0 || len(data) > MaxDocument {
		return Document{}, errors.New("endpoint manifest has an invalid size")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Document{}, errors.New("invalid Ed25519 public key")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode endpoint manifest: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Document{}, err
	}
	if err := validate(&document, now); err != nil {
		return Document{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Document{}, errors.New("endpoint manifest has an invalid signature encoding")
	}
	encoded, err := signingPayload(document)
	if err != nil {
		return Document{}, err
	}
	if !ed25519.Verify(publicKey, encoded, signature) {
		return Document{}, errors.New("endpoint manifest signature verification failed")
	}
	return document, nil
}

func Encode(document Document) ([]byte, error) {
	return json.MarshalIndent(document, "", "  ")
}

func DecodePublicKey(data []byte) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be base64-encoded Ed25519 data")
	}
	return ed25519.PublicKey(decoded), nil
}

func DecodePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("private key must be base64-encoded Ed25519 data")
	}
	return ed25519.PrivateKey(decoded), nil
}

func EncodeKey(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data) + "\n")
}

func signingPayload(document Document) ([]byte, error) {
	return json.Marshal(payload{
		Version:     document.Version,
		GeneratedAt: document.GeneratedAt.UTC(),
		ExpiresAt:   document.ExpiresAt.UTC(),
		Endpoints:   document.Endpoints,
	})
}

func validate(document *Document, now time.Time) error {
	if document.Version != Version {
		return fmt.Errorf("unsupported endpoint manifest version %d", document.Version)
	}
	if document.GeneratedAt.IsZero() || document.ExpiresAt.IsZero() {
		return errors.New("endpoint manifest timestamps are required")
	}
	if !document.ExpiresAt.After(document.GeneratedAt) || document.ExpiresAt.Sub(document.GeneratedAt) > MaxValidity {
		return fmt.Errorf("endpoint manifest validity must be between 0 and %s", MaxValidity)
	}
	if document.GeneratedAt.After(now.Add(10 * time.Minute)) {
		return errors.New("endpoint manifest was generated too far in the future")
	}
	if !document.ExpiresAt.After(now) {
		return errors.New("endpoint manifest has expired")
	}
	if len(document.Endpoints) == 0 || len(document.Endpoints) > MaxEndpoints {
		return fmt.Errorf("endpoint manifest must contain between 1 and %d endpoints", MaxEndpoints)
	}
	seen := make(map[string]bool)
	for index, item := range document.Endpoints {
		normalized, err := NormalizeEndpoint(item)
		if err != nil {
			return fmt.Errorf("endpoint %d: %w", index+1, err)
		}
		key := normalized.Address + "|" + normalized.Hostname
		if seen[key] {
			return fmt.Errorf("endpoint %d is duplicated", index+1)
		}
		seen[key] = true
		document.Endpoints[index] = normalized
	}
	return nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("endpoint manifest contains extra JSON data")
	}
	return fmt.Errorf("decode endpoint manifest: %w", err)
}
