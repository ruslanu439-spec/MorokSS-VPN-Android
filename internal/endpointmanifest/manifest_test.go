package endpointmanifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func signedDocument(t *testing.T, now time.Time) ([]byte, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document := Document{
		Version:     Version,
		GeneratedAt: now.UTC(),
		ExpiresAt:   now.Add(24 * time.Hour).UTC(),
		Endpoints: []Endpoint{{
			Address:  "192.0.2.10:443",
			Hostname: "one.example",
		}},
	}
	if err := Sign(&document, privateKey); err != nil {
		t.Fatal(err)
	}
	data, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	return data, publicKey
}

func TestSignAndVerify(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	data, publicKey := signedDocument(t, now)
	document, err := Verify(data, publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Endpoints) != 1 || document.Endpoints[0].Hostname != "one.example" {
		t.Fatalf("unexpected document: %#v", document)
	}
}

func TestVerifyRejectsTamperingAndExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	data, publicKey := signedDocument(t, now)
	tampered := append([]byte(nil), data...)
	for index := range tampered {
		if tampered[index] == 'o' {
			tampered[index] = 'x'
			break
		}
	}
	if _, err := Verify(tampered, publicKey, now); err == nil {
		t.Fatal("tampered endpoint manifest was accepted")
	}
	if _, err := Verify(data, publicKey, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired endpoint manifest was accepted")
	}
}

func TestParseEndpointSupportsIPv6(t *testing.T) {
	item, err := ParseEndpoint("[2001:db8::1]:443,example.com")
	if err != nil {
		t.Fatal(err)
	}
	if item.Address != "[2001:db8::1]:443" || item.Hostname != "example.com" {
		t.Fatalf("unexpected endpoint: %#v", item)
	}
}
