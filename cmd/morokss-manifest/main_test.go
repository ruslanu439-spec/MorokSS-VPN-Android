package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ruslanu439-spec/MorokSS/internal/endpointmanifest"
)

func TestKeygenAndSign(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.key")
	publicPath := filepath.Join(directory, "public.key")
	manifestPath := filepath.Join(directory, "endpoints.json")
	if err := run([]string{
		"keygen",
		"--private", privatePath,
		"--public", publicPath,
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"sign",
		"--private", privatePath,
		"--out", manifestPath,
		"--valid-for", "24h",
		"--endpoint", "192.0.2.10:443,one.example",
	}); err != nil {
		t.Fatal(err)
	}
	publicData, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := endpointmanifest.DecodePublicKey(publicData)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	document, err := endpointmanifest.Verify(manifestData, publicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Endpoints) != 1 || document.Endpoints[0].Hostname != "one.example" {
		t.Fatalf("unexpected manifest: %#v", document)
	}
	if err := run([]string{"keygen", "--private", privatePath, "--public", publicPath}); err == nil {
		t.Fatal("keygen overwrote existing keys")
	}
}
