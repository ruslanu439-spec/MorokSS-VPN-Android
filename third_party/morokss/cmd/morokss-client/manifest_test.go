package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ruslanu439-spec/MorokSS/internal/endpointmanifest"
)

func writeTestManifest(t *testing.T, directory string, now time.Time) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document := endpointmanifest.Document{
		Version:     endpointmanifest.Version,
		GeneratedAt: now,
		ExpiresAt:   now.Add(24 * time.Hour),
		Endpoints: []endpointmanifest.Endpoint{{
			Address:  "192.0.2.50:443",
			Hostname: "manifest.example",
		}},
	}
	if err := endpointmanifest.Sign(&document, privateKey); err != nil {
		t.Fatal(err)
	}
	data, err := endpointmanifest.Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "source.json")
	publicKeyPath := filepath.Join(directory, "public.key")
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKeyPath, endpointmanifest.EncodeKey(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, publicKeyPath
}

func TestEndpointManifestUsesVerifiedCache(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	manifestPath, publicKeyPath := writeTestManifest(t, directory, now)
	cachePath := filepath.Join(directory, "cache.json")

	items, cached, err := loadEndpointManifest(context.Background(), manifestPath, publicKeyPath, cachePath, now)
	if err != nil {
		t.Fatal(err)
	}
	if cached || len(items) != 1 || items[0].Hostname != "manifest.example" {
		t.Fatalf("unexpected manifest result: cached=%v items=%#v", cached, items)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	items, cached, err = loadEndpointManifest(context.Background(), manifestPath, publicKeyPath, cachePath, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cached || len(items) != 1 {
		t.Fatalf("verified cache wasn't used: cached=%v items=%#v", cached, items)
	}
}

func TestEndpointManifestTriesMultipleSources(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	manifestPath, publicKeyPath := writeTestManifest(t, directory, now)
	items, cached, err := loadEndpointManifestSources(
		context.Background(),
		[]string{filepath.Join(directory, "missing.json"), manifestPath},
		publicKeyPath,
		filepath.Join(directory, "cache.json"),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if cached || len(items) != 1 || items[0].Hostname != "manifest.example" {
		t.Fatalf("backup manifest source was not used: cached=%v items=%#v", cached, items)
	}
}

func TestEndpointManifestRejectsHTTP(t *testing.T) {
	if _, err := readManifestSource(context.Background(), "http://example.com/endpoints.json"); err == nil {
		t.Fatal("plain HTTP manifest source was accepted")
	}
}

func TestEndpointManifestRejectsRollback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(directory, "public.key")
	sourcePath := filepath.Join(directory, "source.json")
	cachePath := filepath.Join(directory, "cache.json")
	if err := os.WriteFile(publicKeyPath, endpointmanifest.EncodeKey(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(path, hostname string, generatedAt time.Time) {
		t.Helper()
		document := endpointmanifest.Document{
			Version: endpointmanifest.Version, GeneratedAt: generatedAt, ExpiresAt: now.Add(24 * time.Hour),
			Endpoints: []endpointmanifest.Endpoint{{Address: "192.0.2.50:443", Hostname: hostname}},
		}
		if err := endpointmanifest.Sign(&document, privateKey); err != nil {
			t.Fatal(err)
		}
		data, err := endpointmanifest.Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(sourcePath, "new.example", now)
	if _, _, err := loadEndpointManifest(context.Background(), sourcePath, publicKeyPath, cachePath, now); err != nil {
		t.Fatal(err)
	}
	write(sourcePath, "old.example", now.Add(-time.Hour))
	items, cached, err := loadEndpointManifest(context.Background(), sourcePath, publicKeyPath, cachePath, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cached || len(items) != 1 || items[0].Hostname != "new.example" {
		t.Fatalf("rollback replaced cached manifest: cached=%v items=%#v", cached, items)
	}
}
