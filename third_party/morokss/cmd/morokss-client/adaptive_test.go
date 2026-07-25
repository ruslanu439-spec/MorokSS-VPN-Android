package main

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProfileCachePrefersLastWorkingProfile(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cachePath := filepath.Join(t.TempDir(), "profiles.json")
	selector := newProfileSelector("auto", cachePath, "server|hostname")
	selector.now = func() time.Time { return now }
	selector.markSuccess("firefox")

	loaded := newProfileSelector("auto", cachePath, "server|hostname")
	loaded.now = func() time.Time { return now }
	candidates, _ := loaded.candidates()
	if len(candidates) == 0 || candidates[0] != "firefox" {
		t.Fatalf("cached profile wasn't preferred: %v", candidates)
	}
}

func TestTLSFailureAddsCooldown(t *testing.T) {
	now := time.Now()
	selector := newProfileSelector("auto", "", "server")
	selector.now = func() time.Time { return now }
	first := automaticProfileOrder()[0]
	selector.markTLSFailure(first)
	candidates, _ := selector.candidates()
	for _, candidate := range candidates {
		if candidate == first {
			t.Fatalf("failed profile %q remained available during cooldown", first)
		}
	}

	now = now.Add(31 * time.Second)
	candidates, _ = selector.candidates()
	if len(candidates) == 0 || candidates[0] != first {
		t.Fatalf("profile didn't return after cooldown: %v", candidates)
	}
}

func TestRandomizedProfileIsNotPersisted(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "profiles.json")
	selector := newProfileSelector("auto", cachePath, "server")
	selector.markSuccess("randomized")
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("randomized profile must not be cached, stat error: %v", err)
	}
}

func TestChangedProfileIsPersistedWithoutWaitingAnHour(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cachePath := filepath.Join(t.TempDir(), "profiles.json")
	selector := newProfileSelector("auto", cachePath, "server")
	selector.now = func() time.Time { return now }
	selector.markSuccess("chrome")
	selector.markTLSFailure("chrome")
	now = now.Add(time.Minute)
	selector.markSuccess("firefox")

	loaded := newProfileSelector("auto", cachePath, "server")
	candidates, _ := loaded.candidates()
	if len(candidates) == 0 || candidates[0] != "firefox" {
		t.Fatalf("changed profile wasn't saved immediately: %v", candidates)
	}
}

func TestAutoModeRetriesOnlyTLSFailure(t *testing.T) {
	selector := newProfileSelector("auto", "", "server")
	profiles := automaticProfileOrder()
	attempts := make([]string, 0, 2)
	opener := func(_ context.Context, _ clientConfig, profile string) (tunnelStream, error) {
		attempts = append(attempts, profile)
		if profile == profiles[0] {
			return nil, atStage(stageTLS, errors.New("connection reset during handshake"))
		}
		return &websocketStream{}, nil
	}
	tunnel, err := openTunnelWith(context.Background(), clientConfig{}, selector, opener)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel == nil || len(attempts) != 2 || attempts[1] != profiles[1] {
		t.Fatalf("unexpected attempts: %v", attempts)
	}

	selector = newProfileSelector("auto", "", "server")
	attempts = nil
	opener = func(_ context.Context, _ clientConfig, profile string) (tunnelStream, error) {
		attempts = append(attempts, profile)
		return nil, atStage(stageTCP, errors.New("network unreachable"))
	}
	if _, err := openTunnelWith(context.Background(), clientConfig{}, selector, opener); err == nil {
		t.Fatal("TCP failure must be returned")
	}
	if len(attempts) != 1 {
		t.Fatalf("TCP failure caused profile probing: %v", attempts)
	}

	selector = newProfileSelector("auto", "", "server")
	attempts = nil
	opener = func(_ context.Context, _ clientConfig, profile string) (tunnelStream, error) {
		attempts = append(attempts, profile)
		return nil, atStage(stageAuth, errors.New("server rejected authentication"))
	}
	if _, err := openTunnelWith(context.Background(), clientConfig{}, selector, opener); err == nil {
		t.Fatal("authentication failure must be returned")
	}
	if len(attempts) != 1 {
		t.Fatalf("authentication failure caused profile probing: %v", attempts)
	}
}

func TestCertificateFailureIsNotProfileFiltering(t *testing.T) {
	err := atStage(stageTLS, x509.UnknownAuthorityError{Cert: &x509.Certificate{}})
	if retryableTLSFailure(err) {
		t.Fatal("certificate error must not trigger another ClientHello profile")
	}
}
