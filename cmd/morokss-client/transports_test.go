package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestTransportAutoFallsBackAndCachesSuccess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cachePath := filepath.Join(t.TempDir(), "transports.json")
	selector := newTransportSelector(transportAuto, cachePath, "server|hostname")
	selector.now = func() time.Time { return now }
	attempts := make([]string, 0, 2)
	opener := func(_ context.Context, config clientConfig, _ *profileSelector) (tunnelStream, error) {
		attempts = append(attempts, config.transport)
		if config.transport == transportWebSocket {
			return nil, atStage(stageWebSocket, errors.New("upgrade rejected"))
		}
		return &websocketStream{}, nil
	}
	tunnel, err := openEndpointTunnelWith(
		context.Background(),
		clientConfig{},
		newProfileSelector("auto", "", "server"),
		selector,
		opener,
	)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel == nil || len(attempts) != 2 || attempts[1] != transportHTTPStream {
		t.Fatalf("unexpected transport attempts: %v", attempts)
	}

	loaded := newTransportSelector(transportAuto, cachePath, "server|hostname")
	candidates, _ := loaded.candidates()
	if len(candidates) == 0 || candidates[0] != transportHTTPStream {
		t.Fatalf("cached transport wasn't preferred: %v", candidates)
	}
}

func TestTransportAutoDoesNotHideAuthenticationFailure(t *testing.T) {
	selector := newTransportSelector(transportAuto, "", "server")
	attempts := 0
	opener := func(_ context.Context, _ clientConfig, _ *profileSelector) (tunnelStream, error) {
		attempts++
		return nil, atStage(stageAuth, errors.New("rejected"))
	}
	_, err := openEndpointTunnelWith(
		context.Background(),
		clientConfig{},
		newProfileSelector("auto", "", "server"),
		selector,
		opener,
	)
	if err == nil || attempts != 1 {
		t.Fatalf("authentication failure caused transport probing: attempts=%d err=%v", attempts, err)
	}
}

func TestHTTPChunkStreamRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	sender := newHTTPChunkStream(left, bufio.NewReader(left))
	receiver := newHTTPChunkStream(right, bufio.NewReader(right))
	done := make(chan error, 1)
	go func() {
		done <- sender.sendBinary([]byte("hello"))
	}()
	payload, err := receiver.receiveBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(payload) != "hello" {
		t.Fatalf("unexpected HTTP stream payload %q", payload)
	}
}
