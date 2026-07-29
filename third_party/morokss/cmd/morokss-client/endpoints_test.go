package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"
)

type probeTestTunnel struct {
	transport string
	profile   string
}

func (*probeTestTunnel) sendBinary([]byte) error        { return nil }
func (*probeTestTunnel) receiveBinary() ([]byte, error) { return nil, io.EOF }
func (*probeTestTunnel) close()                         {}

func testEndpoints(t *testing.T) []endpoint {
	t.Helper()
	first, err := newEndpoint("192.0.2.10:443", "one.example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := newEndpoint("192.0.2.20:443", "two.example")
	if err != nil {
		t.Fatal(err)
	}
	return []endpoint{first, second}
}

func TestEndpointFlagCanBeRepeated(t *testing.T) {
	var values endpointList
	if err := values.Set("192.0.2.10:443,one.example"); err != nil {
		t.Fatal(err)
	}
	if err := values.Set("[2001:db8::10]:8443,two.example"); err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[1].Address != "[2001:db8::10]:8443" || values[1].Hostname != "two.example" {
		t.Fatalf("unexpected parsed endpoints: %#v", values)
	}
	if err := values.Set("missing-hostname"); err == nil {
		t.Fatal("invalid endpoint flag was accepted")
	}
}

func TestEndpointCachePrefersLastWorkingEndpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cachePath := filepath.Join(t.TempDir(), "endpoints.json")
	items := testEndpoints(t)
	pool := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkTCP)
	pool.now = func() time.Time { return now }
	pool.markSuccess(items[1])

	loaded := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkTCP)
	loaded.now = func() time.Time { return now }
	candidates, _ := loaded.candidates()
	if len(candidates) != 2 || candidates[0] != items[1] {
		t.Fatalf("cached endpoint wasn't preferred: %#v", candidates)
	}
}

func TestEndpointFailureAddsCooldown(t *testing.T) {
	now := time.Now()
	items := testEndpoints(t)
	pool := newEndpointPool(items, "", "auto", "", transportAuto, "", networkTCP)
	pool.now = func() time.Time { return now }
	pool.markFailure(items[0])
	candidates, _ := pool.candidates()
	if len(candidates) != 1 || candidates[0] != items[1] {
		t.Fatalf("failed endpoint remained available during cooldown: %#v", candidates)
	}

	now = now.Add(31 * time.Second)
	candidates, _ = pool.candidates()
	if len(candidates) != 2 || candidates[0] != items[0] {
		t.Fatalf("endpoint didn't return after cooldown: %#v", candidates)
	}
}

func TestEndpointPoolKeyDoesNotDependOnOrder(t *testing.T) {
	items := testEndpoints(t)
	reversed := []endpoint{items[1], items[0]}
	if endpointPoolKey(items) != endpointPoolKey(reversed) {
		t.Fatal("the same endpoint set produced different cache keys")
	}
}

func TestEndpointPoolsKeepTCPAndUDPStateSeparate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	items := testEndpoints(t)
	cachePath := filepath.Join(t.TempDir(), "endpoints.json")
	tcpPool := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkTCP)
	udpPool := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkUDP)
	tcpPool.now = func() time.Time { return now }
	udpPool.now = func() time.Time { return now }
	tcpPool.markSuccess(items[0])
	udpPool.markSuccess(items[1])

	loadedTCP := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkTCP)
	loadedUDP := newEndpointPool(items, cachePath, "auto", "", transportAuto, "", networkUDP)
	tcpCandidates, _ := loadedTCP.candidates()
	udpCandidates, _ := loadedUDP.candidates()
	if tcpCandidates[0] != items[0] || udpCandidates[0] != items[1] {
		t.Fatalf("TCP and UDP endpoint state was mixed: tcp=%#v udp=%#v", tcpCandidates, udpCandidates)
	}
}

func TestOpenAnyEndpointFailsOver(t *testing.T) {
	items := testEndpoints(t)
	pool := newEndpointPool(items, "", "auto", "", transportAuto, "", networkTCP)
	attempts := make([]string, 0, 2)
	opener := func(_ context.Context, config clientConfig, selector *profileSelector, transportSelector *transportSelector) (tunnelStream, error) {
		attempts = append(attempts, config.server)
		if selector != pool.profileFor(items[len(attempts)-1]) {
			t.Fatal("endpoint used another endpoint's TLS profile selector")
		}
		if transportSelector != pool.transportFor(items[len(attempts)-1]) {
			t.Fatal("endpoint used another endpoint's transport selector")
		}
		if config.server == items[0].Address {
			return nil, atStage(stageTCP, errors.New("connection refused"))
		}
		return &websocketStream{}, nil
	}

	tunnel, err := openAnyEndpointWith(context.Background(), clientConfig{}, pool, opener)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel == nil || len(attempts) != 2 || attempts[1] != items[1].Address {
		t.Fatalf("unexpected endpoint attempts: %v", attempts)
	}
	candidates, _ := pool.candidates()
	if len(candidates) == 0 || candidates[0] != items[1] {
		t.Fatalf("successful endpoint wasn't selected: %#v", candidates)
	}
}

func TestPathProbeWalksTransportAndProfileMatrix(t *testing.T) {
	profiles := newProfileSelector("auto", "", "server")
	transports := newTransportSelector(transportAuto, "", "server")
	attempts := make([]string, 0)
	opener := func(_ context.Context, config clientConfig, profile string) (tunnelStream, error) {
		attempts = append(attempts, config.transport+"/"+profile)
		return &probeTestTunnel{transport: config.transport, profile: profile}, nil
	}
	probe := func(_ context.Context, tunnel tunnelStream) error {
		selected := tunnel.(*probeTestTunnel)
		if selected.transport == transportHTTPStream && selected.profile == "firefox" {
			return nil
		}
		return atStage(stageProbe, errors.New("stream clamped"))
	}

	if err := probeEndpointPathWith(
		context.Background(),
		clientConfig{},
		profiles,
		transports,
		opener,
		probe,
	); err != nil {
		t.Fatal(err)
	}
	foundWebSocketFirefox := false
	foundHTTPFirefox := false
	for _, attempt := range attempts {
		foundWebSocketFirefox = foundWebSocketFirefox || attempt == transportWebSocket+"/firefox"
		foundHTTPFirefox = foundHTTPFirefox || attempt == transportHTTPStream+"/firefox"
	}
	if !foundWebSocketFirefox || !foundHTTPFirefox {
		t.Fatalf("probe did not walk the matrix: %v", attempts)
	}
	transportCandidates, _ := transports.candidates()
	profileCandidates, _ := profiles.candidates()
	if transportCandidates[0] != transportHTTPStream || profileCandidates[0] != "firefox" {
		t.Fatalf("working tuple was not selected: transport=%v profile=%v", transportCandidates, profileCandidates)
	}
}

func TestTrafficFailureInvalidatesWholeTuple(t *testing.T) {
	items := testEndpoints(t)
	pool := newEndpointPool(items, "", "auto", "", transportAuto, "", networkTCP)
	pool.configureCovers(coverModeOff, nil, "", networkTCP)
	base := &probeTestTunnel{}
	selected := withTunnelSelection(base, "chrome", transportWebSocket)
	tracked := trackEndpointTunnel(selected, pool, items[0], items[0].Hostname)

	reportTunnelFailure(tracked, atStage(stageTraffic, errors.New("connection reset")))

	endpointCandidates, _ := pool.candidates()
	transportCandidates, _ := pool.transportFor(items[0]).candidates()
	profileCandidates, _ := pool.profileFor(items[0]).candidates()
	if len(endpointCandidates) != 1 || endpointCandidates[0] != items[1] {
		t.Fatalf("failed endpoint was not cooled down: %v", endpointCandidates)
	}
	if transportCandidates[0] == transportWebSocket || profileCandidates[0] == "chrome" {
		t.Fatalf("failed tuple stayed preferred: transport=%v profile=%v", transportCandidates, profileCandidates)
	}
}
