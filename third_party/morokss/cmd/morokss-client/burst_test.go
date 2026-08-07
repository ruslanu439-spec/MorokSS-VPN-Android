package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type burstTestTunnel struct {
	mu       sync.Mutex
	sent     [][]byte
	received [][]byte
	closed   bool
}

func (tunnel *burstTestTunnel) sendBinary(payload []byte) error {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	tunnel.sent = append(tunnel.sent, append([]byte(nil), payload...))
	return nil
}

func (tunnel *burstTestTunnel) receiveBinary() ([]byte, error) {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	if len(tunnel.received) == 0 {
		return nil, io.EOF
	}
	payload := tunnel.received[0]
	tunnel.received = tunnel.received[1:]
	return payload, nil
}

func (tunnel *burstTestTunnel) close() {
	tunnel.mu.Lock()
	tunnel.closed = true
	tunnel.mu.Unlock()
}

type burstLocalRecorder struct {
	bytes.Buffer
	writeClosed bool
}

func (*burstLocalRecorder) Read([]byte) (int, error)         { return 0, io.EOF }
func (*burstLocalRecorder) Close() error                     { return nil }
func (*burstLocalRecorder) LocalAddr() net.Addr              { return nil }
func (*burstLocalRecorder) RemoteAddr() net.Addr             { return nil }
func (*burstLocalRecorder) SetDeadline(time.Time) error      { return nil }
func (*burstLocalRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*burstLocalRecorder) SetWriteDeadline(time.Time) error { return nil }
func (local *burstLocalRecorder) CloseWrite() error {
	local.writeClosed = true
	return nil
}

func packedBurstTestValue(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := packBurstEnvelope(data, strings.NewReader(strings.Repeat("x", 16384)))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func packedBurstTestData(t *testing.T, data []byte) []byte {
	t.Helper()
	payload, err := packBurstEnvelope(data, bytes.NewReader(make([]byte, 16384)))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestBurstConfigValidation(t *testing.T) {
	valid := clientConfig{burstChunk: defaultBurstChunk, burstParallel: defaultBurstParallel}
	if err := validateBurstConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []clientConfig{
		{burstChunk: minBurstChunk - 1, burstParallel: 1},
		{burstChunk: maxBurstChunk + 1, burstParallel: 1},
		{burstChunk: minBurstChunk, burstParallel: 0},
		{burstChunk: minBurstChunk, burstParallel: maxBurstParallel + 1},
	} {
		if validateBurstConfig(invalid) == nil {
			t.Fatalf("accepted invalid burst config: %#v", invalid)
		}
	}
}

func TestBurstEnvelopeUsesBoundedPadding(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, defaultBurstChunk)
	payload, err := packBurstEnvelope(data, bytes.NewReader(make([]byte, 16384)))
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 2048 {
		t.Fatalf("default burst envelope is %d bytes, want 2048", len(payload))
	}
	unpacked, err := unpackEnvelope(payload)
	if err != nil || !bytes.Equal(unpacked, data) {
		t.Fatalf("burst envelope did not round-trip: %v", err)
	}
	maximum, err := packBurstEnvelope(bytes.Repeat([]byte{1}, maxBurstChunk), bytes.NewReader(make([]byte, 16384)))
	if err != nil {
		t.Fatal(err)
	}
	if len(maximum) != maxBurstChunk+2 {
		t.Fatalf("explicit maximum burst envelope is %d bytes", len(maximum))
	}
}

func TestOpenBurstSessionJSON(t *testing.T) {
	sessionID := strings.Repeat("a", 32)
	tunnel := &burstTestTunnel{received: [][]byte{packedBurstTestValue(t, burstOpenAck{
		Version: 1, SessionID: sessionID, Status: "open",
	})}}
	if err := openBurstSession(context.Background(), tunnel, sessionID); err != nil {
		t.Fatal(err)
	}
	data, err := unpackEnvelope(tunnel.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	var request burstOpenRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if request.Version != 1 || request.SessionID != sessionID {
		t.Fatalf("unexpected burst open request: %#v", request)
	}
}

func TestBurstRouteKeepsExactSelection(t *testing.T) {
	item, err := newEndpoint("203.0.113.7:443", "origin.example")
	if err != nil {
		t.Fatal(err)
	}
	pool := newEndpointPool([]endpoint{item}, "", "auto", "", transportAuto, "", networkTCP)
	base := clientConfig{protectPath: "/protect", burstSlots: make(chan struct{}, 4)}
	tracked := trackEndpointTunnel(withTunnelSelection(&burstTestTunnel{}, "android", transportHTTPStream), pool, item, "cover.example")
	route, err := routeFromEndpointTunnel(base, tracked)
	if err != nil {
		t.Fatal(err)
	}
	if route.config.server != item.Address || route.config.hostname != item.Hostname ||
		route.config.tlsSNI != "cover.example" || route.profile != "android" ||
		route.config.transport != transportHTTPStream || route.config.network != networkBurstUpload ||
		route.config.protectPath != base.protectPath || route.config.burstSlots != base.burstSlots {
		t.Fatalf("exact burst route was not preserved: %#v", route)
	}
}

func TestBurstUploadAckInvariants(t *testing.T) {
	valid := []burstUploadAck{
		{Status: "written", NextSequence: 4},
		{Status: "duplicate", NextSequence: 7},
		{Status: "pending", NextSequence: 2},
	}
	for _, ack := range valid {
		if err := validateBurstUploadAck(ack, 3, false); err != nil {
			t.Fatalf("rejected valid ACK %#v: %v", ack, err)
		}
	}
	invalid := []burstUploadAck{
		{Status: "written", NextSequence: 3},
		{Status: "pending", NextSequence: 4},
		{Status: "rejected", NextSequence: 4},
	}
	for _, ack := range invalid {
		if validateBurstUploadAck(ack, 3, false) == nil {
			t.Fatalf("accepted invalid ACK %#v", ack)
		}
	}
	if err := validateBurstUploadAck(burstUploadAck{Status: "written", NextSequence: 4}, 3, true); err != nil {
		t.Fatal(err)
	}
	if validateBurstUploadAck(burstUploadAck{Status: "pending", NextSequence: 3}, 3, true) == nil {
		t.Fatal("accepted pending FIN acknowledgement")
	}
}

func TestBurstSlotsAreProcessShared(t *testing.T) {
	slots := make(chan struct{}, 1)
	if err := acquireBurstSlot(context.Background(), slots); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := acquireBurstSlot(ctx, slots); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second session bypassed shared slot: %v", err)
	}
	releaseBurstSlot(slots)
	if err := acquireBurstSlot(context.Background(), slots); err != nil {
		t.Fatal(err)
	}
	releaseBurstSlot(slots)
}

func TestReadBurstChunkCoalescesSmallWrites(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write([]byte("one"))
		time.Sleep(2 * time.Millisecond)
		_, _ = server.Write([]byte("two"))
	}()
	buffer := make([]byte, 32)
	count, err := readBurstChunk(client, buffer, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "onetwo" {
		t.Fatalf("small writes were not coalesced: %q", buffer[:count])
	}
}

func TestBurstDownloadAckInvariants(t *testing.T) {
	idle, err := validateBurstDownloadAck(burstDownloadAck{
		Status: "idle", NextSequence: 3,
	}, 3)
	if err != nil || !idle {
		t.Fatalf("valid idle acknowledgement was rejected: idle=%v err=%v", idle, err)
	}
	for _, ack := range []burstDownloadAck{
		{Status: "written", NextSequence: 4, Length: 1024},
		{Status: "duplicate", NextSequence: 6, Length: 512},
		{Status: "written", NextSequence: 4, Fin: true},
	} {
		idle, err := validateBurstDownloadAck(ack, 3)
		if err != nil || idle {
			t.Fatalf("valid acknowledgement was rejected: %#v idle=%v err=%v", ack, idle, err)
		}
	}
	for _, ack := range []burstDownloadAck{
		{Status: "idle", NextSequence: 4},
		{Status: "written", NextSequence: 3, Length: 1},
		{Status: "written", NextSequence: 4, Length: 1, Fin: true},
		{Status: "rejected", NextSequence: 4},
	} {
		if _, err := validateBurstDownloadAck(ack, 3); err == nil {
			t.Fatalf("invalid acknowledgement was accepted: %#v", ack)
		}
	}
}
