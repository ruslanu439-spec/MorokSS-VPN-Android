package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

var testSecret = []byte("test-secret-that-is-longer-than-thirty-two-bytes")

func TestDailyPathMatchesPythonImplementation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	want := "/api/events/2095cc607656991d79ad85bc3d4a4c40"
	if got := dailyPath(testSecret, now); got != want {
		t.Fatalf("dailyPath() = %q, want %q", got, want)
	}
}

func TestAuthMatchesPythonImplementation(t *testing.T) {
	random := bytes.NewReader(append([]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
	}, 0))
	got, err := makeAuth(testSecret, time.Unix(1700000000, 0), random)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("000000006553f100000102030405060708090a0b0c0d0e0fc63aff39ea5481a2f2e59c111ed814dd9c08accf701802e86d67007eaf8f5e26")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("authentication vector mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	random := bytes.NewReader(make([]byte, 12289))
	payload, err := packEnvelope([]byte("hello"), random)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 512 {
		t.Fatalf("padded envelope length = %d, want 512", len(payload))
	}
	data, err := unpackEnvelope(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("unpacked data = %q", data)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{'u'}, 32*1024)
	payload, err := packDatagram(data, bytes.NewReader(make([]byte, len(data)+16)))
	if err != nil {
		t.Fatal(err)
	}
	unpacked, err := unpackDatagram(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpacked, data) {
		t.Fatal("datagram payload changed during framing")
	}
}

func TestClientHelloProfiles(t *testing.T) {
	for _, profile := range []string{"chrome", "firefox", "safari", "edge", "ios", "android", "randomized"} {
		if _, err := clientHelloID(profile); err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
	}
	if _, err := clientHelloID("unknown"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}

func TestHTTPHeadRejectsOversizedFirstLine(t *testing.T) {
	request := bytes.Repeat([]byte{'x'}, 16*1024+1)
	request = append(request, '\r', '\n', '\r', '\n')
	reader := bufio.NewReaderSize(bytes.NewReader(request), 16*1024)
	if _, _, err := readHTTPHead(reader); err == nil {
		t.Fatal("oversized HTTP first line was accepted")
	}
}

func TestWebSocketRejectsOversizedControlFrame(t *testing.T) {
	frame := append([]byte{0x88, 126, 0, 126}, make([]byte, 126)...)
	stream := &websocketStream{reader: bufio.NewReader(bytes.NewReader(frame))}
	if _, _, err := stream.readFrame(); err == nil {
		t.Fatal("oversized WebSocket control frame was accepted")
	}
}
