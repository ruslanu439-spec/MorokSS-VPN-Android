package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeTraceRecordsRealFlowWithoutSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.jsonl")
	config := clientConfig{
		networkScope: "cellular", burstUpload: true, burstChunk: 1024,
		burstSlots: make(chan struct{}, 8), burstDownloadSlots: make(chan struct{}, 4),
	}
	trace, err := openRuntimeTrace(path, config)
	if err != nil {
		t.Fatal(err)
	}
	config.runtimeTrace = trace
	config.runtimeConnectionID = trace.startFlow(networkTCP)
	config.network = networkBurstUpload
	config.endpointIndex = 1
	trace.tunnelAttempt(config, "android", time.Now().Add(-20*time.Millisecond),
		atStage(stageTCP, errors.New("dial 203.0.113.9:24443: private failure")))
	trace.burstAttempt(config, "upload", "0123456789abcdef", 7, 2, 1024,
		30*time.Millisecond, 80*time.Millisecond, "written", nil)
	trace.finishFlow(config.runtimeConnectionID, nil)
	trace.close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"203.0.113.9", "private failure", "0123456789abcdef"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("runtime trace leaked %q: %s", forbidden, text)
		}
	}
	for _, expected := range []string{
		`"event":"client_start"`, `"event":"connection_start"`,
		`"error_code":"tcp_failed"`, `"session_ref":"01234567"`,
		`"upload_bytes":1024`, `"event":"client_stop"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("runtime trace does not contain %s: %s", expected, text)
		}
	}
}

func TestRuntimeTraceSessionRefIsBounded(t *testing.T) {
	if got := runtimeSessionRef("short"); got != "short" {
		t.Fatalf("short session reference changed: %q", got)
	}
	if got := runtimeSessionRef("0123456789abcdef"); got != "01234567" {
		t.Fatalf("long session reference was not bounded: %q", got)
	}
}

func TestRuntimeTraceTreatsLocalEOFAsNormalClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.jsonl")
	trace, err := openRuntimeTrace(path, clientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	id := trace.startFlow(networkTCP)
	trace.finishFlow(id, io.EOF)
	trace.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"event":"connection_finish"`) ||
		!strings.Contains(string(data), `"status":"closed"`) {
		t.Fatalf("EOF was not recorded as a normal close: %s", data)
	}
}
