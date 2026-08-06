package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDiagnosticTraceRedactsEndpointsByDefault(t *testing.T) {
	trace := newDiagnosticTrace(false)
	failed := trace.startAttempt(1, "203.0.113.10:443", "secret.example", "chrome", transportWebSocket)
	trace.finishAttempt(failed, atStage(stageTLS, errors.New("handshake failed")))
	ready := trace.startAttempt(2, "203.0.113.20:443", "working.example", "firefox", transportHTTPStream)
	trace.finishAttempt(ready, nil)

	report := diagnosticReport{
		SchemaVersion: 1,
		ClientVersion: clientVersion,
		Results: []diagnosticResult{{
			Network:  networkTCP,
			Status:   "ready",
			Stage:    "ready",
			Attempts: trace.snapshot(),
		}},
	}
	var encoded bytes.Buffer
	if err := writeDiagnosticReport(&encoded, report); err != nil {
		t.Fatal(err)
	}
	for _, secretValue := range []string{"203.0.113.10", "203.0.113.20", "secret.example", "working.example", "handshake failed"} {
		if strings.Contains(encoded.String(), secretValue) {
			t.Fatalf("diagnostic report leaked %q: %s", secretValue, encoded.String())
		}
	}
	attempts := report.Results[0].Attempts
	if attempts[0].EndpointIndex != 1 || attempts[0].ErrorCode != "tls_failed" || attempts[1].Status != "ready" {
		t.Fatalf("unexpected attempts: %#v", attempts)
	}
}

func TestDiagnosticTraceCanIncludeEndpoints(t *testing.T) {
	trace := newDiagnosticTrace(true)
	index := trace.startAttempt(3, "203.0.113.30:443", "three.example", "safari", transportWebSocket)
	trace.finishAttempt(index, nil)
	attempts := trace.snapshot()
	if len(attempts) != 1 || attempts[0].Address != "203.0.113.30:443" || attempts[0].Hostname != "three.example" {
		t.Fatalf("endpoint details were not included: %#v", attempts)
	}
}

func TestDiagnosticErrorCodesDoNotContainRawErrors(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{atStage(stageTCP, errors.New("dial 192.0.2.1: private detail")), "tcp_failed"},
		{atStage(stageTLS, errors.New("private TLS detail")), "tls_failed"},
		{atStage(stageWebSocket, errors.New("private HTTP detail")), "websocket_failed"},
		{atStage(stageHTTPStream, errors.New("private stream detail")), "http_stream_failed"},
		{atStage(stageAuth, errors.New("private auth detail")), "authentication_failed"},
	}
	for _, test := range tests {
		if got := diagnosticErrorCode(test.err); got != test.code {
			t.Errorf("diagnosticErrorCode(%v) = %q, want %q", test.err, got, test.code)
		}
	}
}

func TestSupportedDiagnosticNetwork(t *testing.T) {
	for _, value := range []string{networkTCP, networkUDP, diagnosticAll} {
		if !supportedDiagnosticNetwork(value) {
			t.Errorf("expected %q to be supported", value)
		}
	}
	if supportedDiagnosticNetwork("icmp") {
		t.Fatal("unexpected diagnostic network support")
	}
}

func TestClassifyFlowLimit(t *testing.T) {
	ready := clampTrial{Status: "complete"}
	failed := clampTrial{Status: "failed"}
	freshReady := clampDirectionResult{FreshComplete: 8, FreshPlanned: 8}
	tests := []struct {
		name     string
		upload   clampDirectionResult
		download clampDirectionResult
		want     string
	}{
		{"clear", clampDirectionResult{LongFlow: ready}, clampDirectionResult{LongFlow: ready}, "no_per_flow_limit_observed"},
		{"bidirectional", clampDirectionResult{LongFlow: failed, FreshComplete: freshReady.FreshComplete}, clampDirectionResult{LongFlow: failed, FreshComplete: freshReady.FreshComplete}, "likely_bidirectional_per_flow_limit"},
		{"directional", clampDirectionResult{LongFlow: failed, FreshComplete: 8}, clampDirectionResult{LongFlow: ready}, "likely_directional_per_flow_limit"},
		{"aggregate", clampDirectionResult{LongFlow: failed}, clampDirectionResult{LongFlow: failed}, "possible_endpoint_or_aggregate_filtering"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyFlowLimit(test.upload, test.download); got != test.want {
				t.Fatalf("classifyFlowLimit() = %q, want %q", got, test.want)
			}
		})
	}
}
