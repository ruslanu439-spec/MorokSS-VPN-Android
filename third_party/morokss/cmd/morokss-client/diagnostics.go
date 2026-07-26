package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	clientVersion = "0.3.2"
	diagnosticAll = "all"
)

type diagnosticAttempt struct {
	EndpointIndex int    `json:"endpoint_index,omitempty"`
	Address       string `json:"address,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	TLSProfile    string `json:"tls_profile"`
	Transport     string `json:"transport"`
	Status        string `json:"status"`
	Stage         string `json:"stage"`
	ErrorCode     string `json:"error_code,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	startedAt     time.Time
}

type diagnosticSelection struct {
	EndpointIndex int    `json:"endpoint_index"`
	Address       string `json:"address,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	TLSProfile    string `json:"tls_profile"`
	Transport     string `json:"transport"`
}

type diagnosticResult struct {
	Network    string               `json:"network"`
	Status     string               `json:"status"`
	Stage      string               `json:"stage"`
	ErrorCode  string               `json:"error_code,omitempty"`
	DurationMS int64                `json:"duration_ms"`
	Selected   *diagnosticSelection `json:"selected,omitempty"`
	Attempts   []diagnosticAttempt  `json:"attempts"`
}

type diagnosticReport struct {
	SchemaVersion int                `json:"schema_version"`
	ClientVersion string             `json:"client_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Results       []diagnosticResult `json:"results"`
}

type diagnosticTrace struct {
	mu               sync.Mutex
	includeEndpoints bool
	attempts         []diagnosticAttempt
}

func newDiagnosticTrace(includeEndpoints bool) *diagnosticTrace {
	return &diagnosticTrace{includeEndpoints: includeEndpoints}
}

func (trace *diagnosticTrace) startAttempt(endpointIndex int, address, hostname, profile, transport string) int {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	attempt := diagnosticAttempt{
		EndpointIndex: endpointIndex,
		TLSProfile:    profile,
		Transport:     transport,
		Status:        "running",
		Stage:         "connecting",
		startedAt:     time.Now(),
	}
	if trace.includeEndpoints {
		attempt.Address = address
		attempt.Hostname = hostname
	}
	trace.attempts = append(trace.attempts, attempt)
	return len(trace.attempts) - 1
}

func (trace *diagnosticTrace) finishAttempt(index int, err error) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if index < 0 || index >= len(trace.attempts) {
		return
	}
	attempt := &trace.attempts[index]
	attempt.DurationMS = time.Since(attempt.startedAt).Milliseconds()
	if err == nil {
		attempt.Status = "ready"
		attempt.Stage = "ready"
		return
	}
	attempt.Status = "failed"
	attempt.Stage = diagnosticStage(err)
	attempt.ErrorCode = diagnosticErrorCode(err)
}

func (trace *diagnosticTrace) snapshot() []diagnosticAttempt {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	result := make([]diagnosticAttempt, len(trace.attempts))
	copy(result, trace.attempts)
	for index := range result {
		result[index].startedAt = time.Time{}
	}
	return result
}

func supportedDiagnosticNetwork(value string) bool {
	return value == networkTCP || value == networkUDP || value == diagnosticAll
}

func runDiagnostics(ctx context.Context, config clientConfig, tcpPool, udpPool *endpointPool, network string, includeEndpoints bool) (diagnosticReport, bool) {
	report := diagnosticReport{
		SchemaVersion: 1,
		ClientVersion: clientVersion,
		GeneratedAt:   time.Now().UTC(),
		Results:       make([]diagnosticResult, 0, 2),
	}
	successful := true
	if network == networkTCP || network == diagnosticAll {
		result := runNetworkDiagnostic(ctx, config, tcpPool, networkTCP, includeEndpoints)
		report.Results = append(report.Results, result)
		successful = successful && result.Status == "ready"
	}
	if network == networkUDP || network == diagnosticAll {
		result := runNetworkDiagnostic(ctx, config, udpPool, networkUDP, includeEndpoints)
		report.Results = append(report.Results, result)
		successful = successful && result.Status == "ready"
	}
	return report, successful
}

func runNetworkDiagnostic(ctx context.Context, config clientConfig, pool *endpointPool, network string, includeEndpoints bool) diagnosticResult {
	startedAt := time.Now()
	trace := newDiagnosticTrace(includeEndpoints)
	config.network = network
	config.diagnostics = trace
	result := diagnosticResult{Network: network, Status: "failed", Stage: "selection", Attempts: []diagnosticAttempt{}}
	if pool == nil {
		result.ErrorCode = "no_endpoint_pool"
		return result
	}
	tunnel, err := openAnyEndpoint(ctx, config, pool)
	result.DurationMS = time.Since(startedAt).Milliseconds()
	result.Attempts = trace.snapshot()
	if err != nil {
		result.Stage = diagnosticStage(err)
		result.ErrorCode = diagnosticErrorCode(err)
		if len(result.Attempts) > 0 {
			last := result.Attempts[len(result.Attempts)-1]
			result.Stage = last.Stage
			result.ErrorCode = last.ErrorCode
		}
		return result
	}
	tunnel.close()
	result.Status = "ready"
	result.Stage = "ready"
	for index := len(result.Attempts) - 1; index >= 0; index-- {
		attempt := result.Attempts[index]
		if attempt.Status == "ready" {
			result.Selected = &diagnosticSelection{
				EndpointIndex: attempt.EndpointIndex,
				Address:       attempt.Address,
				Hostname:      attempt.Hostname,
				TLSProfile:    attempt.TLSProfile,
				Transport:     attempt.Transport,
			}
			break
		}
	}
	return result
}

func diagnosticStage(err error) string {
	if stage, found := errorStage(err); found {
		return string(stage)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	return "selection"
}

func diagnosticErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) || errors.As(err, &invalidCertificate) {
		return "certificate"
	}
	switch stage, _ := errorStage(err); stage {
	case stageTCP:
		return "tcp_failed"
	case stageTLS:
		return "tls_failed"
	case stageWebSocket:
		return "websocket_failed"
	case stageHTTPStream:
		return "http_stream_failed"
	case stageAuth:
		return "authentication_failed"
	case stageProbe:
		return "path_probe_failed"
	default:
		return "unavailable"
	}
}

func writeDiagnosticReport(destination io.Writer, report diagnosticReport) error {
	encoder := json.NewEncoder(destination)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}
