package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	clientVersion = "0.4.0-alpha13"
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
	SchemaVersion int                   `json:"schema_version"`
	ClientVersion string                `json:"client_version"`
	GeneratedAt   time.Time             `json:"generated_at"`
	BurstUpload   diagnosticBurstConfig `json:"burst_upload"`
	FlowLimit     *flowLimitDiagnostic  `json:"flow_limit,omitempty"`
	Results       []diagnosticResult    `json:"results"`
}

type diagnosticBurstConfig struct {
	Enabled            bool `json:"enabled"`
	ChunkBytes         int  `json:"chunk_bytes"`
	Parallel           int  `json:"parallel"`
	GlobalParallel     bool `json:"global_parallel"`
	DownloadParallel   int  `json:"download_parallel"`
	DownloadChunkBytes int  `json:"download_chunk_bytes,omitempty"`
}

type clampProbeRequest struct {
	Version       int    `json:"version"`
	TraceID       string `json:"trace_id"`
	UploadBytes   int    `json:"upload_bytes"`
	DownloadBytes int    `json:"download_bytes"`
	ChunkBytes    int    `json:"chunk_bytes"`
}

type clampProbeAck struct {
	Version          int    `json:"version"`
	TraceID          string `json:"trace_id"`
	Direction        string `json:"direction"`
	Bytes            int    `json:"bytes"`
	SHA256           string `json:"sha256"`
	ServerDurationMS int64  `json:"server_duration_ms,omitempty"`
}

type clampTrial struct {
	TraceID          string `json:"trace_id"`
	Status           string `json:"status"`
	Stage            string `json:"stage"`
	ErrorCode        string `json:"error_code,omitempty"`
	UploadBytes      int    `json:"upload_bytes"`
	DownloadBytes    int    `json:"download_bytes"`
	DurationMS       int64  `json:"duration_ms"`
	ServerDurationMS int64  `json:"server_duration_ms,omitempty"`
}

type clampDirectionResult struct {
	LongFlow      clampTrial   `json:"long_flow"`
	FreshFlows    []clampTrial `json:"fresh_flows"`
	FreshComplete int          `json:"fresh_complete"`
	FreshPlanned  int          `json:"fresh_planned"`
}

type flowLimitDiagnostic struct {
	Status               string                  `json:"status"`
	Classification       string                  `json:"classification"`
	Selected             *diagnosticSelection    `json:"selected,omitempty"`
	Baseline             clampTrial              `json:"baseline"`
	Upload               *clampDirectionResult   `json:"upload,omitempty"`
	Download             *clampDirectionResult   `json:"download,omitempty"`
	PathCharacterization *pathCharacterization   `json:"path_characterization,omitempty"`
	BurstRuntime         *burstRuntimeDiagnostic `json:"burst_runtime,omitempty"`
}

type burstRuntimeDiagnostic struct {
	Status          string `json:"status"`
	Stage           string `json:"stage"`
	ErrorCode       string `json:"error_code,omitempty"`
	ControlDetached bool   `json:"control_detached"`
	UploadBytes     int    `json:"upload_bytes"`
	DownloadBytes   int    `json:"download_bytes"`
	UploadFlows     int    `json:"upload_flows"`
	DownloadFlows   int    `json:"download_flows"`
	DurationMS      int64  `json:"duration_ms"`
}

type pathCharacterization struct {
	Status                   string                `json:"status"`
	UploadLadder             []clampTrial          `json:"upload_ladder"`
	MaxSuccessfulUploadBytes int                   `json:"max_successful_upload_bytes"`
	MinFailedUploadBytes     int                   `json:"min_failed_upload_bytes,omitempty"`
	EstimatedUploadBPS       int64                 `json:"estimated_upload_bytes_per_second,omitempty"`
	SevereUpstreamDelay      bool                  `json:"severe_upstream_delay"`
	DirectionalAsymmetry     bool                  `json:"directional_asymmetry"`
	RecommendedBurst         diagnosticBurstConfig `json:"recommended_burst"`
	Observations             []string              `json:"observations"`
}

type uploadLadderStep struct {
	bytes   int
	timeout time.Duration
}

type clampTarget struct {
	endpoint  endpoint
	index     int
	tlsSNI    string
	profile   string
	transport string
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
		SchemaVersion: 4,
		ClientVersion: clientVersion,
		GeneratedAt:   time.Now().UTC(),
		BurstUpload: diagnosticBurstConfig{
			Enabled: config.burstUpload, ChunkBytes: config.burstChunk, Parallel: config.burstParallel,
			GlobalParallel: true, DownloadParallel: burstReservedDownloads(config.burstParallel), DownloadChunkBytes: burstDownloadChunk,
		},
		Results: make([]diagnosticResult, 0, 2),
	}
	successful := true
	if network == networkTCP || network == diagnosticAll {
		flowLimit := runFlowLimitDiagnostic(ctx, config, tcpPool, includeEndpoints)
		report.FlowLimit = &flowLimit
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

const (
	clampLongBytes   = 96 * 1024
	clampFreshBytes  = 12 * 1024
	clampFreshTrials = 8
	clampChunkBytes  = 4 * 1024
)

func runFlowLimitDiagnostic(ctx context.Context, config clientConfig, pool *endpointPool, includeEndpoints bool) flowLimitDiagnostic {
	result := flowLimitDiagnostic{Status: "failed", Classification: "unavailable"}
	if pool == nil {
		result.Baseline = failedClampTrial("", 2048, 2048, errors.New("no endpoint pool"), 0)
		return result
	}
	target, baseline, found := selectClampTarget(ctx, config, pool)
	result.Baseline = baseline
	if !found {
		result.Classification = "server_diagnostic_unavailable"
		return result
	}
	selection := &diagnosticSelection{
		EndpointIndex: target.index,
		TLSProfile:    target.profile,
		Transport:     target.transport,
	}
	if includeEndpoints {
		selection.Address = target.endpoint.Address
		selection.Hostname = target.endpoint.Hostname
	}
	result.Selected = selection
	result.Status = "complete"
	result.Upload = runClampDirection(ctx, config, target, true)
	result.Download = runClampDirection(ctx, config, target, false)
	result.Classification = classifyFlowLimit(*result.Upload, *result.Download)
	characterization := runPathCharacterization(ctx, config, target, *result.Upload, *result.Download)
	result.PathCharacterization = &characterization
	if config.burstUpload && ctx.Err() == nil {
		burstRuntime := runBurstRuntimeDiagnostic(ctx, config, target)
		result.BurstRuntime = &burstRuntime
	}
	return result
}

func runBurstRuntimeDiagnostic(ctx context.Context, config clientConfig, target clampTarget) burstRuntimeDiagnostic {
	const payloadBytes = 8 * 1024
	started := time.Now()
	result := burstRuntimeDiagnostic{
		Status:      "failed",
		Stage:       "connecting",
		UploadBytes: payloadBytes,
	}
	fail := func(err error) burstRuntimeDiagnostic {
		result.Stage = diagnosticStage(err)
		result.ErrorCode = diagnosticErrorCode(err)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}

	probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	current := config
	current.server = target.endpoint.Address
	current.hostname = target.endpoint.Hostname
	current.tlsSNI = target.tlsSNI
	current.endpointIndex = target.index
	current.profile = target.profile
	current.transport = target.transport
	current.network = networkBurstOpen
	current.diagnostics = nil
	control, err := openTunnelWithProfile(probeCtx, current, target.profile)
	if err != nil {
		return fail(err)
	}

	sessionID, err := newBurstSessionID(rand.Reader)
	if err != nil {
		control.close()
		return fail(err)
	}
	if err := openBurstSessionMode(probeCtx, control, sessionID, true); err != nil {
		control.close()
		return fail(err)
	}
	routeConfig := current
	routeConfig.network = networkBurstUpload
	route := burstRoute{config: routeConfig, profile: target.profile}
	control.close()
	result.ControlDetached = true
	select {
	case <-time.After(300 * time.Millisecond):
	case <-probeCtx.Done():
		return fail(probeCtx.Err())
	}

	payload := make([]byte, payloadBytes)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return fail(err)
	}
	chunkSize := config.burstChunk
	chunkCount := (len(payload) + chunkSize - 1) / chunkSize
	errorsByFlow := make(chan error, chunkCount)
	var uploads sync.WaitGroup
	for sequence := 0; sequence < chunkCount; sequence++ {
		start := sequence * chunkSize
		end := min(start+chunkSize, len(payload))
		data := append([]byte(nil), payload[start:end]...)
		uploads.Add(1)
		go func(sequence uint64, data []byte) {
			defer uploads.Done()
			errorsByFlow <- uploadBurstChunkWithRetry(probeCtx, route, sessionID, sequence, data, false)
		}(uint64(sequence), data)
	}
	uploads.Wait()
	close(errorsByFlow)
	result.UploadFlows = chunkCount + 1
	for uploadErr := range errorsByFlow {
		if uploadErr != nil {
			return fail(uploadErr)
		}
	}
	if err := uploadBurstChunkWithRetry(probeCtx, route, sessionID, uint64(chunkCount), nil, true); err != nil {
		return fail(err)
	}

	received := make([]byte, 0, len(payload))
	sequence := uint64(0)
	for {
		download, err := downloadBurstChunkWithRetry(probeCtx, route, sessionID, sequence)
		result.DownloadFlows++
		if err != nil {
			return fail(err)
		}
		if download.idle {
			continue
		}
		received = append(received, download.data...)
		sequence++
		if len(received) > len(payload)+burstDownloadChunk {
			return fail(atStage(stageTraffic, errors.New("burst probe returned excess data")))
		}
		if download.fin {
			break
		}
	}
	result.DownloadBytes = len(received)
	wantHash := sha256.Sum256(payload)
	gotHash := sha256.Sum256(received)
	if wantHash != gotHash {
		return fail(atStage(stageTraffic, errors.New("burst probe hash mismatch")))
	}
	result.Status = "complete"
	result.Stage = "complete"
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func runPathCharacterization(
	ctx context.Context,
	config clientConfig,
	target clampTarget,
	upload clampDirectionResult,
	download clampDirectionResult,
) pathCharacterization {
	steps := []uploadLadderStep{
		{bytes: 512, timeout: 20 * time.Second},
		{bytes: 1024, timeout: 20 * time.Second},
		{bytes: 2048, timeout: 25 * time.Second},
		{bytes: 4096, timeout: 35 * time.Second},
		{bytes: 8192, timeout: 55 * time.Second},
	}
	trials := make([]clampTrial, 0, len(steps)+1)
	for _, step := range steps {
		if ctx.Err() != nil {
			break
		}
		trials = append(trials, runClampTrial(ctx, config, target, step.bytes, 0, step.timeout))
	}
	// Reuse the already measured 12 KiB fresh-flow result instead of adding
	// another long trial to an intentionally comprehensive mobile diagnostic.
	if len(upload.FreshFlows) > 0 {
		trials = append(trials, upload.FreshFlows[0])
	}
	return analyzePathCharacterization(trials, upload, download)
}

func analyzePathCharacterization(
	trials []clampTrial,
	upload clampDirectionResult,
	download clampDirectionResult,
) pathCharacterization {
	result := pathCharacterization{
		Status:       "complete",
		UploadLadder: trials,
		RecommendedBurst: diagnosticBurstConfig{
			Enabled: false, ChunkBytes: 1024, Parallel: 2, GlobalParallel: true,
			DownloadParallel:   1,
			DownloadChunkBytes: burstDownloadChunk,
		},
		Observations: make([]string, 0, 4),
	}
	result.RecommendedBurst.Enabled = upload.LongFlow.Status != "complete" || download.LongFlow.Status != "complete"
	var throughputTrial *clampTrial
	for index := range trials {
		trial := &trials[index]
		if trial.Status == "complete" {
			if trial.UploadBytes > result.MaxSuccessfulUploadBytes {
				result.MaxSuccessfulUploadBytes = trial.UploadBytes
				throughputTrial = trial
			}
			if trial.ServerDurationMS >= 5000 || trial.DurationMS >= 10000 {
				result.SevereUpstreamDelay = true
			}
		} else if result.MinFailedUploadBytes == 0 || trial.UploadBytes < result.MinFailedUploadBytes {
			result.MinFailedUploadBytes = trial.UploadBytes
		}
	}
	if throughputTrial != nil && throughputTrial.ServerDurationMS > 0 {
		result.EstimatedUploadBPS = int64(throughputTrial.UploadBytes) * 1000 / throughputTrial.ServerDurationMS
	}
	result.DirectionalAsymmetry = upload.FreshComplete < upload.FreshPlanned/2 &&
		download.FreshComplete >= download.FreshPlanned/2
	if result.SevereUpstreamDelay {
		result.Observations = append(result.Observations, "severe_upstream_delay")
	}
	if result.DirectionalAsymmetry {
		result.Observations = append(result.Observations, "upload_slower_or_less_reliable_than_download")
	}
	if result.MinFailedUploadBytes > 0 {
		result.Observations = append(result.Observations, "fresh_upload_size_boundary_observed")
	}
	if result.MaxSuccessfulUploadBytes == 0 {
		result.Status = "failed"
		result.Observations = append(result.Observations, "no_upload_ladder_step_completed")
	}
	return result
}

func selectClampTarget(ctx context.Context, config clientConfig, pool *endpointPool) (clampTarget, clampTrial, bool) {
	items, _ := pool.candidates()
	var last clampTrial
	for _, item := range items {
		transports, _ := pool.transportFor(item).candidates()
		profiles, _ := pool.profileFor(item).candidates()
		covers, _ := pool.coverFor(item).candidates()
		if len(covers) == 0 {
			covers = []string{item.Hostname}
		}
		for _, cover := range covers {
			for _, transport := range transports {
				for _, profile := range profiles {
					target := clampTarget{
						endpoint:  item,
						index:     pool.endpointIndex(item),
						tlsSNI:    cover,
						profile:   profile,
						transport: transport,
					}
					last = runClampTrial(ctx, config, target, 2048, 2048, 12*time.Second)
					if last.Status == "complete" {
						return target, last, true
					}
					if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
						return clampTarget{}, last, false
					}
				}
			}
		}
	}
	if last.TraceID == "" {
		last = failedClampTrial("", 2048, 2048, errors.New("no available clamp target"), 0)
	}
	return clampTarget{}, last, false
}

func runClampDirection(ctx context.Context, config clientConfig, target clampTarget, upload bool) *clampDirectionResult {
	uploadBytes, downloadBytes := 0, clampLongBytes
	if upload {
		uploadBytes, downloadBytes = clampLongBytes, 0
	}
	result := &clampDirectionResult{
		LongFlow:     runClampTrial(ctx, config, target, uploadBytes, downloadBytes, 18*time.Second),
		FreshFlows:   make([]clampTrial, 0, clampFreshTrials),
		FreshPlanned: clampFreshTrials,
	}
	consecutiveFailures := 0
	for index := 0; index < clampFreshTrials; index++ {
		up, down := 0, clampFreshBytes
		if upload {
			up, down = clampFreshBytes, 0
		}
		trial := runClampTrial(ctx, config, target, up, down, 10*time.Second)
		result.FreshFlows = append(result.FreshFlows, trial)
		if trial.Status == "complete" {
			result.FreshComplete++
			consecutiveFailures = 0
		} else {
			consecutiveFailures++
			if consecutiveFailures >= 3 {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result
}

func classifyFlowLimit(upload, download clampDirectionResult) string {
	freshUpload := upload.FreshComplete >= 6
	freshDownload := download.FreshComplete >= 6
	longUpload := upload.LongFlow.Status == "complete"
	longDownload := download.LongFlow.Status == "complete"
	switch {
	case longUpload && longDownload:
		return "no_per_flow_limit_observed"
	case !longUpload && !longDownload && freshUpload && freshDownload:
		return "likely_bidirectional_per_flow_limit"
	case (!longUpload && freshUpload) || (!longDownload && freshDownload):
		return "likely_directional_per_flow_limit"
	case !freshUpload && !freshDownload:
		return "possible_endpoint_or_aggregate_filtering"
	default:
		return "inconclusive"
	}
}

func runClampTrial(ctx context.Context, config clientConfig, target clampTarget, uploadBytes, downloadBytes int, timeout time.Duration) clampTrial {
	traceID, err := randomTraceID()
	if err != nil {
		return failedClampTrial("", uploadBytes, downloadBytes, err, 0)
	}
	started := time.Now()
	trialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	current := config
	current.server = target.endpoint.Address
	current.hostname = target.endpoint.Hostname
	current.endpointIndex = target.index
	current.tlsSNI = target.tlsSNI
	current.profile = target.profile
	current.transport = target.transport
	current.network = networkClamp
	current.diagnostics = nil
	tunnel, err := openTunnelWithProfile(trialCtx, current, target.profile)
	if err != nil {
		return failedClampTrial(traceID, uploadBytes, downloadBytes, err, time.Since(started))
	}
	defer tunnel.close()
	serverDuration, err := probeClampPath(trialCtx, tunnel, clampProbeRequest{
		Version: 1, TraceID: traceID, UploadBytes: uploadBytes,
		DownloadBytes: downloadBytes, ChunkBytes: clampChunkBytes,
	})
	if err != nil {
		return failedClampTrial(traceID, uploadBytes, downloadBytes, err, time.Since(started))
	}
	return clampTrial{
		TraceID: traceID, Status: "complete", Stage: "complete",
		UploadBytes: uploadBytes, DownloadBytes: downloadBytes,
		DurationMS: time.Since(started).Milliseconds(), ServerDurationMS: serverDuration,
	}
}

func failedClampTrial(traceID string, uploadBytes, downloadBytes int, err error, duration time.Duration) clampTrial {
	return clampTrial{
		TraceID: traceID, Status: "failed", Stage: diagnosticStage(err),
		ErrorCode: diagnosticErrorCode(err), UploadBytes: uploadBytes,
		DownloadBytes: downloadBytes, DurationMS: duration.Milliseconds(),
	}
}

func randomTraceID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func probeClampPath(ctx context.Context, tunnel tunnelStream, request clampProbeRequest) (int64, error) {
	deadline := time.AfterFunc(16*time.Second, tunnel.close)
	defer deadline.Stop()
	contextDone := make(chan struct{})
	defer close(contextDone)
	go func() {
		select {
		case <-ctx.Done():
			tunnel.close()
		case <-contextDone:
		}
	}()
	requestData, err := json.Marshal(request)
	if err != nil {
		return 0, atStage(stageProbe, err)
	}
	envelope, err := packEnvelope(requestData, rand.Reader)
	if err != nil {
		return 0, atStage(stageProbe, err)
	}
	if err := tunnel.sendBinary(envelope); err != nil {
		return 0, atStage(stageProbe, fmt.Errorf("send clamp request: %w", err))
	}
	uploadHash := sha256.New()
	remaining := request.UploadBytes
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		size := request.ChunkBytes
		if remaining < size {
			size = remaining
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, chunk); err != nil {
			return 0, atStage(stageProbe, err)
		}
		_, _ = uploadHash.Write(chunk)
		packed, err := packEnvelope(chunk, rand.Reader)
		if err != nil {
			return 0, atStage(stageProbe, err)
		}
		if err := tunnel.sendBinary(packed); err != nil {
			return 0, atStage(stageProbe, fmt.Errorf("clamp upload: %w", err))
		}
		remaining -= size
	}
	uploadAck, err := receiveClampAck(tunnel)
	if err != nil || uploadAck.Version != 1 || uploadAck.TraceID != request.TraceID ||
		uploadAck.Direction != "upload" || uploadAck.Bytes != request.UploadBytes ||
		uploadAck.SHA256 != hex.EncodeToString(uploadHash.Sum(nil)) {
		return 0, atStage(stageProbe, errors.New("invalid clamp upload confirmation"))
	}
	downloadHash := sha256.New()
	received := 0
	for received < request.DownloadBytes {
		payload, err := tunnel.receiveBinary()
		if err != nil {
			return 0, atStage(stageProbe, fmt.Errorf("clamp download: %w", err))
		}
		data, err := unpackEnvelope(payload)
		if err != nil || len(data) == 0 || received+len(data) > request.DownloadBytes {
			return 0, atStage(stageProbe, errors.New("invalid clamp download"))
		}
		_, _ = downloadHash.Write(data)
		received += len(data)
	}
	downloadAck, err := receiveClampAck(tunnel)
	if err != nil || downloadAck.Version != 1 || downloadAck.TraceID != request.TraceID ||
		downloadAck.Direction != "download" || downloadAck.Bytes != request.DownloadBytes ||
		downloadAck.SHA256 != hex.EncodeToString(downloadHash.Sum(nil)) {
		return 0, atStage(stageProbe, errors.New("invalid clamp download confirmation"))
	}
	return downloadAck.ServerDurationMS, nil
}

func receiveClampAck(tunnel tunnelStream) (clampProbeAck, error) {
	payload, err := tunnel.receiveBinary()
	if err != nil {
		return clampProbeAck{}, err
	}
	data, err := unpackEnvelope(payload)
	if err != nil {
		return clampProbeAck{}, err
	}
	var ack clampProbeAck
	if err := json.Unmarshal(data, &ack); err != nil {
		return clampProbeAck{}, err
	}
	return ack, nil
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
	case stageTraffic:
		return "traffic_failed"
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
