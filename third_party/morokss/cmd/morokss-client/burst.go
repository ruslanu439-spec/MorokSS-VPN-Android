package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	minBurstChunk         = 1024
	maxBurstChunk         = 8192
	defaultBurstChunk     = 1024
	minBurstParallel      = 1
	maxBurstParallel      = 8
	defaultBurstParallel  = 8
	burstUploadAttempts   = 3
	burstAttemptTimeout   = 20 * time.Second
	burstResponseTimeout  = 15 * time.Second
	burstCoalesceDelay    = 15 * time.Millisecond
	burstDownloadChunk    = 8 * 1024
	burstDownloadParallel = 8
	burstDownloadIdle     = 50 * time.Millisecond
)

type burstOpenRequest struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Probe     bool   `json:"probe,omitempty"`
}

type burstOpenAck struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

type burstUploadHeader struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	Fin       bool   `json:"fin"`
	Length    int    `json:"length"`
}

type burstUploadAck struct {
	Version      int    `json:"version"`
	SessionID    string `json:"session_id"`
	Sequence     uint64 `json:"sequence"`
	Status       string `json:"status"`
	NextSequence uint64 `json:"next_sequence"`
	Fin          bool   `json:"fin"`
}

type burstDownloadRequest struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	MaxLength int    `json:"max_length"`
}

type burstDownloadAck struct {
	Version      int    `json:"version"`
	SessionID    string `json:"session_id"`
	Sequence     uint64 `json:"sequence"`
	Status       string `json:"status"`
	NextSequence uint64 `json:"next_sequence"`
	Length       int    `json:"length"`
	SHA256       string `json:"sha256"`
	Fin          bool   `json:"fin"`
}

type burstDownloadResult struct {
	data []byte
	fin  bool
	idle bool
}

type burstDownloadOutcome struct {
	sequence uint64
	result   burstDownloadResult
	err      error
}

type burstRoute struct {
	config  clientConfig
	profile string
}

type burstChunk struct {
	sequence uint64
	data     []byte
}

func validateBurstConfig(config clientConfig) error {
	if config.burstChunk < minBurstChunk || config.burstChunk > maxBurstChunk {
		return fmt.Errorf("--burst-chunk must be between %d and %d", minBurstChunk, maxBurstChunk)
	}
	if config.burstParallel < minBurstParallel || config.burstParallel > maxBurstParallel {
		return fmt.Errorf("--burst-parallel must be between %d and %d", minBurstParallel, maxBurstParallel)
	}
	return nil
}

func newBurstSessionID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("read burst session ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func routeFromEndpointTunnel(base clientConfig, tunnel tunnelStream) (burstRoute, error) {
	selected, ok := tunnel.(*endpointTunnel)
	if !ok || selected.profile == "" || selected.wire == "" {
		return burstRoute{}, errors.New("burst control tunnel has no exact endpoint route")
	}
	current := base
	current.server = selected.item.Address
	current.hostname = selected.item.Hostname
	current.tlsSNI = selected.cover
	current.endpointIndex = selected.pool.endpointIndex(selected.item)
	current.profile = selected.profile
	current.transport = selected.wire
	current.network = networkBurstUpload
	current.diagnostics = nil
	return burstRoute{config: current, profile: selected.profile}, nil
}

func sendBurstJSON(tunnel tunnelStream, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode burst message: %w", err)
	}
	envelope, err := packBurstEnvelope(data, rand.Reader)
	if err != nil {
		return fmt.Errorf("pack burst message: %w", err)
	}
	if err := tunnel.sendBinary(envelope); err != nil {
		return fmt.Errorf("send burst message: %w", err)
	}
	return nil
}

func receiveBurstFrame(ctx context.Context, tunnel tunnelStream) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			tunnel.close()
		case <-stop:
		}
	}()
	timer := time.AfterFunc(burstResponseTimeout, tunnel.close)
	payload, err := tunnel.receiveBinary()
	if !timer.Stop() && err == nil {
		err = errors.New("burst response timed out")
	}
	close(stop)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("receive burst message: %w", err)
	}
	data, err := unpackEnvelope(payload)
	if err != nil {
		return nil, fmt.Errorf("unpack burst message: %w", err)
	}
	return data, nil
}

func receiveBurstJSON(ctx context.Context, tunnel tunnelStream, value any) error {
	data, err := receiveBurstFrame(ctx, tunnel)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode burst message: %w", err)
	}
	return nil
}

func openBurstSession(ctx context.Context, tunnel tunnelStream, sessionID string) error {
	return openBurstSessionMode(ctx, tunnel, sessionID, false)
}

func openBurstSessionMode(ctx context.Context, tunnel tunnelStream, sessionID string, probe bool) error {
	request := burstOpenRequest{Version: 1, SessionID: sessionID, Probe: probe}
	if err := sendBurstJSON(tunnel, request); err != nil {
		return atStage(stageAuth, err)
	}
	var ack burstOpenAck
	if err := receiveBurstJSON(ctx, tunnel, &ack); err != nil {
		return atStage(stageAuth, err)
	}
	if ack.Version != 1 || ack.SessionID != sessionID || ack.Status != "open" {
		return atStage(stageAuth, errors.New("invalid burst open acknowledgement"))
	}
	return nil
}

func handleBurstLocal(ctx context.Context, local net.Conn, config clientConfig, pool *endpointPool) error {
	controlConfig := config
	controlConfig.network = networkBurstOpen
	control, err := openAnyEndpoint(ctx, controlConfig, pool)
	if err != nil {
		return err
	}
	defer control.close()

	route, err := routeFromEndpointTunnel(config, control)
	if err != nil {
		return err
	}
	sessionID, err := newBurstSessionID(rand.Reader)
	if err != nil {
		return err
	}
	if err := openBurstSession(ctx, control, sessionID); err != nil {
		reportTunnelFailure(control, err)
		return err
	}

	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	uploadDone := make(chan error, 1)
	downloadDone := make(chan error, 1)
	go func() {
		uploadDone <- runBurstUploads(connectionCtx, local, route, sessionID, config.burstChunk, config.burstParallel)
	}()
	go func() {
		downloadDone <- relayBurstDownload(connectionCtx, route, sessionID, local)
	}()

	var uploadResult, downloadResult error
	for uploadDone != nil || downloadDone != nil {
		select {
		case err := <-uploadDone:
			uploadDone = nil
			uploadResult = err
			if err != nil {
				cancel()
				control.close()
				_ = local.Close()
			}
		case err := <-downloadDone:
			downloadDone = nil
			downloadResult = err
			if err != nil {
				cancel()
				control.close()
				_ = local.Close()
			}
		case <-ctx.Done():
			cancel()
			control.close()
			_ = local.Close()
			if uploadDone != nil {
				uploadResult = <-uploadDone
				uploadDone = nil
			}
			if downloadDone != nil {
				downloadResult = <-downloadDone
				downloadDone = nil
			}
		}
	}
	if uploadResult != nil && !errors.Is(uploadResult, context.Canceled) {
		return uploadResult
	}
	if downloadResult != nil && !errors.Is(downloadResult, context.Canceled) {
		reportTunnelFailure(control, downloadResult)
		return downloadResult
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func relayBurstDownload(ctx context.Context, route burstRoute, sessionID string, local net.Conn) error {
	downloadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	outcomes := make(chan burstDownloadOutcome, burstDownloadParallel*2)
	retryReady := make(chan uint64, burstDownloadParallel)
	inflight := make(map[uint64]bool, burstDownloadParallel)
	scheduled := make(map[uint64]bool, burstDownloadParallel)
	pending := make(map[uint64]burstDownloadOutcome, burstDownloadParallel)
	var workers sync.WaitGroup

	launch := func(sequence uint64) {
		if inflight[sequence] {
			return
		}
		inflight[sequence] = true
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := downloadBurstChunkWithRetry(downloadCtx, route, sessionID, sequence)
			select {
			case outcomes <- burstDownloadOutcome{sequence: sequence, result: result, err: err}:
			case <-downloadCtx.Done():
			}
		}()
	}
	scheduleRetry := func(sequence uint64) {
		if scheduled[sequence] {
			return
		}
		scheduled[sequence] = true
		go func() {
			timer := time.NewTimer(burstDownloadIdle)
			defer timer.Stop()
			select {
			case <-timer.C:
				select {
				case retryReady <- sequence:
				case <-downloadCtx.Done():
				}
			case <-downloadCtx.Done():
			}
		}()
	}
	defer func() {
		cancel()
		workers.Wait()
	}()

	nextRequest := uint64(0)
	nextWrite := uint64(0)
	fillWindow := func() {
		for nextRequest < nextWrite+burstDownloadParallel {
			launch(nextRequest)
			nextRequest++
		}
	}
	fillWindow()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sequence := <-retryReady:
			delete(scheduled, sequence)
			if sequence >= nextWrite {
				if _, complete := pending[sequence]; !complete {
					launch(sequence)
				}
			}
		case outcome := <-outcomes:
			delete(inflight, outcome.sequence)
			if outcome.err != nil {
				pending[outcome.sequence] = outcome
			} else if outcome.result.idle {
				scheduleRetry(outcome.sequence)
			} else {
				pending[outcome.sequence] = outcome
			}
		}

		for {
			outcome, ready := pending[nextWrite]
			if !ready {
				break
			}
			delete(pending, nextWrite)
			if outcome.err != nil {
				return outcome.err
			}
			if len(outcome.result.data) > 0 {
				if err := writeAll(local, outcome.result.data); err != nil {
					return atStage(stageTraffic, fmt.Errorf("write burst download: %w", err))
				}
			}
			nextWrite++
			if outcome.result.fin {
				if closer, ok := local.(interface{ CloseWrite() error }); ok {
					if err := closer.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
						return atStage(stageTraffic, fmt.Errorf("finish burst download: %w", err))
					}
				}
				return nil
			}
		}
		fillWindow()
	}
}

func downloadBurstChunkWithRetry(ctx context.Context, route burstRoute, sessionID string, sequence uint64) (burstDownloadResult, error) {
	var attemptErrors []error
	for attempt := 1; attempt <= burstUploadAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return burstDownloadResult{}, err
		}
		if err := acquireBurstSlot(ctx, route.config.burstDownloadSlots); err != nil {
			return burstDownloadResult{}, err
		}
		if err := acquireBurstSlot(ctx, route.config.burstSlots); err != nil {
			releaseBurstSlot(route.config.burstDownloadSlots)
			return burstDownloadResult{}, err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, burstAttemptTimeout)
		result, err := downloadBurstChunk(attemptCtx, route, sessionID, sequence)
		cancel()
		releaseBurstSlot(route.config.burstSlots)
		releaseBurstSlot(route.config.burstDownloadSlots)
		if err == nil {
			return result, nil
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("attempt %d: %w", attempt, err))
		if attempt < burstUploadAttempts {
			if err := waitBurstRetry(ctx, attempt); err != nil {
				return burstDownloadResult{}, err
			}
		}
	}
	return burstDownloadResult{}, atStage(stageTraffic, fmt.Errorf("burst download sequence %d failed: %w", sequence, errors.Join(attemptErrors...)))
}

func downloadBurstChunk(ctx context.Context, route burstRoute, sessionID string, sequence uint64) (burstDownloadResult, error) {
	current := route.config
	current.network = networkBurstDownload
	tunnel, err := openTunnelWithProfile(ctx, current, route.profile)
	if err != nil {
		return burstDownloadResult{}, err
	}
	defer tunnel.close()
	request := burstDownloadRequest{
		Version: 1, SessionID: sessionID, Sequence: sequence, MaxLength: burstDownloadChunk,
	}
	if err := sendBurstJSON(tunnel, request); err != nil {
		return burstDownloadResult{}, err
	}
	var ack burstDownloadAck
	if err := receiveBurstJSON(ctx, tunnel, &ack); err != nil {
		return burstDownloadResult{}, err
	}
	if ack.Version != 1 || ack.SessionID != sessionID || ack.Sequence != sequence || ack.Length < 0 || ack.Length > burstDownloadChunk {
		return burstDownloadResult{}, errors.New("invalid burst download acknowledgement")
	}
	idle, err := validateBurstDownloadAck(ack, sequence)
	if err != nil {
		return burstDownloadResult{}, err
	}
	if idle {
		return burstDownloadResult{idle: true}, nil
	}
	data := []byte(nil)
	if ack.Length > 0 {
		data, err = receiveBurstFrame(ctx, tunnel)
		if err != nil {
			return burstDownloadResult{}, err
		}
		if len(data) != ack.Length {
			return burstDownloadResult{}, errors.New("burst download length mismatch")
		}
	}
	wantHash := hex.EncodeToString(sha256Sum(data))
	if ack.SHA256 != wantHash {
		return burstDownloadResult{}, errors.New("burst download hash mismatch")
	}
	return burstDownloadResult{data: data, fin: ack.Fin}, nil
}

func validateBurstDownloadAck(ack burstDownloadAck, sequence uint64) (bool, error) {
	if ack.Status == "idle" {
		if ack.NextSequence > sequence || ack.Length != 0 || ack.Fin {
			return false, errors.New("invalid idle burst download acknowledgement")
		}
		return true, nil
	}
	if (ack.Status != "written" && ack.Status != "duplicate") || ack.NextSequence < sequence+1 {
		return false, errors.New("burst download sequence was not acknowledged")
	}
	if ack.Fin && ack.Length != 0 {
		return false, errors.New("burst download FIN contains data")
	}
	return false, nil
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func runBurstUploads(ctx context.Context, local net.Conn, route burstRoute, sessionID string, chunkSize, parallel int) error {
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan burstChunk)
	var workers sync.WaitGroup
	var firstError error
	var errorOnce sync.Once
	fail := func(err error) {
		errorOnce.Do(func() {
			firstError = err
			cancel()
			_ = local.Close()
		})
	}
	for index := 0; index < parallel; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for chunk := range jobs {
				if err := uploadBurstChunkWithRetry(uploadCtx, route, sessionID, chunk.sequence, chunk.data, false); err != nil {
					fail(err)
					return
				}
			}
		}()
	}

	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-uploadCtx.Done():
			_ = local.Close()
		case <-stopWatcher:
		}
	}()

	sequence := uint64(0)
	buffer := make([]byte, chunkSize)
	readFinished := false
	for !readFinished {
		count, readErr := readBurstChunk(local, buffer, burstCoalesceDelay)
		if count > 0 {
			data := append([]byte(nil), buffer[:count]...)
			select {
			case jobs <- burstChunk{sequence: sequence, data: data}:
				sequence++
			case <-uploadCtx.Done():
				readFinished = true
			}
		}
		if readErr != nil {
			readFinished = true
			if !errors.Is(readErr, io.EOF) && uploadCtx.Err() == nil {
				fail(atStage(stageTraffic, fmt.Errorf("read burst upload: %w", readErr)))
			}
		}
	}
	close(jobs)
	workers.Wait()
	close(stopWatcher)
	if firstError != nil {
		return firstError
	}
	if err := uploadCtx.Err(); err != nil {
		return err
	}
	return uploadBurstChunkWithRetry(uploadCtx, route, sessionID, sequence, nil, true)
}

func readBurstChunk(local net.Conn, buffer []byte, coalesceDelay time.Duration) (int, error) {
	count, readErr := local.Read(buffer)
	if count == 0 || readErr != nil || count == len(buffer) || coalesceDelay <= 0 {
		return count, readErr
	}
	deadline := time.Now().Add(coalesceDelay)
	if err := local.SetReadDeadline(deadline); err != nil {
		return count, nil
	}
	defer local.SetReadDeadline(time.Time{})
	for count < len(buffer) {
		more, err := local.Read(buffer[count:])
		count += more
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				return count, nil
			}
			return count, err
		}
	}
	return count, nil
}

func uploadBurstChunkWithRetry(ctx context.Context, route burstRoute, sessionID string, sequence uint64, data []byte, fin bool) error {
	var attemptErrors []error
	for attempt := 1; attempt <= burstUploadAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := acquireBurstSlot(ctx, route.config.burstSlots); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, burstAttemptTimeout)
		err := uploadBurstChunk(attemptCtx, route, sessionID, sequence, data, fin)
		cancel()
		releaseBurstSlot(route.config.burstSlots)
		if err == nil {
			return nil
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("attempt %d: %w", attempt, err))
		if attempt < burstUploadAttempts {
			if err := waitBurstRetry(ctx, attempt); err != nil {
				return err
			}
		}
	}
	return atStage(stageTraffic, fmt.Errorf("burst upload sequence %d failed: %w", sequence, errors.Join(attemptErrors...)))
}

func acquireBurstSlot(ctx context.Context, slots chan struct{}) error {
	if slots == nil {
		return nil
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func burstReservedDownloads(globalParallel int) int {
	parallel := globalParallel / 2
	if parallel < 1 {
		return 1
	}
	return parallel
}

func releaseBurstSlot(slots chan struct{}) {
	if slots != nil {
		<-slots
	}
}

func waitBurstRetry(ctx context.Context, attempt int) error {
	jitter := []byte{0}
	_, _ = io.ReadFull(rand.Reader, jitter)
	delay := time.Duration(attempt)*100*time.Millisecond + time.Duration(jitter[0])*time.Millisecond/4
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func uploadBurstChunk(ctx context.Context, route burstRoute, sessionID string, sequence uint64, data []byte, fin bool) error {
	if fin && len(data) != 0 {
		return errors.New("burst FIN cannot contain data")
	}
	if len(data) > maxBurstChunk {
		return fmt.Errorf("burst upload exceeds %d bytes", maxBurstChunk)
	}
	tunnel, err := openTunnelWithProfile(ctx, route.config, route.profile)
	if err != nil {
		return err
	}
	defer tunnel.close()
	header := burstUploadHeader{
		Version: 1, SessionID: sessionID, Sequence: sequence, Fin: fin, Length: len(data),
	}
	if err := sendBurstJSON(tunnel, header); err != nil {
		return err
	}
	if len(data) > 0 {
		envelope, err := packBurstEnvelope(data, rand.Reader)
		if err != nil {
			return err
		}
		if err := tunnel.sendBinary(envelope); err != nil {
			return fmt.Errorf("send burst payload: %w", err)
		}
	}
	var ack burstUploadAck
	if err := receiveBurstJSON(ctx, tunnel, &ack); err != nil {
		return err
	}
	if ack.Version != 1 || ack.SessionID != sessionID || ack.Sequence != sequence || ack.Fin != fin {
		return errors.New("invalid burst upload acknowledgement")
	}
	return validateBurstUploadAck(ack, sequence, fin)
}

func validateBurstUploadAck(ack burstUploadAck, sequence uint64, fin bool) error {
	wantNext := sequence + 1
	if fin {
		if (ack.Status != "written" && ack.Status != "duplicate") || ack.NextSequence != wantNext {
			return errors.New("invalid burst FIN acknowledgement")
		}
		return nil
	}
	switch ack.Status {
	case "written", "duplicate":
		if ack.NextSequence < wantNext {
			return errors.New("burst acknowledgement did not advance the sequence")
		}
	case "pending":
		if ack.NextSequence > sequence {
			return errors.New("invalid pending burst acknowledgement")
		}
	default:
		return fmt.Errorf("burst upload was rejected with status %q", ack.Status)
	}
	return nil
}
