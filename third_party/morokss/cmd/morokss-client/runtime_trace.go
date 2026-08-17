package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	runtimeTraceSchema    = 1
	runtimeTraceMaxEvents = 6000
)

type runtimeTrace struct {
	mu            sync.Mutex
	file          *os.File
	started       time.Time
	events        int
	dropped       int
	nextFlowID    uint64
	flows         map[uint64]*runtimeFlowStats
	globalSlots   chan struct{}
	downloadSlots chan struct{}
}

type runtimeFlowStats struct {
	started          time.Time
	network          string
	uploadBytes      int64
	downloadBytes    int64
	uploadAttempts   int
	downloadAttempts int
	retries          int
	maxSlotWaitMS    int64
}

type runtimeEvent struct {
	SchemaVersion    int    `json:"schema_version,omitempty"`
	Timestamp        string `json:"timestamp"`
	ElapsedMS        int64  `json:"elapsed_ms"`
	Event            string `json:"event"`
	ClientVersion    string `json:"client_version,omitempty"`
	NetworkScope     string `json:"network_scope,omitempty"`
	Network          string `json:"network,omitempty"`
	ConnectionID     uint64 `json:"connection_id,omitempty"`
	SessionRef       string `json:"session_ref,omitempty"`
	EndpointIndex    int    `json:"endpoint_index,omitempty"`
	TLSProfile       string `json:"tls_profile,omitempty"`
	Transport        string `json:"transport,omitempty"`
	Direction        string `json:"direction,omitempty"`
	Sequence         uint64 `json:"sequence,omitempty"`
	Attempt          int    `json:"attempt,omitempty"`
	Bytes            int    `json:"bytes,omitempty"`
	Status           string `json:"status,omitempty"`
	Stage            string `json:"stage,omitempty"`
	ErrorCode        string `json:"error_code,omitempty"`
	DurationMS       int64  `json:"duration_ms,omitempty"`
	SlotWaitMS       int64  `json:"slot_wait_ms,omitempty"`
	GlobalActive     int    `json:"global_active,omitempty"`
	GlobalLimit      int    `json:"global_limit,omitempty"`
	DownloadActive   int    `json:"download_active,omitempty"`
	DownloadLimit    int    `json:"download_limit,omitempty"`
	UploadBytes      int64  `json:"upload_bytes,omitempty"`
	DownloadBytes    int64  `json:"download_bytes,omitempty"`
	UploadAttempts   int    `json:"upload_attempts,omitempty"`
	DownloadAttempts int    `json:"download_attempts,omitempty"`
	Retries          int    `json:"retries,omitempty"`
	MaxSlotWaitMS    int64  `json:"max_slot_wait_ms,omitempty"`
	DroppedEvents    int    `json:"dropped_events,omitempty"`
	BurstEnabled     bool   `json:"burst_enabled,omitempty"`
	BurstChunk       int    `json:"burst_chunk,omitempty"`
	BurstParallel    int    `json:"burst_parallel,omitempty"`
	DownloadParallel int    `json:"download_parallel,omitempty"`
}

func openRuntimeTrace(path string, config clientConfig) (*runtimeTrace, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	trace := &runtimeTrace{
		file:          file,
		started:       time.Now(),
		flows:         make(map[uint64]*runtimeFlowStats),
		globalSlots:   config.burstSlots,
		downloadSlots: config.burstDownloadSlots,
	}
	trace.writeLocked(runtimeEvent{
		SchemaVersion: runtimeTraceSchema,
		Event:         "client_start", ClientVersion: clientVersion,
		NetworkScope: config.networkScope, BurstEnabled: config.burstUpload,
		BurstChunk: config.burstChunk, BurstParallel: cap(config.burstSlots),
		DownloadParallel: cap(config.burstDownloadSlots),
	})
	return trace, nil
}

func (trace *runtimeTrace) close() {
	if trace == nil {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.writeLocked(runtimeEvent{Event: "client_stop", Status: "complete", DroppedEvents: trace.dropped})
	_ = trace.file.Sync()
	_ = trace.file.Close()
}

func (trace *runtimeTrace) startFlow(network string) uint64 {
	if trace == nil {
		return 0
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.nextFlowID++
	id := trace.nextFlowID
	trace.flows[id] = &runtimeFlowStats{started: time.Now(), network: network}
	trace.writeLocked(runtimeEvent{Event: "connection_start", ConnectionID: id, Network: network, Status: "running"})
	return id
}

func (trace *runtimeTrace) finishFlow(id uint64, err error) {
	if trace == nil || id == 0 {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	stats := trace.flows[id]
	if stats == nil {
		return
	}
	delete(trace.flows, id)
	event := runtimeEvent{
		Event: "connection_finish", ConnectionID: id, Network: stats.network,
		Status: "complete", DurationMS: time.Since(stats.started).Milliseconds(),
		UploadBytes: stats.uploadBytes, DownloadBytes: stats.downloadBytes,
		UploadAttempts: stats.uploadAttempts, DownloadAttempts: stats.downloadAttempts,
		Retries: stats.retries, MaxSlotWaitMS: stats.maxSlotWaitMS,
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		event.Status = "closed"
		err = nil
	}
	setRuntimeError(&event, err)
	trace.writeLocked(event)
}

func (trace *runtimeTrace) tunnelAttempt(config clientConfig, profile string, started time.Time, err error) {
	if trace == nil {
		return
	}
	event := runtimeEvent{
		Event: "tunnel_attempt", ConnectionID: config.runtimeConnectionID,
		Network: config.network, EndpointIndex: config.endpointIndex + 1,
		TLSProfile: profile, Transport: config.transport,
		Status: "ready", DurationMS: time.Since(started).Milliseconds(),
	}
	setRuntimeError(&event, err)
	trace.emit(event)
}

func (trace *runtimeTrace) sessionEvent(config clientConfig, eventName, sessionID string, started time.Time, err error) {
	if trace == nil {
		return
	}
	event := runtimeEvent{
		Event: eventName, ConnectionID: config.runtimeConnectionID,
		Network: config.network, SessionRef: runtimeSessionRef(sessionID),
		Status: "complete", DurationMS: time.Since(started).Milliseconds(),
	}
	setRuntimeError(&event, err)
	trace.emit(event)
}

func (trace *runtimeTrace) burstAttempt(config clientConfig, direction, sessionID string, sequence uint64,
	attempt, bytes int, slotWait, duration time.Duration, status string, err error) {
	if trace == nil {
		return
	}
	event := runtimeEvent{
		Event: "burst_attempt", ConnectionID: config.runtimeConnectionID,
		Network: "tcp", SessionRef: runtimeSessionRef(sessionID), Direction: direction,
		Sequence: sequence, Attempt: attempt, Bytes: bytes, Status: status,
		SlotWaitMS: slotWait.Milliseconds(), DurationMS: duration.Milliseconds(),
		GlobalActive: len(trace.globalSlots), GlobalLimit: cap(trace.globalSlots),
		DownloadActive: len(trace.downloadSlots), DownloadLimit: cap(trace.downloadSlots),
	}
	setRuntimeError(&event, err)
	trace.mu.Lock()
	if stats := trace.flows[config.runtimeConnectionID]; stats != nil {
		if direction == "upload" {
			stats.uploadAttempts++
			if err == nil {
				stats.uploadBytes += int64(bytes)
			}
		} else {
			stats.downloadAttempts++
			if err == nil {
				stats.downloadBytes += int64(bytes)
			}
		}
		if attempt > 1 {
			stats.retries++
		}
		if event.SlotWaitMS > stats.maxSlotWaitMS {
			stats.maxSlotWaitMS = event.SlotWaitMS
		}
	}
	trace.writeLocked(event)
	trace.mu.Unlock()
}

func (trace *runtimeTrace) addDatagram(config clientConfig, direction string, bytes int) {
	if trace == nil {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if stats := trace.flows[config.runtimeConnectionID]; stats != nil {
		if direction == "upload" {
			stats.uploadBytes += int64(bytes)
		} else {
			stats.downloadBytes += int64(bytes)
		}
	}
}

func (trace *runtimeTrace) emit(event runtimeEvent) {
	if trace == nil {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.writeLocked(event)
}

func (trace *runtimeTrace) writeLocked(event runtimeEvent) {
	if trace.file == nil {
		return
	}
	if trace.events >= runtimeTraceMaxEvents && event.Event != "client_stop" {
		trace.dropped++
		return
	}
	now := time.Now()
	if event.Timestamp == "" {
		event.Timestamp = now.UTC().Format(time.RFC3339Nano)
	}
	event.ElapsedMS = now.Sub(trace.started).Milliseconds()
	data, err := json.Marshal(event)
	if err != nil {
		trace.dropped++
		return
	}
	data = append(data, '\n')
	if _, err := trace.file.Write(data); err != nil {
		trace.dropped++
		return
	}
	trace.events++
}

func setRuntimeError(event *runtimeEvent, err error) {
	if err == nil || errors.Is(err, os.ErrClosed) {
		return
	}
	if errors.Is(err, context.Canceled) {
		event.Status = "canceled"
	} else {
		event.Status = "failed"
	}
	event.Stage = diagnosticStage(err)
	event.ErrorCode = diagnosticErrorCode(err)
}

func runtimeSessionRef(sessionID string) string {
	if len(sessionID) <= 8 {
		return sessionID
	}
	return sessionID[:8]
}
