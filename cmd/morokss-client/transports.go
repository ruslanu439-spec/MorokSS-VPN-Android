package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

const (
	transportAuto       = "auto"
	transportWebSocket  = "websocket"
	transportHTTPStream = "http-stream"
)

type tunnelStream interface {
	sendBinary([]byte) error
	receiveBinary() ([]byte, error)
	close()
}

type transportFailure struct {
	count      int
	retryAfter time.Time
}

type cachedTransport struct {
	Transport   string    `json:"transport"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type transportCache struct {
	Version   int                        `json:"version"`
	Endpoints map[string]cachedTransport `json:"endpoints"`
}

var transportCacheFileMu sync.Mutex

type transportSelector struct {
	mu          sync.Mutex
	mode        string
	cachePath   string
	endpointKey string
	lastGood    string
	lastSaved   time.Time
	failures    map[string]transportFailure
	now         func() time.Time
}

func newTransportSelector(mode, cachePath, endpointKey string) *transportSelector {
	selector := &transportSelector{
		mode:        mode,
		cachePath:   cachePath,
		endpointKey: endpointKey,
		failures:    make(map[string]transportFailure),
		now:         time.Now,
	}
	if mode == transportAuto {
		entry := loadCachedTransport(cachePath, endpointKey, time.Now())
		selector.lastGood = entry.Transport
		selector.lastSaved = entry.ConfirmedAt
	}
	return selector
}

func (selector *transportSelector) candidates() ([]string, time.Duration) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	if selector.mode != transportAuto {
		return []string{selector.mode}, 0
	}
	ordered := make([]string, 0, 2)
	if selector.lastGood != "" {
		ordered = append(ordered, selector.lastGood)
	}
	for _, transport := range []string{transportWebSocket, transportHTTPStream} {
		if transport != selector.lastGood {
			ordered = append(ordered, transport)
		}
	}
	now := selector.now()
	available := make([]string, 0, len(ordered))
	var earliest time.Time
	for _, transport := range ordered {
		failure, failed := selector.failures[transport]
		if !failed || !failure.retryAfter.After(now) {
			available = append(available, transport)
			continue
		}
		if earliest.IsZero() || failure.retryAfter.Before(earliest) {
			earliest = failure.retryAfter
		}
	}
	if len(available) == 0 && !earliest.IsZero() {
		return nil, earliest.Sub(now)
	}
	return available, 0
}

func (selector *transportSelector) markFailure(transport string) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	failure := selector.failures[transport]
	failure.count++
	exponent := failure.count - 1
	if exponent > 4 {
		exponent = 4
	}
	failure.retryAfter = selector.now().Add(30 * time.Second * time.Duration(1<<exponent))
	selector.failures[transport] = failure
	if selector.lastGood == transport {
		selector.lastGood = ""
	}
}

func (selector *transportSelector) markSuccess(transport string) bool {
	selector.mu.Lock()
	if selector.mode != transportAuto {
		selector.mu.Unlock()
		return false
	}
	changed := selector.lastGood != transport
	selector.lastGood = transport
	delete(selector.failures, transport)
	now := selector.now()
	if !changed && !selector.lastSaved.IsZero() && now.Sub(selector.lastSaved) < time.Hour {
		selector.mu.Unlock()
		return false
	}
	selector.lastSaved = now
	cachePath := selector.cachePath
	endpointKey := selector.endpointKey
	selector.mu.Unlock()
	if err := saveCachedTransport(cachePath, endpointKey, transport, now); err != nil {
		log.Printf("cannot save transport cache: %v", err)
	}
	return changed
}

func openEndpointTunnel(ctx context.Context, config clientConfig, profileSelector *profileSelector, transportSelector *transportSelector) (tunnelStream, error) {
	return openEndpointTunnelWith(ctx, config, profileSelector, transportSelector, openTunnel)
}

type selectedTransportOpener func(context.Context, clientConfig, *profileSelector) (tunnelStream, error)

func openEndpointTunnelWith(ctx context.Context, config clientConfig, profileSelector *profileSelector, selector *transportSelector, opener selectedTransportOpener) (tunnelStream, error) {
	transports, retryAfter := selector.candidates()
	if len(transports) == 0 {
		return nil, fmt.Errorf("all transports are cooling down; retry after %s", retryAfter.Round(time.Second))
	}
	var lastError error
	for _, transport := range transports {
		current := config
		current.transport = transport
		tunnel, err := opener(ctx, current, profileSelector)
		if err == nil {
			if selector.markSuccess(transport) {
				log.Printf("transport %s is working and was selected", transport)
			}
			return tunnel, nil
		}
		lastError = err
		if !retryableTransportFailure(err) {
			return nil, err
		}
		selector.markFailure(transport)
		log.Printf("transport %s failed; trying another transport", transport)
	}
	return nil, fmt.Errorf("all available transports failed: %w", lastError)
}

func retryableTransportFailure(err error) bool {
	stage, found := errorStage(err)
	return found && (stage == stageWebSocket || stage == stageHTTPStream) && !errors.Is(err, context.Canceled)
}

func supportedTransport(value string) bool {
	return value == transportAuto || value == transportWebSocket || value == transportHTTPStream
}

func defaultTransportCachePath() string {
	directory, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "morokss", "transports.json")
}

func loadTransportCache(path string) transportCache {
	state := transportCache{Version: 1, Endpoints: make(map[string]cachedTransport)}
	if path == "" {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 {
		return transportCache{Version: 1, Endpoints: make(map[string]cachedTransport)}
	}
	if state.Endpoints == nil {
		state.Endpoints = make(map[string]cachedTransport)
	}
	return state
}

func loadCachedTransport(path, endpointKey string, now time.Time) cachedTransport {
	entry, found := loadTransportCache(path).Endpoints[endpointKey]
	if !found || now.Sub(entry.ConfirmedAt) > 7*24*time.Hour || !supportedTransport(entry.Transport) || entry.Transport == transportAuto {
		return cachedTransport{}
	}
	return entry
}

func saveCachedTransport(path, endpointKey, transport string, now time.Time) error {
	if path == "" {
		return nil
	}
	transportCacheFileMu.Lock()
	defer transportCacheFileMu.Unlock()
	state := loadTransportCache(path)
	state.Endpoints[endpointKey] = cachedTransport{Transport: transport, ConfirmedAt: now.UTC()}
	if len(state.Endpoints) > 64 {
		keys := make([]string, 0, len(state.Endpoints))
		for key := range state.Endpoints {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool {
			return state.Endpoints[keys[left]].ConfirmedAt.Before(state.Endpoints[keys[right]].ConfirmedAt)
		})
		for _, key := range keys[:len(keys)-64] {
			delete(state.Endpoints, key)
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "transports-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path)
	}
	return os.Rename(temporaryName, path)
}
