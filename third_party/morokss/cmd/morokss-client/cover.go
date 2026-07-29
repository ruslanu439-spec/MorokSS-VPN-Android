package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	coverModeAuto = "auto"
	coverModeOff  = "off"
	networkProbe  = "probe"
	probeBytes    = 96 * 1024
	probeChunk    = 4 * 1024
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" || strings.ContainsAny(item, " /\\:") {
			return fmt.Errorf("invalid hostname %q", item)
		}
		*values = append(*values, item)
	}
	return nil
}

type coverFailure struct {
	count      int
	retryAfter time.Time
}

type cachedCover struct {
	SNI         string    `json:"sni"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type coverCache struct {
	Version   int                    `json:"version"`
	Endpoints map[string]cachedCover `json:"endpoints"`
}

var coverCacheFileMu sync.Mutex

type coverSelector struct {
	mu          sync.Mutex
	mode        string
	candidates_ []string
	cachePath   string
	endpointKey string
	lastGood    string
	lastSaved   time.Time
	verified    map[string]bool
	failures    map[string]coverFailure
	now         func() time.Time
}

func newCoverSelector(mode string, configured []string, cachePath, endpointKey, realHostname string) *coverSelector {
	candidates := []string{strings.ToLower(strings.TrimSpace(realHostname))}
	if mode == coverModeAuto {
		candidates = append(candidates, configured...)
	}
	candidates = uniqueStrings(candidates)
	selector := &coverSelector{
		mode: mode, candidates_: candidates, cachePath: cachePath, endpointKey: endpointKey,
		verified: make(map[string]bool), failures: make(map[string]coverFailure), now: time.Now,
	}
	if mode == coverModeAuto {
		entry := loadCachedCover(cachePath, endpointKey, candidates, time.Now())
		selector.lastGood = entry.SNI
		selector.lastSaved = entry.ConfirmedAt
	}
	return selector
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (selector *coverSelector) candidates() ([]string, time.Duration) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	ordered := make([]string, 0, len(selector.candidates_))
	if selector.lastGood != "" {
		ordered = append(ordered, selector.lastGood)
	}
	for _, candidate := range selector.candidates_ {
		if candidate != selector.lastGood {
			ordered = append(ordered, candidate)
		}
	}
	now := selector.now()
	available := make([]string, 0, len(ordered))
	var earliest time.Time
	for _, candidate := range ordered {
		failure, failed := selector.failures[candidate]
		if !failed || !failure.retryAfter.After(now) {
			available = append(available, candidate)
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

func (selector *coverSelector) needsProbe(sni string) bool {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	return !selector.verified[sni]
}

func (selector *coverSelector) markFailure(sni string) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	failure := selector.failures[sni]
	failure.count++
	exponent := failure.count - 1
	if exponent > 4 {
		exponent = 4
	}
	failure.retryAfter = selector.now().Add(30 * time.Second * time.Duration(1<<exponent))
	selector.failures[sni] = failure
	delete(selector.verified, sni)
	if selector.lastGood == sni {
		selector.lastGood = ""
	}
}

func (selector *coverSelector) markSuccess(sni string) bool {
	selector.mu.Lock()
	changed := selector.lastGood != sni
	selector.lastGood = sni
	selector.verified[sni] = true
	delete(selector.failures, sni)
	now := selector.now()
	shouldSave := selector.mode == coverModeAuto && (changed || selector.lastSaved.IsZero() || now.Sub(selector.lastSaved) >= time.Hour)
	if shouldSave {
		selector.lastSaved = now
	}
	cachePath, endpointKey := selector.cachePath, selector.endpointKey
	selector.mu.Unlock()
	if shouldSave {
		if err := saveCachedCover(cachePath, endpointKey, sni, now); err != nil {
			log.Printf("cannot save cover SNI cache: %v", err)
		}
	}
	return changed
}

func probeDataPath(ctx context.Context, tunnel tunnelStream) error {
	deadline := time.AfterFunc(15*time.Second, tunnel.close)
	defer deadline.Stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	uploadHash := sha256.New()
	remaining := probeBytes
	for remaining > 0 {
		size := probeChunk
		if remaining < size {
			size = remaining
		}
		chunk := make([]byte, size)
		if _, err := rand.Read(chunk); err != nil {
			return atStage(stageProbe, err)
		}
		_, _ = uploadHash.Write(chunk)
		envelope, err := packEnvelope(chunk, rand.Reader)
		if err != nil {
			return atStage(stageProbe, err)
		}
		if err := tunnel.sendBinary(envelope); err != nil {
			return atStage(stageProbe, fmt.Errorf("upload probe: %w", err))
		}
		remaining -= size
	}
	ack, err := tunnel.receiveBinary()
	if err != nil {
		return atStage(stageProbe, fmt.Errorf("upload confirmation: %w", err))
	}
	ackData, err := unpackEnvelope(ack)
	if err != nil || len(ackData) != 35 || string(ackData[:3]) != "up:" || !equalBytes(ackData[3:], uploadHash.Sum(nil)) {
		return atStage(stageProbe, errors.New("invalid upload confirmation"))
	}
	downHash := sha256.New()
	received := 0
	for received < probeBytes {
		payload, err := tunnel.receiveBinary()
		if err != nil {
			return atStage(stageProbe, fmt.Errorf("download probe: %w", err))
		}
		data, err := unpackEnvelope(payload)
		if err != nil || len(data) == 0 || received+len(data) > probeBytes {
			return atStage(stageProbe, errors.New("invalid download probe"))
		}
		_, _ = downHash.Write(data)
		received += len(data)
	}
	ack, err = tunnel.receiveBinary()
	if err != nil {
		return atStage(stageProbe, fmt.Errorf("download confirmation: %w", err))
	}
	ackData, err = unpackEnvelope(ack)
	if err != nil || len(ackData) != 37 || string(ackData[:5]) != "down:" || !equalBytes(ackData[5:], downHash.Sum(nil)) {
		return atStage(stageProbe, errors.New("invalid download confirmation"))
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func defaultCoverCachePath() string {
	directory, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "morokss", "cover-sni.json")
}

func loadCoverCache(path string) coverCache {
	state := coverCache{Version: 1, Endpoints: make(map[string]cachedCover)}
	if path == "" {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return state
	}
	if json.Unmarshal(data, &state) != nil || state.Version != 1 {
		return coverCache{Version: 1, Endpoints: make(map[string]cachedCover)}
	}
	if state.Endpoints == nil {
		state.Endpoints = make(map[string]cachedCover)
	}
	return state
}

func loadCachedCover(path, endpointKey string, candidates []string, now time.Time) cachedCover {
	entry, found := loadCoverCache(path).Endpoints[endpointKey]
	if !found || now.Sub(entry.ConfirmedAt) > 24*time.Hour {
		return cachedCover{}
	}
	for _, candidate := range candidates {
		if candidate == entry.SNI {
			return entry
		}
	}
	return cachedCover{}
}

func saveCachedCover(path, endpointKey, sni string, now time.Time) error {
	if path == "" {
		return nil
	}
	coverCacheFileMu.Lock()
	defer coverCacheFileMu.Unlock()
	state := loadCoverCache(path)
	state.Endpoints[endpointKey] = cachedCover{SNI: sni, ConfirmedAt: now.UTC()}
	if len(state.Endpoints) > 64 {
		keys := make([]string, 0, len(state.Endpoints))
		for key := range state.Endpoints {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			return state.Endpoints[keys[i]].ConfirmedAt.Before(state.Endpoints[keys[j]].ConfirmedAt)
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
	temporary, err := os.CreateTemp(directory, "cover-sni-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}

func coverEndpointKey(endpointKey, scope string) string {
	digest := sha256.Sum256([]byte(endpointKey + "|" + scope))
	return hex.EncodeToString(digest[:16])
}
