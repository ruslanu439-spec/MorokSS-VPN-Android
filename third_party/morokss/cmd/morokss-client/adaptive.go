package main

import (
	"context"
	"crypto/x509"
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

type failureStage string

const (
	stageTCP        failureStage = "tcp"
	stageTLS        failureStage = "tls"
	stageWebSocket  failureStage = "websocket"
	stageHTTPStream failureStage = "http-stream"
	stageAuth       failureStage = "auth"
	stageProbe      failureStage = "path-probe"
	stageTraffic    failureStage = "traffic"
)

type stagedError struct {
	stage failureStage
	err   error
}

func (failure *stagedError) Error() string {
	return fmt.Sprintf("%s stage: %v", failure.stage, failure.err)
}

func (failure *stagedError) Unwrap() error {
	return failure.err
}

func atStage(stage failureStage, err error) error {
	return &stagedError{stage: stage, err: err}
}

func errorStage(err error) (failureStage, bool) {
	var failure *stagedError
	if !errors.As(err, &failure) {
		return "", false
	}
	return failure.stage, true
}

func retryableTLSFailure(err error) bool {
	stage, found := errorStage(err)
	if !found || stage != stageTLS || errors.Is(err, context.Canceled) {
		return false
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	return !errors.As(err, &unknownAuthority) &&
		!errors.As(err, &hostnameError) &&
		!errors.As(err, &invalidCertificate)
}

type profileFailure struct {
	count      int
	retryAfter time.Time
}

type cachedProfile struct {
	Profile     string    `json:"profile"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type profileCache struct {
	Version int                      `json:"version"`
	Servers map[string]cachedProfile `json:"servers"`
}

var profileCacheFileMu sync.Mutex

type profileSelector struct {
	mu        sync.Mutex
	mode      string
	cachePath string
	serverKey string
	lastGood  string
	lastSaved time.Time
	failures  map[string]profileFailure
	now       func() time.Time
}

func newProfileSelector(mode, cachePath, serverKey string) *profileSelector {
	selector := &profileSelector{
		mode:      mode,
		cachePath: cachePath,
		serverKey: serverKey,
		failures:  make(map[string]profileFailure),
		now:       time.Now,
	}
	if mode == "auto" {
		selector.lastGood = loadCachedProfile(cachePath, serverKey, time.Now())
	}
	return selector
}

func (selector *profileSelector) candidates() ([]string, time.Duration) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	if selector.mode != "auto" {
		return []string{selector.mode}, 0
	}

	ordered := make([]string, 0, 5)
	seen := make(map[string]bool)
	appendProfile := func(profile string) {
		if profile != "" && !seen[profile] {
			seen[profile] = true
			ordered = append(ordered, profile)
		}
	}
	appendProfile(selector.lastGood)
	for _, profile := range automaticProfileOrder() {
		appendProfile(profile)
	}

	now := selector.now()
	available := make([]string, 0, len(ordered))
	var earliest time.Time
	for _, profile := range ordered {
		failure, failed := selector.failures[profile]
		if !failed || !failure.retryAfter.After(now) {
			available = append(available, profile)
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

func (selector *profileSelector) markTLSFailure(profile string) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	failure := selector.failures[profile]
	failure.count++
	exponent := failure.count - 1
	if exponent > 4 {
		exponent = 4
	}
	failure.retryAfter = selector.now().Add(30 * time.Second * time.Duration(1<<exponent))
	selector.failures[profile] = failure
	if selector.lastGood == profile {
		selector.lastGood = ""
	}
}

func (selector *profileSelector) markSuccess(profile string) bool {
	selector.mu.Lock()
	if selector.mode != "auto" {
		selector.mu.Unlock()
		return false
	}
	if profile == "randomized" {
		delete(selector.failures, profile)
		selector.mu.Unlock()
		return false
	}
	changed := selector.lastGood != profile
	selector.lastGood = profile
	delete(selector.failures, profile)
	cachePath := selector.cachePath
	serverKey := selector.serverKey
	now := selector.now()
	if !changed && !selector.lastSaved.IsZero() && now.Sub(selector.lastSaved) < time.Hour {
		selector.mu.Unlock()
		return changed
	}
	selector.lastSaved = now
	selector.mu.Unlock()
	if err := saveCachedProfile(cachePath, serverKey, profile, now); err != nil {
		log.Printf("cannot save TLS profile cache: %v", err)
	}
	return changed
}

func automaticProfileOrder() []string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return []string{"safari", "chrome", "firefox", "randomized"}
	case "android":
		return []string{"android", "chrome", "randomized"}
	default:
		return []string{"chrome", "firefox", "randomized"}
	}
}

func defaultProfileCachePath() string {
	directory, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "morokss", "tls-profiles.json")
}

func loadProfileCache(path string) profileCache {
	state := profileCache{Version: 1, Servers: make(map[string]cachedProfile)}
	if path == "" {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 {
		return profileCache{Version: 1, Servers: make(map[string]cachedProfile)}
	}
	if state.Servers == nil {
		state.Servers = make(map[string]cachedProfile)
	}
	return state
}

func loadCachedProfile(path, serverKey string, now time.Time) string {
	entry, found := loadProfileCache(path).Servers[serverKey]
	if !found || now.Sub(entry.ConfirmedAt) > 7*24*time.Hour {
		return ""
	}
	if _, err := clientHelloID(entry.Profile); err != nil {
		return ""
	}
	return entry.Profile
}

func saveCachedProfile(path, serverKey, profile string, now time.Time) error {
	if path == "" {
		return nil
	}
	profileCacheFileMu.Lock()
	defer profileCacheFileMu.Unlock()
	state := loadProfileCache(path)
	state.Servers[serverKey] = cachedProfile{Profile: profile, ConfirmedAt: now.UTC()}
	if len(state.Servers) > 64 {
		keys := make([]string, 0, len(state.Servers))
		for key := range state.Servers {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool {
			return state.Servers[keys[left]].ConfirmedAt.Before(state.Servers[keys[right]].ConfirmedAt)
		})
		for _, key := range keys[:len(keys)-64] {
			delete(state.Servers, key)
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
	temporary, err := os.CreateTemp(directory, "tls-profiles-*.tmp")
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
