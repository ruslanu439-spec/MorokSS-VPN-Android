package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ruslanu439-spec/MorokSS/internal/endpointmanifest"
)

type endpoint struct {
	Address  string
	Hostname string
}

func newEndpoint(address, hostname string) (endpoint, error) {
	normalized, err := endpointmanifest.NormalizeEndpoint(endpointmanifest.Endpoint{
		Address:  address,
		Hostname: hostname,
	})
	if err != nil {
		return endpoint{}, err
	}
	return endpoint{Address: normalized.Address, Hostname: normalized.Hostname}, nil
}

func (item endpoint) key() string {
	return item.Address + "|" + item.Hostname
}

type endpointList []endpoint

func (items *endpointList) String() string {
	if items == nil {
		return ""
	}
	values := make([]string, 0, len(*items))
	for _, item := range *items {
		values = append(values, item.Address+","+item.Hostname)
	}
	return strings.Join(values, ";")
}

func (items *endpointList) Set(value string) error {
	separator := strings.LastIndex(value, ",")
	if separator < 1 || separator == len(value)-1 {
		return fmt.Errorf("invalid --endpoint %q: expected ADDRESS,HOSTNAME", value)
	}
	item, err := newEndpoint(value[:separator], value[separator+1:])
	if err != nil {
		return err
	}
	*items = append(*items, item)
	return nil
}

var _ flag.Value = (*endpointList)(nil)

func uniqueEndpoints(items []endpoint) []endpoint {
	result := make([]endpoint, 0, len(items))
	seen := make(map[string]bool)
	for _, item := range items {
		if !seen[item.key()] {
			seen[item.key()] = true
			result = append(result, item)
		}
	}
	return result
}

type endpointFailure struct {
	count      int
	retryAfter time.Time
}

type cachedEndpoint struct {
	Endpoint    string    `json:"endpoint"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type endpointCache struct {
	Version int                       `json:"version"`
	Pools   map[string]cachedEndpoint `json:"pools"`
}

var endpointCacheFileMu sync.Mutex

type endpointPool struct {
	mu                sync.Mutex
	endpoints         []endpoint
	poolKey           string
	cachePath         string
	lastGood          string
	lastSaved         time.Time
	lastSavedEndpoint string
	failures          map[string]endpointFailure
	profiles          map[string]*profileSelector
	transports        map[string]*transportSelector
	covers            map[string]*coverSelector
	now               func() time.Time
}

func newEndpointPool(items []endpoint, cachePath, profileMode, profileCachePath, transportMode, transportCachePath, scope string) *endpointPool {
	items = uniqueEndpoints(items)
	poolKey := endpointPoolKey(items)
	if scope != "" {
		poolKey += ":" + scope
	}
	pool := &endpointPool{
		endpoints:  items,
		poolKey:    poolKey,
		cachePath:  cachePath,
		failures:   make(map[string]endpointFailure),
		profiles:   make(map[string]*profileSelector),
		transports: make(map[string]*transportSelector),
		covers:     make(map[string]*coverSelector),
		now:        time.Now,
	}
	entry := loadCachedEndpoint(cachePath, poolKey, items, time.Now())
	pool.lastGood = entry.Endpoint
	pool.lastSaved = entry.ConfirmedAt
	pool.lastSavedEndpoint = entry.Endpoint
	for _, item := range items {
		selectorKey := item.key() + "|" + scope
		pool.profiles[item.key()] = newProfileSelector(profileMode, profileCachePath, selectorKey)
		pool.transports[item.key()] = newTransportSelector(transportMode, transportCachePath, selectorKey)
	}
	return pool
}

func (pool *endpointPool) configureCovers(mode string, candidates []string, cachePath, scope string) {
	for _, item := range pool.endpoints {
		key := coverEndpointKey(item.key(), scope)
		pool.covers[item.key()] = newCoverSelector(mode, candidates, cachePath, key, item.Hostname)
	}
}

func (pool *endpointPool) coverFor(item endpoint) *coverSelector {
	selector := pool.covers[item.key()]
	if selector == nil {
		selector = newCoverSelector(coverModeOff, nil, "", item.key(), item.Hostname)
		pool.covers[item.key()] = selector
	}
	return selector
}

func (pool *endpointPool) len() int {
	return len(pool.endpoints)
}

func (pool *endpointPool) profileFor(item endpoint) *profileSelector {
	return pool.profiles[item.key()]
}

func (pool *endpointPool) transportFor(item endpoint) *transportSelector {
	return pool.transports[item.key()]
}

func (pool *endpointPool) candidates() ([]endpoint, time.Duration) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	ordered := make([]endpoint, 0, len(pool.endpoints))
	if pool.lastGood != "" {
		for _, item := range pool.endpoints {
			if item.key() == pool.lastGood {
				ordered = append(ordered, item)
				break
			}
		}
	}
	for _, item := range pool.endpoints {
		if item.key() != pool.lastGood {
			ordered = append(ordered, item)
		}
	}

	now := pool.now()
	available := make([]endpoint, 0, len(ordered))
	var earliest time.Time
	for _, item := range ordered {
		failure, failed := pool.failures[item.key()]
		if !failed || !failure.retryAfter.After(now) {
			available = append(available, item)
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

func (pool *endpointPool) markFailure(item endpoint) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	failure := pool.failures[item.key()]
	failure.count++
	exponent := failure.count - 1
	if exponent > 4 {
		exponent = 4
	}
	failure.retryAfter = pool.now().Add(30 * time.Second * time.Duration(1<<exponent))
	pool.failures[item.key()] = failure
	if pool.lastGood == item.key() {
		pool.lastGood = ""
	}
}

func (pool *endpointPool) markSuccess(item endpoint) bool {
	pool.mu.Lock()
	key := item.key()
	changed := pool.lastGood != key
	pool.lastGood = key
	delete(pool.failures, key)
	now := pool.now()
	shouldSave := changed || pool.lastSavedEndpoint != key || pool.lastSaved.IsZero() || now.Sub(pool.lastSaved) >= time.Hour
	if shouldSave {
		pool.lastSaved = now
		pool.lastSavedEndpoint = key
	}
	cachePath := pool.cachePath
	poolKey := pool.poolKey
	pool.mu.Unlock()

	if shouldSave {
		if err := saveCachedEndpoint(cachePath, poolKey, key, now); err != nil {
			log.Printf("cannot save endpoint cache: %v", err)
		}
	}
	return changed
}

type endpointOpener func(context.Context, clientConfig, *profileSelector, *transportSelector) (tunnelStream, error)

func openAnyEndpoint(ctx context.Context, config clientConfig, pool *endpointPool) (tunnelStream, error) {
	candidates, retryAfter := pool.candidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("all endpoints are cooling down; retry after %s", retryAfter.Round(time.Second))
	}
	attemptErrors := make([]error, 0)
	for endpointIndex, item := range candidates {
		current := config
		current.server = item.Address
		current.hostname = item.Hostname
		current.endpointIndex = pool.endpointIndex(item)
		coverSelector := pool.coverFor(item)
		covers, coverRetry := coverSelector.candidates()
		if len(covers) == 0 {
			attemptErrors = append(attemptErrors, fmt.Errorf("%s: all cover SNI candidates are cooling down for %s", item.Address, coverRetry.Round(time.Second)))
			continue
		}
		for _, cover := range covers {
			current.tlsSNI = cover
			if coverSelector.needsProbe(cover) {
				probeConfig := current
				probeConfig.network = networkProbe
				probeTunnel, err := openEndpointTunnel(ctx, probeConfig, pool.profileFor(item), pool.transportFor(item))
				if err == nil {
					err = probeDataPath(ctx, probeTunnel)
					probeTunnel.close()
				}
				if err != nil {
					coverSelector.markFailure(cover)
					attemptErrors = append(attemptErrors, fmt.Errorf("%s with cover SNI %s: %w", item.Address, cover, err))
					log.Printf("cover SNI %s failed the 96 KiB path probe; trying another", cover)
					continue
				}
				if coverSelector.markSuccess(cover) {
					log.Printf("cover SNI %s passed the 96 KiB path probe and was selected", cover)
				}
			}
			tunnel, err := openEndpointTunnel(ctx, current, pool.profileFor(item), pool.transportFor(item))
			if err == nil {
				pool.markSuccess(item)
				return tunnel, nil
			}
			coverSelector.markFailure(cover)
			attemptErrors = append(attemptErrors, fmt.Errorf("%s with cover SNI %s: %w", item.Address, cover, err))
		}
		pool.markFailure(item)
		if endpointIndex+1 < len(candidates) {
			log.Printf("trying another endpoint")
		}
	}
	return nil, fmt.Errorf("all available endpoints and cover SNI candidates failed: %w", errors.Join(attemptErrors...))
}

func openAnyEndpointWith(ctx context.Context, config clientConfig, pool *endpointPool, opener endpointOpener) (tunnelStream, error) {
	candidates, retryAfter := pool.candidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("all endpoints are cooling down; retry after %s", retryAfter.Round(time.Second))
	}
	attemptErrors := make([]error, 0, len(candidates))
	for index, item := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current := config
		current.server = item.Address
		current.hostname = item.Hostname
		current.endpointIndex = pool.endpointIndex(item)
		tunnel, err := opener(ctx, current, pool.profileFor(item), pool.transportFor(item))
		if err == nil {
			if pool.markSuccess(item) {
				log.Printf("endpoint %s with TLS hostname %s is working and was selected", item.Address, item.Hostname)
			}
			return tunnel, nil
		}
		pool.markFailure(item)
		attemptErrors = append(attemptErrors, fmt.Errorf("%s (%s): %w", item.Address, item.Hostname, err))
		stage, staged := errorStage(err)
		if staged {
			log.Printf("endpoint %s failed at %s stage: %v", item.Address, stage, errors.Unwrap(err))
		} else {
			log.Printf("endpoint %s failed: %v", item.Address, err)
		}
		if index+1 < len(candidates) {
			log.Printf("trying another endpoint")
		}
	}
	return nil, fmt.Errorf("all available endpoints failed: %w", errors.Join(attemptErrors...))
}

func (pool *endpointPool) endpointIndex(item endpoint) int {
	for index, candidate := range pool.endpoints {
		if candidate.key() == item.key() {
			return index + 1
		}
	}
	return 0
}

func endpointPoolKey(items []endpoint) string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.key())
	}
	sort.Strings(keys)
	hash := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(hash[:16])
}

func defaultEndpointCachePath() string {
	directory, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "morokss", "endpoints.json")
}

func loadEndpointCache(path string) endpointCache {
	state := endpointCache{Version: 1, Pools: make(map[string]cachedEndpoint)}
	if path == "" {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 {
		return endpointCache{Version: 1, Pools: make(map[string]cachedEndpoint)}
	}
	if state.Pools == nil {
		state.Pools = make(map[string]cachedEndpoint)
	}
	return state
}

func loadCachedEndpoint(path, poolKey string, items []endpoint, now time.Time) cachedEndpoint {
	entry, found := loadEndpointCache(path).Pools[poolKey]
	if !found || now.Sub(entry.ConfirmedAt) > 7*24*time.Hour {
		return cachedEndpoint{}
	}
	for _, item := range items {
		if item.key() == entry.Endpoint {
			return entry
		}
	}
	return cachedEndpoint{}
}

func saveCachedEndpoint(path, poolKey, endpointKey string, now time.Time) error {
	if path == "" {
		return nil
	}
	endpointCacheFileMu.Lock()
	defer endpointCacheFileMu.Unlock()
	state := loadEndpointCache(path)
	state.Pools[poolKey] = cachedEndpoint{Endpoint: endpointKey, ConfirmedAt: now.UTC()}
	if len(state.Pools) > 64 {
		keys := make([]string, 0, len(state.Pools))
		for key := range state.Pools {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool {
			return state.Pools[keys[left]].ConfirmedAt.Before(state.Pools[keys[right]].ConfirmedAt)
		})
		for _, key := range keys[:len(keys)-64] {
			delete(state.Pools, key)
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
	temporary, err := os.CreateTemp(directory, "endpoints-*.tmp")
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
