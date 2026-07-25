package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ruslanu439-spec/MorokSS/internal/endpointmanifest"
)

func loadEndpointManifest(ctx context.Context, source, publicKeyPath, cachePath string, now time.Time) ([]endpoint, bool, error) {
	keyData, err := readSmallFile(publicKeyPath, 4*1024)
	if err != nil {
		return nil, false, fmt.Errorf("read endpoint manifest public key: %w", err)
	}
	publicKey, err := endpointmanifest.DecodePublicKey(keyData)
	if err != nil {
		return nil, false, err
	}

	data, sourceErr := readManifestSource(ctx, source)
	if sourceErr == nil {
		document, verifyErr := endpointmanifest.Verify(data, publicKey, now)
		if verifyErr == nil {
			if err := saveManifestCache(cachePath, data); err != nil {
				return nil, false, fmt.Errorf("save endpoint manifest cache: %w", err)
			}
			return convertManifestEndpoints(document.Endpoints), false, nil
		}
		sourceErr = verifyErr
	}

	cached, cacheErr := readSmallFile(cachePath, endpointmanifest.MaxDocument)
	if cacheErr == nil {
		document, verifyErr := endpointmanifest.Verify(cached, publicKey, now)
		if verifyErr == nil {
			return convertManifestEndpoints(document.Endpoints), true, nil
		}
		cacheErr = verifyErr
	}
	return nil, false, fmt.Errorf("load endpoint manifest: %w", errors.Join(sourceErr, cacheErr))
}

func readManifestSource(ctx context.Context, source string) ([]byte, error) {
	lower := strings.ToLower(source)
	if strings.HasPrefix(lower, "https://") {
		requestContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "MorokSS manifest updater")
		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many endpoint manifest redirects")
				}
				if request.URL.Scheme != "https" {
					return errors.New("endpoint manifest redirect must use HTTPS")
				}
				return nil
			},
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("endpoint manifest server returned %s", response.Status)
		}
		return readLimited(response.Body, endpointmanifest.MaxDocument)
	}
	if strings.HasPrefix(lower, "http://") {
		return nil, errors.New("remote endpoint manifest must use HTTPS")
	}
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" && strings.Contains(source, "://") {
		return nil, fmt.Errorf("unsupported endpoint manifest URL scheme %q", parsed.Scheme)
	}
	return readSmallFile(source, endpointmanifest.MaxDocument)
}

func readSmallFile(path string, limit int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimited(file, limit)
}

func readLimited(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("data exceeds %d bytes", limit)
	}
	return data, nil
}

func convertManifestEndpoints(items []endpointmanifest.Endpoint) []endpoint {
	result := make([]endpoint, 0, len(items))
	for _, item := range items {
		result = append(result, endpoint{Address: item.Address, Hostname: item.Hostname})
	}
	return result
}

func defaultManifestCachePath() string {
	directory, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "morokss", "endpoint-manifest.json")
}

func saveManifestCache(path string, data []byte) error {
	if path == "" {
		return nil
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "endpoint-manifest-*.tmp")
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
