package main

import (
	"path/filepath"
	"testing"
)

func TestCoverSelectorPrefersRealHostnameThenCachesWorkingSNI(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cover.json")
	selector := newCoverSelector(coverModeAuto, []string{"allowed.example", "allowed.example"}, cachePath, "server:cellular", "vpn.example")
	candidates, _ := selector.candidates()
	if len(candidates) != 2 || candidates[0] != "vpn.example" || candidates[1] != "allowed.example" {
		t.Fatalf("unexpected cover candidates: %v", candidates)
	}
	if !selector.needsProbe("allowed.example") {
		t.Fatal("a candidate must pass a full path probe in a new process")
	}
	selector.markSuccess("allowed.example")
	if selector.needsProbe("allowed.example") {
		t.Fatal("successful candidate was not marked as verified")
	}

	loaded := newCoverSelector(coverModeAuto, []string{"allowed.example"}, cachePath, "server:cellular", "vpn.example")
	candidates, _ = loaded.candidates()
	if candidates[0] != "allowed.example" {
		t.Fatalf("cached cover SNI was not preferred: %v", candidates)
	}
	if !loaded.needsProbe("allowed.example") {
		t.Fatal("cached candidate must be probed again after process restart")
	}
}

func TestCoverSelectorOffUsesOnlyCertificateHostname(t *testing.T) {
	selector := newCoverSelector(coverModeOff, []string{"ignored.example"}, "", "server", "vpn.example")
	candidates, _ := selector.candidates()
	if len(candidates) != 1 || candidates[0] != "vpn.example" {
		t.Fatalf("off mode used a cover SNI: %v", candidates)
	}
}
