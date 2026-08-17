package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTunnelOpenAdmissionHonorsLimitAndCancellation(t *testing.T) {
	slots := make(chan struct{}, 1)
	if err := acquireTunnelOpenSlot(context.Background(), slots); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := acquireTunnelOpenSlot(ctx, slots); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second admission error = %v, want deadline exceeded", err)
	}
	releaseTunnelOpenSlot(slots)
	if err := acquireTunnelOpenSlot(context.Background(), slots); err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
	releaseTunnelOpenSlot(slots)
}
