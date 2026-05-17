package warp

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingRotatorScanner struct {
	calls     int
	responses [][]ScanResult
}

func (s *recordingRotatorScanner) Scan(ctx context.Context, endpoints []Endpoint) []ScanResult {
	s.calls++
	if len(s.responses) == 0 {
		return nil
	}
	response := s.responses[0]
	if len(s.responses) > 1 {
		s.responses = s.responses[1:]
	}
	return response
}

func TestEndpointRotatorRefreshesCacheWithInjectedScanner(t *testing.T) {
	slow := mustEndpoint(t, "162.159.192.10", 2408)
	fast := mustEndpoint(t, "162.159.193.20", 2408)
	checkedAt := time.Date(2026, 5, 18, 11, 0, 0, 0, time.UTC)
	cache := NewEndpointCache(time.Minute, WithCacheClock(func() time.Time { return checkedAt }))
	scanner := &recordingRotatorScanner{responses: [][]ScanResult{{
		{Endpoint: slow, Healthy: true, RTT: 40 * time.Millisecond, CheckedAt: checkedAt},
		{Endpoint: fast, Healthy: true, RTT: 15 * time.Millisecond, CheckedAt: checkedAt},
	}}}

	rotator, err := NewEndpointRotator(scanner, cache, []Endpoint{slow, fast}, WithRotationInterval(time.Minute))
	if err != nil {
		t.Fatalf("NewEndpointRotator returned error: %v", err)
	}

	results, err := rotator.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if scanner.calls != 1 {
		t.Fatalf("scanner calls = %d, want 1", scanner.calls)
	}
	if len(results) != 2 || results[0].Endpoint != fast {
		t.Fatalf("refresh results not ranked by RTT: %#v", results)
	}
	cached := cache.Ranked()
	if len(cached) != 2 || cached[0].Endpoint != fast {
		t.Fatalf("cache was not refreshed with ranked endpoint results: %#v", cached)
	}
	current, ok := rotator.Current()
	if !ok || current != fast {
		t.Fatalf("current endpoint = %#v, %t; want fast healthy endpoint", current, ok)
	}
}

func TestEndpointRotatorRunUsesInjectedTicksAndStopsOnContextCancellation(t *testing.T) {
	endpoint := mustEndpoint(t, "162.159.192.10", 2408)
	checkedAt := time.Date(2026, 5, 18, 11, 30, 0, 0, time.UTC)
	scanner := &recordingRotatorScanner{responses: [][]ScanResult{
		{{Endpoint: endpoint, Healthy: true, RTT: 40 * time.Millisecond, CheckedAt: checkedAt}},
		{{Endpoint: endpoint, Healthy: true, RTT: 20 * time.Millisecond, CheckedAt: checkedAt.Add(time.Minute)}},
	}}
	cache := NewEndpointCache(time.Minute, WithCacheClock(func() time.Time { return checkedAt }))
	ticks := make(chan time.Time)
	rotator, err := NewEndpointRotator(scanner, cache, []Endpoint{endpoint}, WithRotationTicks(ticks))
	if err != nil {
		t.Fatalf("NewEndpointRotator returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan RotationUpdate, 2)
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Run(ctx, func(update RotationUpdate) {
			updates <- update
		})
	}()

	first := <-updates
	if len(first.Results) != 1 || first.Results[0].RTT != 40*time.Millisecond {
		t.Fatalf("initial update = %#v, want first scanner response", first)
	}
	ticks <- checkedAt.Add(time.Minute)
	second := <-updates
	if len(second.Results) != 1 || second.Results[0].RTT != 20*time.Millisecond {
		t.Fatalf("tick update = %#v, want second scanner response", second)
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if scanner.calls != 2 {
		t.Fatalf("scanner calls = %d, want 2", scanner.calls)
	}
}

func TestEndpointRotatorRefreshHonorsCanceledContextWithoutScannerCall(t *testing.T) {
	endpoint := mustEndpoint(t, "162.159.192.10", 2408)
	cache := NewEndpointCache(time.Minute)
	scanner := &recordingRotatorScanner{}
	rotator, err := NewEndpointRotator(scanner, cache, []Endpoint{endpoint})
	if err != nil {
		t.Fatalf("NewEndpointRotator returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := rotator.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh error = %v, want context.Canceled", err)
	}
	if scanner.calls != 0 {
		t.Fatalf("scanner calls = %d, want 0 when context is already canceled", scanner.calls)
	}
	if cached := cache.Ranked(); len(cached) != 0 {
		t.Fatalf("canceled refresh should not mutate cache, got %#v", cached)
	}
}
