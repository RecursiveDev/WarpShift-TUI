package warp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEndpointModelAcceptsKnownCloudflareWARPPrefixesOnly(t *testing.T) {
	endpoint, err := NewEndpoint("162.159.192.10", 2408, TransportUDP)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}

	if endpoint.String() != "162.159.192.10:2408/udp" {
		t.Fatalf("unexpected endpoint string: %q", endpoint.String())
	}
	if !IsKnownCloudflareWARPEndpoint(endpoint) {
		t.Fatal("expected endpoint to be recognized as a known Cloudflare WARP endpoint")
	}

	if _, err := NewEndpoint("8.8.8.8", 2408, TransportUDP); err == nil {
		t.Fatal("expected non-Cloudflare endpoint to be rejected")
	}
	if _, err := NewEndpoint("162.159.192.10", 0, TransportUDP); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
}

func TestScannerRanksByHealthyRTTAndCachesFreshResults(t *testing.T) {
	primary := mustEndpoint(t, "162.159.192.10", 2408)
	fast := mustEndpoint(t, "162.159.193.20", 2408)
	failed := mustEndpoint(t, "162.159.194.30", 2408)
	checkedAt := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)

	probeCalls := 0
	scanner, err := NewScanner(ProbeFunc(func(ctx context.Context, endpoint Endpoint) (time.Duration, error) {
		probeCalls++
		switch endpoint.Key() {
		case primary.Key():
			return 40 * time.Millisecond, nil
		case fast.Key():
			return 15 * time.Millisecond, nil
		case failed.Key():
			return 0, errors.New("probe timeout")
		default:
			return 0, errors.New("unexpected endpoint")
		}
	}), WithScannerClock(func() time.Time { return checkedAt }))
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	results := scanner.Scan(context.Background(), []Endpoint{primary, fast, failed})
	if probeCalls != 3 {
		t.Fatalf("expected 3 probe calls, got %d", probeCalls)
	}

	ranked := RankByRTT(results)
	if ranked[0].Endpoint != fast || ranked[1].Endpoint != primary || ranked[2].Endpoint != failed {
		t.Fatalf("unexpected ranking: %#v", ranked)
	}
	if !ranked[0].Healthy || ranked[2].Healthy || ranked[2].Error == "" {
		t.Fatalf("expected healthy endpoints first and failed endpoint with error: %#v", ranked)
	}

	now := checkedAt
	cache := NewEndpointCache(time.Minute, WithCacheClock(func() time.Time { return now }))
	cache.Store(results)
	cached := cache.Ranked()
	if len(cached) != 3 || cached[0].Endpoint != fast {
		t.Fatalf("unexpected cached ranking: %#v", cached)
	}

	now = checkedAt.Add(2 * time.Minute)
	if cached := cache.Ranked(); len(cached) != 0 {
		t.Fatalf("expected stale cache entries to be omitted, got %#v", cached)
	}
}

func mustEndpoint(t *testing.T, address string, port int) Endpoint {
	t.Helper()
	endpoint, err := NewEndpoint(address, port, TransportUDP)
	if err != nil {
		t.Fatalf("NewEndpoint(%q, %d) returned error: %v", address, port, err)
	}
	return endpoint
}
