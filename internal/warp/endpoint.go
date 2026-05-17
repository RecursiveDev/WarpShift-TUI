package warp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type Transport string

const TransportUDP Transport = "udp"

type Endpoint struct {
	Address   string
	Port      int
	Transport Transport
}

func NewEndpoint(address string, port int, transport Transport) (Endpoint, error) {
	endpoint := Endpoint{Address: address, Port: port, Transport: transport}
	if port <= 0 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid port")
	}
	if transport != TransportUDP {
		return Endpoint{}, fmt.Errorf("unsupported transport")
	}
	if !IsKnownCloudflareWARPEndpoint(endpoint) {
		return Endpoint{}, fmt.Errorf("endpoint is outside known Cloudflare WARP ranges")
	}
	return endpoint, nil
}

func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d/%s", e.Address, e.Port, e.Transport)
}

func (e Endpoint) Key() string {
	return e.String()
}

func IsKnownCloudflareWARPEndpoint(endpoint Endpoint) bool {
	addr, err := netip.ParseAddr(endpoint.Address)
	if err != nil {
		return false
	}
	prefixes := []string{"162.159.192.0/24", "162.159.193.0/24", "162.159.194.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"}
	for _, value := range prefixes {
		prefix := netip.MustParsePrefix(value)
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type ProbeFunc func(context.Context, Endpoint) (time.Duration, error)

type Scanner struct {
	probe ProbeFunc
	clock func() time.Time
}

type ScannerOption func(*Scanner)

func WithScannerClock(clock func() time.Time) ScannerOption {
	return func(scanner *Scanner) { scanner.clock = clock }
}

func NewScanner(probe ProbeFunc, options ...ScannerOption) (*Scanner, error) {
	if probe == nil {
		return nil, errors.New("probe is required")
	}
	scanner := &Scanner{probe: probe, clock: time.Now}
	for _, option := range options {
		option(scanner)
	}
	if scanner.clock == nil {
		scanner.clock = time.Now
	}
	return scanner, nil
}

type ScanResult struct {
	Endpoint  Endpoint
	Healthy   bool
	RTT       time.Duration
	CheckedAt time.Time
	Error     string
}

func (s *Scanner) Scan(ctx context.Context, endpoints []Endpoint) []ScanResult {
	results := make([]ScanResult, 0, len(endpoints))
	for _, endpoint := range endpoints {
		rtt, err := s.probe(ctx, endpoint)
		result := ScanResult{Endpoint: endpoint, CheckedAt: s.clock()}
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Healthy = true
			result.RTT = rtt
		}
		results = append(results, result)
	}
	return results
}

func RankByRTT(results []ScanResult) []ScanResult {
	ranked := append([]ScanResult(nil), results...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Healthy != ranked[j].Healthy {
			return ranked[i].Healthy
		}
		return ranked[i].RTT < ranked[j].RTT
	})
	return ranked
}

type EndpointCache struct {
	ttl     time.Duration
	clock   func() time.Time
	mu      sync.Mutex
	results []ScanResult
}

type CacheOption func(*EndpointCache)

func WithCacheClock(clock func() time.Time) CacheOption {
	return func(cache *EndpointCache) { cache.clock = clock }
}

func NewEndpointCache(ttl time.Duration, options ...CacheOption) *EndpointCache {
	cache := &EndpointCache{ttl: ttl, clock: time.Now}
	for _, option := range options {
		option(cache)
	}
	if cache.clock == nil {
		cache.clock = time.Now
	}
	return cache
}

func (c *EndpointCache) Store(results []ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append([]ScanResult(nil), results...)
}

func (c *EndpointCache) Ranked() []ScanResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	fresh := make([]ScanResult, 0, len(c.results))
	for _, result := range c.results {
		if c.ttl <= 0 || now.Sub(result.CheckedAt) <= c.ttl {
			fresh = append(fresh, result)
		}
	}
	return RankByRTT(fresh)
}
