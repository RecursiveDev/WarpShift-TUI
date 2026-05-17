package warp

import (
	"context"
	"errors"
	"time"
)

// EndpointScanner is the injectable scanning dependency used by EndpointRotator.
// Scanner satisfies this interface; tests can provide fakes to avoid live network access.
type EndpointScanner interface {
	Scan(context.Context, []Endpoint) []ScanResult
}

// RotationUpdate is emitted after each successful cache refresh.
type RotationUpdate struct {
	Results []ScanResult
	Current Endpoint
	Healthy bool
}

// EndpointRotator periodically refreshes endpoint health through an injected scanner.
type EndpointRotator struct {
	scanner   EndpointScanner
	cache     *EndpointCache
	endpoints []Endpoint
	interval  time.Duration
	ticks     <-chan time.Time
}

// EndpointRotatorOption customizes EndpointRotator behavior.
type EndpointRotatorOption func(*EndpointRotator)

// WithRotationInterval sets the automatic refresh interval used by Run.
func WithRotationInterval(interval time.Duration) EndpointRotatorOption {
	return func(rotator *EndpointRotator) {
		if interval > 0 {
			rotator.interval = interval
		}
	}
}

// WithRotationTicks injects a tick source for deterministic tests or external schedulers.
func WithRotationTicks(ticks <-chan time.Time) EndpointRotatorOption {
	return func(rotator *EndpointRotator) {
		if ticks != nil {
			rotator.ticks = ticks
		}
	}
}

// NewEndpointRotator creates an endpoint rotator with no live network behavior of its own.
func NewEndpointRotator(scanner EndpointScanner, cache *EndpointCache, endpoints []Endpoint, options ...EndpointRotatorOption) (*EndpointRotator, error) {
	if scanner == nil {
		return nil, errors.New("endpoint scanner is required")
	}
	if cache == nil {
		return nil, errors.New("endpoint cache is required")
	}
	if len(endpoints) == 0 {
		return nil, errors.New("at least one endpoint is required")
	}
	rotator := &EndpointRotator{
		scanner:   scanner,
		cache:     cache,
		endpoints: append([]Endpoint(nil), endpoints...),
		interval:  time.Minute,
	}
	for _, option := range options {
		option(rotator)
	}
	return rotator, nil
}

// Refresh scans once, stores the results in the cache, and returns ranked results.
func (r *EndpointRotator) Refresh(ctx context.Context) ([]ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := r.scanner.Scan(ctx, append([]Endpoint(nil), r.endpoints...))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.cache.Store(results)
	return r.cache.Ranked(), nil
}

// Current returns the best healthy cached endpoint when one is available.
func (r *EndpointRotator) Current() (Endpoint, bool) {
	for _, result := range r.cache.Ranked() {
		if result.Healthy {
			return result.Endpoint, true
		}
	}
	return Endpoint{}, false
}

// Run refreshes immediately and then after each interval or injected tick until ctx is canceled.
func (r *EndpointRotator) Run(ctx context.Context, emit func(RotationUpdate)) error {
	if err := r.refreshAndEmit(ctx, emit); err != nil {
		return err
	}
	if r.ticks != nil {
		return r.runWithTicks(ctx, emit, r.ticks)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	return r.runWithTicks(ctx, emit, ticker.C)
}

func (r *EndpointRotator) runWithTicks(ctx context.Context, emit func(RotationUpdate), ticks <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			if err := r.refreshAndEmit(ctx, emit); err != nil {
				return err
			}
		}
	}
}

func (r *EndpointRotator) refreshAndEmit(ctx context.Context, emit func(RotationUpdate)) error {
	results, err := r.Refresh(ctx)
	if err != nil {
		return err
	}
	if emit != nil {
		current, healthy := r.Current()
		emit(RotationUpdate{Results: results, Current: current, Healthy: healthy})
	}
	return nil
}
