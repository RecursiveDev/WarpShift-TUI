package warp

import "errors"

type FailoverSelector struct {
	endpoints     []Endpoint
	currentIndex  int
	failures      int
	failoverAfter int
	rollback      bool
	fixedEndpoint *Endpoint
}

type FailoverOption func(*FailoverSelector)

func FailoverAfter(count int) FailoverOption {
	return func(selector *FailoverSelector) {
		if count > 0 {
			selector.failoverAfter = count
		}
	}
}

func WithRollback(enabled bool) FailoverOption {
	return func(selector *FailoverSelector) { selector.rollback = enabled }
}

func WithFixedEndpoint(endpoint Endpoint) FailoverOption {
	return func(selector *FailoverSelector) { selector.fixedEndpoint = &endpoint }
}

func NewFailoverSelector(results []ScanResult, options ...FailoverOption) (*FailoverSelector, error) {
	selector := &FailoverSelector{failoverAfter: 1}
	for _, result := range RankByRTT(results) {
		if result.Healthy {
			selector.endpoints = append(selector.endpoints, result.Endpoint)
		}
	}
	for _, option := range options {
		option(selector)
	}
	if len(selector.endpoints) == 0 {
		return nil, errors.New("at least one healthy endpoint is required")
	}
	if selector.fixedEndpoint != nil {
		for i, endpoint := range selector.endpoints {
			if endpoint == *selector.fixedEndpoint {
				selector.currentIndex = i
				break
			}
		}
	}
	return selector, nil
}

func (s *FailoverSelector) Current() Endpoint {
	return s.endpoints[s.currentIndex]
}

func (s *FailoverSelector) RecordFailure() Endpoint {
	if s.fixedEndpoint != nil {
		return *s.fixedEndpoint
	}
	s.failures++
	if s.failures >= s.failoverAfter && len(s.endpoints) > 1 {
		s.currentIndex = (s.currentIndex + 1) % len(s.endpoints)
		s.failures = 0
	}
	return s.Current()
}

func (s *FailoverSelector) RecordSuccess() Endpoint {
	if s.fixedEndpoint != nil {
		return *s.fixedEndpoint
	}
	s.failures = 0
	if s.rollback {
		s.currentIndex = 0
	}
	return s.Current()
}
