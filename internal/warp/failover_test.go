package warp

import (
	"testing"
	"time"
)

func TestFailoverSelectorMovesToNextHealthyEndpointAfterFailures(t *testing.T) {
	primary := mustEndpoint(t, "162.159.192.10", 2408)
	backup := mustEndpoint(t, "162.159.193.20", 2408)
	unhealthy := mustEndpoint(t, "162.159.194.30", 2408)

	selector, err := NewFailoverSelector([]ScanResult{
		{Endpoint: primary, Healthy: true, RTT: 20 * time.Millisecond},
		{Endpoint: backup, Healthy: true, RTT: 30 * time.Millisecond},
		{Endpoint: unhealthy, Healthy: false, Error: "timeout"},
	}, FailoverAfter(2), WithRollback(true))
	if err != nil {
		t.Fatalf("NewFailoverSelector returned error: %v", err)
	}

	if got := selector.Current(); got != primary {
		t.Fatalf("expected primary endpoint, got %v", got)
	}
	if got := selector.RecordFailure(); got != primary {
		t.Fatalf("expected one failure to stay on primary, got %v", got)
	}
	if got := selector.RecordFailure(); got != backup {
		t.Fatalf("expected second failure to fail over to backup, got %v", got)
	}
	if got := selector.RecordSuccess(); got != primary {
		t.Fatalf("expected rollback to primary after success, got %v", got)
	}
}

func TestFailoverSelectorSupportsFixedEndpointBehavior(t *testing.T) {
	primary := mustEndpoint(t, "162.159.192.10", 2408)
	fixed := mustEndpoint(t, "162.159.193.20", 2408)

	selector, err := NewFailoverSelector([]ScanResult{
		{Endpoint: primary, Healthy: true, RTT: 20 * time.Millisecond},
		{Endpoint: fixed, Healthy: true, RTT: 30 * time.Millisecond},
	}, WithFixedEndpoint(fixed), FailoverAfter(1), WithRollback(true))
	if err != nil {
		t.Fatalf("NewFailoverSelector returned error: %v", err)
	}

	if got := selector.Current(); got != fixed {
		t.Fatalf("expected fixed endpoint, got %v", got)
	}
	if got := selector.RecordFailure(); got != fixed {
		t.Fatalf("expected failure to keep fixed endpoint, got %v", got)
	}
	if got := selector.RecordSuccess(); got != fixed {
		t.Fatalf("expected success to keep fixed endpoint, got %v", got)
	}
}

func TestFailoverSelectorRequiresHealthyEndpoint(t *testing.T) {
	unhealthy := mustEndpoint(t, "162.159.194.30", 2408)
	if _, err := NewFailoverSelector([]ScanResult{{Endpoint: unhealthy, Healthy: false, Error: "timeout"}}); err == nil {
		t.Fatal("expected selector without healthy endpoints to fail")
	}
}
