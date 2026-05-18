package warp

import (
	"testing"
	"time"
)

func TestRotationPolicyValidatesStrategiesAndSelectsLabels(t *testing.T) {
	policy := DefaultRotationPolicy()
	policy.Strategies = []RotationStrategy{RotationStrategyLatency, RotationStrategyFailure, RotationStrategyTimed}
	policy.FailureThreshold = 3
	policy.TimedInterval = 5 * time.Minute
	policy.TargetLabels = []string{"general"}
	policy.RegionLabels = []string{"global"}
	policy.MaxLatency = 150 * time.Millisecond
	if err := ValidateRotationPolicy(policy); err != nil {
		t.Fatalf("ValidateRotationPolicy returned unexpected error: %v", err)
	}
	entries := []EndpointPoolEntry{
		{Endpoint: mustEndpoint(t, "162.159.192.1", 2408), Labels: []string{"cloudflare-warp", "ipv4", "general", "global"}},
		{Endpoint: mustEndpoint(t, "162.159.193.1", 2408), Labels: []string{"cloudflare-warp", "ipv4", "other", "global"}},
		{Endpoint: mustEndpoint(t, "162.159.194.1", 2408), Labels: []string{"cloudflare-warp", "ipv4", "general", "lab"}},
	}
	selected := SelectEndpointPoolForRotation(entries, policy)
	if len(selected) != 1 || selected[0].Endpoint.Address != "162.159.192.1" {
		t.Fatalf("selected entries = %#v, want only matching target and region labels", selected)
	}

	bad := policy
	bad.Strategies = []RotationStrategy{"streaming-unlock"}
	if err := ValidateRotationPolicy(bad); err == nil {
		t.Fatal("expected unsupported rotation strategy to be rejected")
	}
	bad = policy
	bad.TimedInterval = 0
	if err := ValidateRotationPolicy(bad); err == nil {
		t.Fatal("expected timed rotation without positive interval to be rejected")
	}
}
