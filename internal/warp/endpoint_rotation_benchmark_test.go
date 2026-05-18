package warp

import (
	"testing"
	"time"
)

func BenchmarkEndpointPoolExpansion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		entries, err := ExpandKnownWARPEndpointPool(EndpointPoolSpec{Ports: []int{2408, 500}, MaxPerPrefix: 2, IncludeIPv4: true, IncludeIPv6: true})
		if err != nil {
			b.Fatalf("ExpandKnownWARPEndpointPool: %v", err)
		}
		if len(entries) == 0 {
			b.Fatal("expected generated endpoint entries")
		}
	}
}

func BenchmarkStreamingRotationPlan(b *testing.B) {
	entries, err := ExpandKnownWARPEndpointPool(EndpointPoolSpec{Ports: []int{2408}, MaxPerPrefix: 2, IncludeIPv4: true})
	if err != nil {
		b.Fatalf("ExpandKnownWARPEndpointPool: %v", err)
	}
	profiles := []ProfileSummary{{Name: "default", Active: true}, {Name: "backup"}}
	history := []StreamingRotationResult{{CheckedAt: time.Unix(1700000000, 0), Endpoint: entries[0].Endpoint.String(), ProfileName: "backup", Healthy: false, TargetOK: false, LatencyMS: 200}}
	policy := RotationPolicy{Strategies: []RotationStrategy{RotationStrategyLatency, RotationStrategyFailure}, FailureThreshold: 2, TargetLabels: []string{"general"}, RegionLabels: []string{"global"}}
	planner := NewStreamingRotationPlanner(WithStreamingRotationClock(func() time.Time { return time.Unix(1700000600, 0) }))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := planner.Plan(StreamingRotationPlanRequest{Policy: policy, EndpointPool: entries, Profiles: profiles, History: history, Cooldown: time.Minute, BackoffBase: time.Minute, MaxCandidates: 4})
		if err != nil {
			b.Fatalf("Plan: %v", err)
		}
		if len(plan.Candidates) == 0 {
			b.Fatal("expected rotation candidates")
		}
	}
}
