package warp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStreamingRotationPlannerAppliesPolicyHealthCooldownAndTargetLabels(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	policy := DefaultRotationPolicy()
	policy.FailureThreshold = 2
	policy.MaxLatency = 150 * time.Millisecond
	policy.TargetLabels = []string{"streaming"}
	policy.RegionLabels = []string{"global"}

	entries := []EndpointPoolEntry{
		{Endpoint: mustEndpoint(t, "162.159.192.1", 2408), Labels: []string{"cloudflare-warp", "streaming", "global", "ipv4"}},
		{Endpoint: mustEndpoint(t, "162.159.193.1", 2408), Labels: []string{"cloudflare-warp", "streaming", "global", "ipv4"}},
		{Endpoint: mustEndpoint(t, "162.159.194.1", 2408), Labels: []string{"cloudflare-warp", "general", "global", "ipv4"}},
	}
	profiles := []ProfileSummary{{Name: "alpha", Active: true}, {Name: "beta"}}
	history := []StreamingRotationResult{
		{CheckedAt: now.Add(-30 * time.Second), Endpoint: entries[0].Endpoint.String(), ProfileName: "alpha", Healthy: false, TargetOK: false, Error: "probe failed"},
		{CheckedAt: now.Add(-20 * time.Second), Endpoint: entries[0].Endpoint.String(), ProfileName: "alpha", Healthy: false, TargetOK: false, Error: "probe failed again"},
		{CheckedAt: now.Add(-15 * time.Second), Endpoint: entries[1].Endpoint.String(), ProfileName: "alpha", Healthy: true, TargetOK: true, LatencyMS: 40},
	}

	planner := NewStreamingRotationPlanner(WithStreamingRotationClock(func() time.Time { return now }))
	plan, err := planner.Plan(StreamingRotationPlanRequest{
		Policy:        policy,
		EndpointPool:  entries,
		Profiles:      profiles,
		History:       history,
		Cooldown:      time.Minute,
		BackoffBase:   time.Minute,
		MaxCandidates: 3,
	})
	if err != nil {
		t.Fatalf("Plan returned unexpected error: %v", err)
	}
	if len(plan.Candidates) == 0 {
		t.Fatal("expected at least one rotation candidate")
	}
	first := plan.Candidates[0]
	if first.Endpoint != entries[1].Endpoint || first.ProfileName != "alpha" || first.FailureCount != 0 {
		t.Fatalf("first candidate = %#v, want healthy active alpha profile on second endpoint", first)
	}
	if first.LastLatency != 40*time.Millisecond {
		t.Fatalf("first candidate latency = %s, want 40ms", first.LastLatency)
	}
	if len(plan.Skipped) == 0 || plan.Skipped[0].Endpoint != entries[0].Endpoint || plan.Skipped[0].Reason != "cooldown" {
		t.Fatalf("skipped = %#v, want first endpoint skipped for cooldown", plan.Skipped)
	}
	for _, candidate := range plan.Candidates {
		if !containsString(candidate.Labels, "streaming") || !containsString(candidate.Labels, "global") {
			t.Fatalf("candidate labels = %v, want streaming/global", candidate.Labels)
		}
	}
}

func TestStreamingRotationExecutorAndHistoryStoreAreSecretSafeAndLocal(t *testing.T) {
	now := time.Date(2026, 5, 18, 11, 0, 0, 0, time.UTC)
	candidates := []StreamingRotationCandidate{
		{Endpoint: mustEndpoint(t, "162.159.192.1", 2408), ProfileName: "alpha", Labels: []string{"streaming", "global"}},
		{Endpoint: mustEndpoint(t, "162.159.193.1", 2408), ProfileName: "beta", Labels: []string{"streaming", "global"}},
	}
	plan := StreamingRotationPlan{GeneratedAt: now, TargetLabels: []string{"streaming"}, Candidates: candidates}
	calls := 0
	executor, err := NewStreamingRotationExecutor(func(ctx context.Context, candidate StreamingRotationCandidate, targetLabels []string) StreamingTargetProbeResult {
		calls++
		if candidate.ProfileName == "alpha" {
			return StreamingTargetProbeResult{OK: false, Latency: 90 * time.Millisecond, Error: "target denied"}
		}
		return StreamingTargetProbeResult{OK: true, Latency: 35 * time.Millisecond}
	}, WithStreamingRotationExecutorClock(func() time.Time { return now.Add(time.Duration(calls) * time.Second) }))
	if err != nil {
		t.Fatalf("NewStreamingRotationExecutor returned unexpected error: %v", err)
	}

	run, err := executor.Run(context.Background(), plan, StreamingRotationRunOptions{MaxAttempts: 2})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if !run.Selected.TargetOK || run.Selected.ProfileName != "beta" || calls != 2 {
		t.Fatalf("run result = %#v calls=%d, want beta selected after two attempts", run, calls)
	}
	if len(run.Attempts) != 2 || run.Attempts[0].TargetOK || !run.Attempts[1].TargetOK {
		t.Fatalf("attempts = %#v, want first denied and second OK", run.Attempts)
	}
	if run.Attempts[0].Error != "denied" {
		t.Fatalf("first attempt error = %q, want categorical denied", run.Attempts[0].Error)
	}

	store, err := NewStreamingRotationHistoryStore(t.TempDir() + string(os.PathSeparator) + "rotation-history.json")
	if err != nil {
		t.Fatalf("NewStreamingRotationHistoryStore returned unexpected error: %v", err)
	}
	opaqueResult := StreamingRotationResult{CheckedAt: now.Add(3 * time.Second), Endpoint: candidates[0].Endpoint.String(), ProfileName: "gamma", Healthy: false, TargetOK: false, Error: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/="}
	if err := store.Append(append(run.Attempts, opaqueResult)...); err != nil {
		t.Fatalf("Append returned unexpected error: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if len(loaded) != 3 || loaded[1].ProfileName != "beta" || !loaded[1].TargetOK {
		t.Fatalf("loaded history = %#v, want three secret-safe attempts", loaded)
	}
	if loaded[0].Error != "denied" || loaded[2].Error != "probe failed" {
		t.Fatalf("loaded errors = %q/%q, want categorical sanitized errors", loaded[0].Error, loaded[2].Error)
	}
	data, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("marshal history: %v", err)
	}
	for _, forbidden := range []string{"private_key", "peer_public_key", "license", "token", "secret"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Fatalf("history leaked forbidden marker %q in %s", forbidden, string(data))
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.Path())
		if err != nil {
			t.Fatalf("stat history file: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("history file mode = %04o, want 0600", got)
		}
	}
}

func TestStreamingRotationHistoryRejectsSymlinkOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}

	dir := t.TempDir()
	target := dir + string(os.PathSeparator) + "target-history.json"
	link := dir + string(os.PathSeparator) + "rotation-history.json"
	if err := os.WriteFile(target, []byte("[]\n"), 0o600); err != nil {
		t.Fatalf("write rotation history target fixture: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create rotation history symlink fixture: %v", err)
	}
	store, err := NewStreamingRotationHistoryStore(link)
	if err != nil {
		t.Fatalf("NewStreamingRotationHistoryStore returned unexpected error: %v", err)
	}

	_, err = store.Load()
	if err == nil {
		t.Fatal("expected symlink rotation history path to be rejected")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Load error = %q, want symlink rejection", err.Error())
	}
}

func TestSafeRotationErrorCategorizesProbeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "timeout", in: "dial tcp 203.0.113.1:443: i/o timeout after 5s", want: "timeout"},
		{name: "deadline", in: "context deadline exceeded", want: "timeout"},
		{name: "denied", in: "target denied by policy", want: "denied"},
		{name: "forbidden", in: "http 403 forbidden", want: "denied"},
		{name: "unavailable", in: "target unavailable: connection refused", want: "unavailable"},
		{name: "network unreachable", in: "dial udp: network is unreachable", want: "unavailable"},
		{name: "unhealthy", in: "target health check unhealthy", want: "unhealthy"},
		{name: "explicit secret marker", in: "private_key=abc123", want: "probe failed"},
		{name: "opaque token-like", in: "probe failed with bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature", want: "probe failed"},
		{name: "opaque base64-like", in: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/=", want: "probe failed"},
		{name: "unknown raw details", in: "upstream returned account abc123 opaque diagnostic", want: "probe failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeRotationError(tt.in); got != tt.want {
				t.Fatalf("safeRotationError(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStreamingRotationExecutorRejectsUnsafeInputs(t *testing.T) {
	if _, err := NewStreamingRotationExecutor(nil); err == nil {
		t.Fatal("expected nil target probe to be rejected")
	}
	executor, err := NewStreamingRotationExecutor(func(context.Context, StreamingRotationCandidate, []string) StreamingTargetProbeResult {
		return StreamingTargetProbeResult{}
	})
	if err != nil {
		t.Fatalf("NewStreamingRotationExecutor returned unexpected error: %v", err)
	}
	_, err = executor.Run(context.Background(), StreamingRotationPlan{}, StreamingRotationRunOptions{MaxAttempts: 1})
	if err == nil || !errors.Is(err, ErrNoStreamingRotationCandidates) {
		t.Fatalf("Run error = %v, want ErrNoStreamingRotationCandidates", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
