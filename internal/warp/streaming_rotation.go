package warp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ErrNoStreamingRotationCandidates is returned when no bounded candidate can be attempted.
var ErrNoStreamingRotationCandidates = errors.New("no streaming rotation candidates available")

// ErrNoStreamingRotationTargetAccepted is returned when all attempted candidates fail target checks.
var ErrNoStreamingRotationTargetAccepted = errors.New("no streaming rotation target accepted")

// StreamingRotationPlanRequest contains caller-supplied inputs for planning a streaming/IP rotation.
type StreamingRotationPlanRequest struct {
	Policy        RotationPolicy
	EndpointPool  []EndpointPoolEntry
	Profiles      []ProfileSummary
	History       []StreamingRotationResult
	TargetLabels  []string
	Cooldown      time.Duration
	BackoffBase   time.Duration
	MaxCandidates int
}

// StreamingRotationPlan is secret-safe data suitable for CLI/TUI display.
type StreamingRotationPlan struct {
	GeneratedAt  time.Time                    `json:"generated_at"`
	TargetLabels []string                     `json:"target_labels,omitempty"`
	Candidates   []StreamingRotationCandidate `json:"candidates"`
	Skipped      []StreamingRotationSkipped   `json:"skipped,omitempty"`
}

// StreamingRotationCandidate is a non-secret endpoint/profile pairing selected for rotation.
type StreamingRotationCandidate struct {
	Endpoint      Endpoint      `json:"-"`
	EndpointValue string        `json:"endpoint"`
	ProfileName   string        `json:"profile_name,omitempty"`
	ActiveProfile bool          `json:"active_profile,omitempty"`
	Labels        []string      `json:"labels,omitempty"`
	FailureCount  int           `json:"failure_count,omitempty"`
	LastLatency   time.Duration `json:"-"`
	LastLatencyMS int64         `json:"last_latency_ms,omitempty"`
	CooldownUntil time.Time     `json:"cooldown_until,omitempty"`
}

// StreamingRotationSkipped records why a candidate was not included in a plan.
type StreamingRotationSkipped struct {
	Endpoint      Endpoint  `json:"-"`
	EndpointValue string    `json:"endpoint"`
	ProfileName   string    `json:"profile_name,omitempty"`
	Reason        string    `json:"reason"`
	RetryAfter    time.Time `json:"retry_after,omitempty"`
}

// StreamingRotationResult is a secret-safe local history record for future TUI/reporting.
type StreamingRotationResult struct {
	CheckedAt    time.Time `json:"checked_at"`
	Mode         string    `json:"mode,omitempty"`
	Endpoint     string    `json:"endpoint"`
	ProfileName  string    `json:"profile_name,omitempty"`
	TargetLabels []string  `json:"target_labels,omitempty"`
	Healthy      bool      `json:"healthy"`
	TargetOK     bool      `json:"target_ok"`
	LatencyMS    int64     `json:"latency_ms,omitempty"`
	Attempt      int       `json:"attempt,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// StreamingTargetProbeResult describes one injected target check result.
type StreamingTargetProbeResult struct {
	OK      bool
	Latency time.Duration
	Error   string
}

// StreamingTargetProbe checks whether a planned candidate satisfies target labels.
type StreamingTargetProbe func(context.Context, StreamingRotationCandidate, []string) StreamingTargetProbeResult

type streamingRotationStats struct {
	Failures     int
	LastFailure  time.Time
	LastLatency  time.Duration
	LastTargetOK bool
}

// StreamingRotationPlanner builds bounded rotation plans from supplied inputs without implicit network access.
type StreamingRotationPlanner struct {
	clock func() time.Time
}

// StreamingRotationPlannerOption customizes planner behavior.
type StreamingRotationPlannerOption func(*StreamingRotationPlanner)

// WithStreamingRotationClock injects deterministic time for tests and schedulers.
func WithStreamingRotationClock(clock func() time.Time) StreamingRotationPlannerOption {
	return func(planner *StreamingRotationPlanner) {
		if clock != nil {
			planner.clock = clock
		}
	}
}

// NewStreamingRotationPlanner creates a rotation planner over supplied inputs.
func NewStreamingRotationPlanner(options ...StreamingRotationPlannerOption) *StreamingRotationPlanner {
	planner := &StreamingRotationPlanner{clock: time.Now}
	for _, option := range options {
		option(planner)
	}
	if planner.clock == nil {
		planner.clock = time.Now
	}
	return planner
}

// Plan selects endpoint/profile candidates using policy labels, health history, cooldown, and backoff.
func (p *StreamingRotationPlanner) Plan(request StreamingRotationPlanRequest) (StreamingRotationPlan, error) {
	policy := request.Policy
	if len(policy.Strategies) == 0 {
		policy = DefaultRotationPolicy()
	}
	if err := ValidateRotationPolicy(policy); err != nil {
		return StreamingRotationPlan{}, err
	}
	now := p.clock()
	maxCandidates := request.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 3
	}
	cooldown := request.Cooldown
	if cooldown <= 0 {
		cooldown = time.Minute
	}
	backoffBase := request.BackoffBase
	if backoffBase <= 0 {
		backoffBase = cooldown
	}
	threshold := policy.FailureThreshold
	if threshold <= 0 {
		threshold = 1
	}

	labels := append(cleanLabels(policy.TargetLabels), cleanLabels(policy.RegionLabels)...)
	labels = append(labels, cleanLabels(request.TargetLabels)...)
	entries := FilterEndpointPool(request.EndpointPool, EndpointPoolFilter{Labels: labels})
	stats := buildStreamingRotationStats(request.History)
	profiles := request.Profiles
	if len(profiles) == 0 {
		profiles = []ProfileSummary{{}}
	}

	plan := StreamingRotationPlan{GeneratedAt: now, TargetLabels: labels}
	for _, entry := range entries {
		for _, profile := range profiles {
			key := streamingRotationKey(entry.Endpoint.String(), profile.Name)
			stat := stats[key]
			if stat.Failures >= threshold {
				until := stat.LastFailure.Add(streamingBackoff(backoffBase, stat.Failures-threshold))
				if now.Before(until) {
					plan.Skipped = append(plan.Skipped, StreamingRotationSkipped{Endpoint: entry.Endpoint, EndpointValue: entry.Endpoint.String(), ProfileName: profile.Name, Reason: "cooldown", RetryAfter: until})
					continue
				}
			}
			if policy.MaxLatency > 0 && stat.LastLatency > policy.MaxLatency {
				plan.Skipped = append(plan.Skipped, StreamingRotationSkipped{Endpoint: entry.Endpoint, EndpointValue: entry.Endpoint.String(), ProfileName: profile.Name, Reason: "latency"})
				continue
			}
			plan.Candidates = append(plan.Candidates, StreamingRotationCandidate{
				Endpoint:      entry.Endpoint,
				EndpointValue: entry.Endpoint.String(),
				ProfileName:   profile.Name,
				ActiveProfile: profile.Active,
				Labels:        append([]string(nil), entry.Labels...),
				FailureCount:  stat.Failures,
				LastLatency:   stat.LastLatency,
				LastLatencyMS: stat.LastLatency.Milliseconds(),
			})
		}
	}
	sortStreamingRotationCandidates(plan.Candidates)
	if len(plan.Candidates) > maxCandidates {
		plan.Candidates = plan.Candidates[:maxCandidates]
	}
	return plan, nil
}

// StreamingRotationExecutor executes planned candidates through an injected target probe.
type StreamingRotationExecutor struct {
	probe StreamingTargetProbe
	clock func() time.Time
}

// StreamingRotationExecutorOption customizes executor behavior.
type StreamingRotationExecutorOption func(*StreamingRotationExecutor)

// WithStreamingRotationExecutorClock injects deterministic time for run results.
func WithStreamingRotationExecutorClock(clock func() time.Time) StreamingRotationExecutorOption {
	return func(executor *StreamingRotationExecutor) {
		if clock != nil {
			executor.clock = clock
		}
	}
}

// NewStreamingRotationExecutor creates an executor with no live behavior except the injected probe.
func NewStreamingRotationExecutor(probe StreamingTargetProbe, options ...StreamingRotationExecutorOption) (*StreamingRotationExecutor, error) {
	if probe == nil {
		return nil, errors.New("streaming target probe is required")
	}
	executor := &StreamingRotationExecutor{probe: probe, clock: time.Now}
	for _, option := range options {
		option(executor)
	}
	if executor.clock == nil {
		executor.clock = time.Now
	}
	return executor, nil
}

// StreamingRotationRunOptions bounds run-like behavior.
type StreamingRotationRunOptions struct {
	MaxAttempts int
}

// StreamingRotationRun contains all attempted candidates and the selected successful result.
type StreamingRotationRun struct {
	Selected StreamingRotationResult   `json:"selected"`
	Attempts []StreamingRotationResult `json:"attempts"`
}

// Run checks planned candidates until one target succeeds or the bounded attempts are exhausted.
func (e *StreamingRotationExecutor) Run(ctx context.Context, plan StreamingRotationPlan, options StreamingRotationRunOptions) (StreamingRotationRun, error) {
	if len(plan.Candidates) == 0 {
		return StreamingRotationRun{}, ErrNoStreamingRotationCandidates
	}
	maxAttempts := options.MaxAttempts
	if maxAttempts <= 0 || maxAttempts > len(plan.Candidates) {
		maxAttempts = len(plan.Candidates)
	}
	if maxAttempts <= 0 {
		return StreamingRotationRun{}, ErrNoStreamingRotationCandidates
	}
	run := StreamingRotationRun{Attempts: make([]StreamingRotationResult, 0, maxAttempts)}
	for i := 0; i < maxAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		candidate := plan.Candidates[i]
		probeResult := e.probe(ctx, candidate, append([]string(nil), plan.TargetLabels...))
		result := StreamingRotationResult{
			CheckedAt:    e.clock(),
			Mode:         "run",
			Endpoint:     candidate.Endpoint.String(),
			ProfileName:  candidate.ProfileName,
			TargetLabels: append([]string(nil), plan.TargetLabels...),
			Healthy:      probeResult.Error == "",
			TargetOK:     probeResult.OK,
			LatencyMS:    probeResult.Latency.Milliseconds(),
			Attempt:      i + 1,
			Error:        safeRotationError(probeResult.Error),
		}
		run.Attempts = append(run.Attempts, result)
		if result.TargetOK {
			run.Selected = result
			return run, nil
		}
	}
	return run, ErrNoStreamingRotationTargetAccepted
}

// StreamingRotationHistoryStore persists local secret-safe rotation history.
type StreamingRotationHistoryStore struct {
	path string
}

// NewStreamingRotationHistoryStore creates a history store at a local JSON path.
func NewStreamingRotationHistoryStore(path string) (*StreamingRotationHistoryStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("rotation history path is required")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("rotation history path invalid: %w", err)
	}
	return &StreamingRotationHistoryStore{path: abs}, nil
}

// Path returns the cleaned local history path.
func (s *StreamingRotationHistoryStore) Path() string {
	return s.path
}

// Load returns stored rotation history, or an empty slice when no history exists.
func (s *StreamingRotationHistoryStore) Load() ([]StreamingRotationResult, error) {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat rotation history: %w", err)
	}
	if err := ensureRotationHistoryFileMode(s.path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read rotation history: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var history []StreamingRotationResult
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("parse rotation history: %w", err)
	}
	return history, nil
}

// Append adds records to local rotation history using restrictive permissions where supported.
func (s *StreamingRotationHistoryStore) Append(results ...StreamingRotationResult) error {
	history, err := s.Load()
	if err != nil {
		return err
	}
	for _, result := range results {
		result.Error = safeRotationError(result.Error)
		history = append(history, result)
	}
	return writeRotationHistorySecure(s.path, history)
}

func buildStreamingRotationStats(history []StreamingRotationResult) map[string]streamingRotationStats {
	ordered := append([]StreamingRotationResult(nil), history...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].CheckedAt.Before(ordered[j].CheckedAt) })
	stats := map[string]streamingRotationStats{}
	for _, result := range ordered {
		key := streamingRotationKey(result.Endpoint, result.ProfileName)
		stat := stats[key]
		if result.LatencyMS > 0 {
			stat.LastLatency = time.Duration(result.LatencyMS) * time.Millisecond
		}
		stat.LastTargetOK = result.TargetOK
		if result.Healthy && result.TargetOK {
			stat.Failures = 0
		} else {
			stat.Failures++
			stat.LastFailure = result.CheckedAt
		}
		stats[key] = stat
	}
	return stats
}

func streamingRotationKey(endpoint, profile string) string {
	return endpoint + "\x00" + profile
}

func streamingBackoff(base time.Duration, extraFailures int) time.Duration {
	if base <= 0 {
		base = time.Minute
	}
	if extraFailures < 0 {
		extraFailures = 0
	}
	if extraFailures > 5 {
		extraFailures = 5
	}
	return base * time.Duration(1<<extraFailures)
}

func sortStreamingRotationCandidates(candidates []StreamingRotationCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.ActiveProfile != right.ActiveProfile {
			return left.ActiveProfile
		}
		if left.FailureCount != right.FailureCount {
			return left.FailureCount < right.FailureCount
		}
		leftLatency, rightLatency := candidateSortLatency(left.LastLatency), candidateSortLatency(right.LastLatency)
		if leftLatency != rightLatency {
			return leftLatency < rightLatency
		}
		if left.Endpoint.String() != right.Endpoint.String() {
			return left.Endpoint.String() < right.Endpoint.String()
		}
		return left.ProfileName < right.ProfileName
	})
}

func candidateSortLatency(latency time.Duration) time.Duration {
	if latency <= 0 {
		return time.Hour
	}
	return latency
}

func safeRotationError(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	lower := strings.ToLower(value)
	if containsRotationErrorMarker(lower, []string{"private_key", "peer_public_key", "license", "token", "secret", "bearer", "credential", "password", "api_key"}) {
		return "probe failed"
	}
	if containsRotationErrorMarker(lower, []string{"timeout", "timed out", "deadline exceeded"}) {
		return "timeout"
	}
	if containsRotationErrorMarker(lower, []string{"denied", "forbidden", "unauthorized", "permission"}) {
		return "denied"
	}
	if containsRotationErrorMarker(lower, []string{"unavailable", "connection refused", "network is unreachable", "no route", "dns", "temporary failure"}) {
		return "unavailable"
	}
	if containsRotationErrorMarker(lower, []string{"unhealthy", "health check"}) {
		return "unhealthy"
	}

	return "probe failed"
}

func containsRotationErrorMarker(value string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func writeRotationHistorySecure(path string, history []StreamingRotationResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create rotation history directory: %w", err)
	}
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rotation history: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open rotation history: %w", err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write rotation history: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close rotation history: %w", closeErr)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("set rotation history permissions: %w", err)
		}
	}
	return nil
}

func ensureRotationHistoryFileMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat rotation history: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("rotation history file permissions for %s are too open (%04o); chmod 600 %s before loading", path, info.Mode().Perm(), path)
	}
	return nil
}
