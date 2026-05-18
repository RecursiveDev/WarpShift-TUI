package warp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// RotationStrategy names endpoint rotation triggers supported by the planner.
type RotationStrategy string

const (
	RotationStrategyLatency RotationStrategy = "latency"
	RotationStrategyFailure RotationStrategy = "failure"
	RotationStrategyTimed   RotationStrategy = "timed"
)

// RotationPolicy describes endpoint rotation preferences before target probing.
type RotationPolicy struct {
	Strategies       []RotationStrategy
	FailureThreshold int
	TimedInterval    time.Duration
	MaxLatency       time.Duration
	TargetLabels     []string
	RegionLabels     []string
}

// DefaultRotationPolicy returns a conservative latency/failure rotation policy.
func DefaultRotationPolicy() RotationPolicy {
	return RotationPolicy{
		Strategies:       []RotationStrategy{RotationStrategyLatency, RotationStrategyFailure},
		FailureThreshold: 1,
		TimedInterval:    time.Minute,
		TargetLabels:     []string{"general"},
		RegionLabels:     []string{"global"},
	}
}

// ValidateRotationPolicy validates rotation configuration without making network calls.
func ValidateRotationPolicy(policy RotationPolicy) error {
	if len(policy.Strategies) == 0 {
		return errors.New("rotation policy requires at least one strategy")
	}
	for _, strategy := range policy.Strategies {
		switch strategy {
		case RotationStrategyLatency, RotationStrategyFailure, RotationStrategyTimed:
		default:
			return fmt.Errorf("unsupported rotation strategy %q", strategy)
		}
		if strategy == RotationStrategyFailure && policy.FailureThreshold <= 0 {
			return errors.New("failure-based rotation requires a positive failure threshold")
		}
		if strategy == RotationStrategyTimed && policy.TimedInterval <= 0 {
			return errors.New("timed rotation requires a positive interval")
		}
	}
	if policy.MaxLatency < 0 {
		return errors.New("latency-based rotation maximum cannot be negative")
	}
	return nil
}

// SelectEndpointPoolForRotation returns entries matching policy target/region labels.
func SelectEndpointPoolForRotation(entries []EndpointPoolEntry, policy RotationPolicy) []EndpointPoolEntry {
	labels := append([]string{}, cleanLabels(policy.TargetLabels)...)
	labels = append(labels, cleanLabels(policy.RegionLabels)...)
	return FilterEndpointPool(entries, EndpointPoolFilter{Labels: labels})
}

func cleanLabels(values []string) []string {
	labels := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			labels = append(labels, value)
		}
	}
	return labels
}
