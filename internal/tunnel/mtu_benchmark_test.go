package tunnel

import (
	"context"
	"testing"
)

func BenchmarkDetectMTU(b *testing.B) {
	cfg := MTUDetectionConfig{Min: 1280, Max: 1420, Step: 10, Default: 1280}
	probe := func(_ context.Context, candidate int) (bool, error) {
		return candidate <= 1360, nil
	}
	for i := 0; i < b.N; i++ {
		mtu, result, err := DetectMTU(context.Background(), cfg, probe)
		if err != nil {
			b.Fatalf("DetectMTU: %v", err)
		}
		if mtu != 1360 || !result.ProbedOK {
			b.Fatalf("DetectMTU = mtu=%d result=%+v, want 1360", mtu, result)
		}
	}
}
