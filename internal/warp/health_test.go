package warp

import "testing"

func TestParseCloudflareTraceWARPStatus(t *testing.T) {
	tests := []struct {
		name    string
		trace   string
		want    WARPStatus
		healthy bool
	}{
		{
			name:    "off",
			trace:   "fl=123f1\ncolo=SJC\nwarp=off\n",
			want:    WARPStatusOff,
			healthy: false,
		},
		{
			name:    "on",
			trace:   "fl=123f1\ncolo=SJC\nwarp=on\n",
			want:    WARPStatusOn,
			healthy: true,
		},
		{
			name:    "plus",
			trace:   "fl=123f1\ncolo=SJC\nwarp=plus\n",
			want:    WARPStatusPlus,
			healthy: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health, err := ParseCloudflareTrace(test.trace)
			if err != nil {
				t.Fatalf("ParseCloudflareTrace returned error: %v", err)
			}
			if health.WARP != test.want {
				t.Fatalf("expected WARP status %q, got %q", test.want, health.WARP)
			}
			if health.Healthy() != test.healthy {
				t.Fatalf("expected Healthy=%v for %q", test.healthy, test.want)
			}
			if health.Fields["colo"] != "SJC" {
				t.Fatalf("expected trace fields to preserve colo, got %#v", health.Fields)
			}
		})
	}
}

func TestParseCloudflareTraceRejectsMissingOrUnknownWARPStatus(t *testing.T) {
	if _, err := ParseCloudflareTrace("fl=123f1\ncolo=SJC\n"); err == nil {
		t.Fatal("expected missing warp field to fail")
	}
	if _, err := ParseCloudflareTrace("warp=maybe\n"); err == nil {
		t.Fatal("expected unknown warp field to fail")
	}
}
