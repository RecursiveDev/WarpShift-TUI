package warp

import (
	"fmt"
	"strings"
)

type WARPStatus string

const (
	WARPStatusOff  WARPStatus = "off"
	WARPStatusOn   WARPStatus = "on"
	WARPStatusPlus WARPStatus = "plus"
)

type Health struct {
	WARP   WARPStatus
	Fields map[string]string
}

func (h Health) Healthy() bool {
	return h.WARP == WARPStatusOn || h.WARP == WARPStatusPlus
}

func ParseCloudflareTrace(trace string) (Health, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(trace, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[key] = value
	}
	status, ok := fields["warp"]
	if !ok {
		return Health{}, fmt.Errorf("trace missing warp status")
	}
	health := Health{Fields: fields, WARP: WARPStatus(status)}
	switch health.WARP {
	case WARPStatusOff, WARPStatusOn, WARPStatusPlus:
		return health, nil
	default:
		return Health{}, fmt.Errorf("unknown warp status")
	}
}
