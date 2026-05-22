package warp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var knownCloudflareWARPPrefixValues = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.194.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"2606:4700:d0::/48",
}

// EndpointPoolSpec controls deterministic expansion of known Cloudflare WARP ranges.
type EndpointPoolSpec struct {
	Ports        []int
	MaxPerPrefix int
	IncludeIPv4  bool
	IncludeIPv6  bool
}

// EndpointPoolEntry attaches non-secret routing labels to a generated endpoint.
type EndpointPoolEntry struct {
	Endpoint Endpoint
	Labels   []string
}

// EndpointPoolFilter filters deterministic endpoint pool entries without probing networks.
type EndpointPoolFilter struct {
	AddressFamily string
	Ports         []int
	Labels        []string
}

// KnownCloudflareWARPPrefixes returns the compact known WARP endpoint ranges used for validation/generation.
func KnownCloudflareWARPPrefixes() ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(knownCloudflareWARPPrefixValues))
	for _, value := range knownCloudflareWARPPrefixValues {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse known WARP prefix %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// ExpandKnownWARPEndpointPool deterministically expands compact WARP ranges into a bounded local pool.
func ExpandKnownWARPEndpointPool(spec EndpointPoolSpec) ([]EndpointPoolEntry, error) {
	ports := normalizeEndpointPoolPorts(spec.Ports)
	if len(ports) == 0 {
		return nil, errors.New("endpoint pool requires at least one port")
	}
	maxPerPrefix := spec.MaxPerPrefix
	if maxPerPrefix <= 0 {
		maxPerPrefix = 1
	}
	includeIPv4, includeIPv6 := spec.IncludeIPv4, spec.IncludeIPv6
	if !includeIPv4 && !includeIPv6 {
		includeIPv4 = true
	}

	entries := []EndpointPoolEntry{}
	prefixes, err := KnownCloudflareWARPPrefixes()
	if err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		if (family == "ipv4" && !includeIPv4) || (family == "ipv6" && !includeIPv6) {
			continue
		}
		addr := firstUsableAddress(prefix)
		for generated := 0; generated < maxPerPrefix && prefix.Contains(addr); generated++ {
			for _, port := range ports {
				endpoint, err := NewEndpoint(addr.String(), port, TransportUDP)
				if err != nil {
					return nil, fmt.Errorf("generate endpoint pool: %w", err)
				}
				entries = append(entries, EndpointPoolEntry{
					Endpoint: endpoint,
					Labels:   []string{"cloudflare-warp", "global", "general", family, "range:" + prefix.String()},
				})
			}
			addr = addr.Next()
		}
	}
	return entries, nil
}

// FilterEndpointPool filters generated endpoints by address family, port, and labels.
func FilterEndpointPool(entries []EndpointPoolEntry, filter EndpointPoolFilter) []EndpointPoolEntry {
	family := strings.ToLower(strings.TrimSpace(filter.AddressFamily))
	ports := map[int]bool{}
	for _, port := range filter.Ports {
		ports[port] = true
	}
	labels := make([]string, 0, len(filter.Labels))
	for _, label := range filter.Labels {
		label = strings.TrimSpace(label)
		if label != "" {
			labels = append(labels, label)
		}
	}
	filtered := make([]EndpointPoolEntry, 0, len(entries))
	for _, entry := range entries {
		addr, err := netip.ParseAddr(entry.Endpoint.Address)
		if err != nil {
			continue
		}
		if family == "ipv4" && !addr.Is4() {
			continue
		}
		if family == "ipv6" && !addr.Is6() {
			continue
		}
		if len(ports) > 0 && !ports[entry.Endpoint.Port] {
			continue
		}
		if !entryHasLabels(entry, labels) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func normalizeEndpointPoolPorts(values []int) []int {
	if len(values) == 0 {
		values = []int{2408}
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, port := range values {
		if port <= 0 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports
}

func firstUsableAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	next := addr.Next()
	if prefix.Contains(next) {
		return next
	}
	return addr
}

func entryHasLabels(entry EndpointPoolEntry, labels []string) bool {
	if len(labels) == 0 {
		return true
	}
	available := map[string]bool{}
	for _, label := range entry.Labels {
		available[label] = true
	}
	for _, label := range labels {
		if !available[label] {
			return false
		}
	}
	return true
}
