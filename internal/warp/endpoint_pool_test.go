package warp

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpandKnownWARPEndpointPoolIsDeterministicAndFilterable(t *testing.T) {
	pool, err := ExpandKnownWARPEndpointPool(EndpointPoolSpec{Ports: []int{2408, 500}, MaxPerPrefix: 2, IncludeIPv4: true, IncludeIPv6: true})
	if err != nil {
		t.Fatalf("ExpandKnownWARPEndpointPool returned unexpected error: %v", err)
	}
	again, err := ExpandKnownWARPEndpointPool(EndpointPoolSpec{Ports: []int{2408, 500}, MaxPerPrefix: 2, IncludeIPv4: true, IncludeIPv6: true})
	if err != nil {
		t.Fatalf("second pool expansion returned unexpected error: %v", err)
	}
	if !reflect.DeepEqual(pool, again) {
		t.Fatal("endpoint pool expansion was not deterministic")
	}
	if len(pool) == 0 {
		t.Fatal("endpoint pool should not be empty")
	}
	first := pool[0]
	if first.Endpoint.Address != "162.159.192.1" || first.Endpoint.Port != 2408 || !hasLabel(first.Labels, "ipv4") || !hasLabel(first.Labels, "cloudflare-warp") {
		t.Fatalf("first endpoint entry = %#v, want deterministic IPv4 WARP endpoint", first)
	}
	ipv6 := FilterEndpointPool(pool, EndpointPoolFilter{AddressFamily: "ipv6"})
	if len(ipv6) == 0 {
		t.Fatal("IPv6 filter should retain generated IPv6 WARP endpoints")
	}
	for _, entry := range ipv6 {
		if strings.Contains(entry.Endpoint.Address, ".") || !hasLabel(entry.Labels, "ipv6") {
			t.Fatalf("IPv6 filtered entry = %#v, want IPv6-labeled endpoint", entry)
		}
		if !IsKnownCloudflareWARPEndpoint(entry.Endpoint) {
			t.Fatalf("generated endpoint should be in known WARP ranges: %#v", entry.Endpoint)
		}
	}
	port500 := FilterEndpointPool(pool, EndpointPoolFilter{Ports: []int{500}})
	if len(port500) == 0 {
		t.Fatal("port filter should retain generated port 500 endpoints")
	}
	for _, entry := range port500 {
		if entry.Endpoint.Port != 500 {
			t.Fatalf("port-filtered endpoint = %#v, want port 500", entry.Endpoint)
		}
	}
}

func hasLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}
