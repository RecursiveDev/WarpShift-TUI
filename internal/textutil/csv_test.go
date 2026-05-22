package textutil

import (
	"reflect"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: []string{}},
		{name: "whitespace only", raw: " \t\n ", want: []string{}},
		{name: "single", raw: "alpha", want: []string{"alpha"}},
		{name: "multi", raw: "alpha,beta,gamma", want: []string{"alpha", "beta", "gamma"}},
		{name: "mixed spacing and empty entries", raw: " alpha, , beta ,, gamma ", want: []string{"alpha", "beta", "gamma"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCSV(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SplitCSV(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}
