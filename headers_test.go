package procproxy

import "testing"

func TestHeaderWhitelist(t *testing.T) {
	filter := NewHeaderAllowList("allowed")
	if !filter.Passes("allowed") {
		t.Fatalf("allowed didn't pass")
	}
	if filter.Passes("forbidden") {
		t.Fatalf("forbidden passed")
	}
}

func TestHeaderBlocklist(t *testing.T) {
	filter := NewHeaderBlockList("forbidden")
	if !filter.Passes("allowed") {
		t.Fatalf("allowed didn't pass")
	}
	if filter.Passes("forbidden") {
		t.Fatalf("forbidden passed")
	}
}