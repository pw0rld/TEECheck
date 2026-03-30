package kgpack

import "testing"

func TestDefaultGraphExportPath(t *testing.T) {
	got := defaultGraphExportPath("/tmp/DCAP-QVL_v038")
	want := "reports/dcap-qvl-v038-gitnexus-graph.json"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}
