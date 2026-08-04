package codeql

import "testing"

// A thin-shell query's answer is in its message and its related locations,
// not in the primary location alone. RollbackVersionNotPropagated selects the
// producer and names, via $@ placeholders, both the producer and the authority
// call sites — so its SARIF result carries relatedLocations pointing at
// core/kernel/ree_fs_ta.c even though the primary location is signed_hdr.c.
// Dropping them left the agents with one line number and no consumer.
func TestParseSARIF_KeepsRelatedLocations(t *testing.T) {
	data := []byte(`{"runs":[{"results":[{
	  "ruleId":"teecheck/trustir-cpp/twe-state-001",
	  "message":{"text":"TWE-STATE-001: producer [shdr_load_pub_key](1) never propagates rollback field 'version'; authority [check_update_version](2) (state_restore_acceptance) therefore checks a default version."},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"core/crypto/signed_hdr.c"},"region":{"startLine":262}}}],
	  "relatedLocations":[
	    {"id":1,"message":{"text":"shdr_load_pub_key"},"physicalLocation":{"artifactLocation":{"uri":"core/crypto/signed_hdr.c"},"region":{"startLine":262}}},
	    {"id":2,"message":{"text":"check_update_version"},"physicalLocation":{"artifactLocation":{"uri":"core/kernel/ree_fs_ta.c"},"region":{"startLine":639}}}
	  ]}]}]}`)

	out, err := ParseSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("results = %d, want 1", len(out))
	}
	r := out[0]
	if r.Message == "" {
		t.Error("message must survive")
	}
	if len(r.Related) != 2 {
		t.Fatalf("related = %+v, want 2", r.Related)
	}
	if r.Related[1].Path != "core/kernel/ree_fs_ta.c" || r.Related[1].StartLine != 639 {
		t.Errorf("related[1] = %+v, want ree_fs_ta.c:639", r.Related[1])
	}
	// The related location's message is the symbol name — this is what fills
	// ToolLocation.Symbol, whose absence the ToolFact has been declaring as a
	// coverage gap ("SARIF related-location parsing not implemented").
	if r.Related[1].Symbol != "check_update_version" {
		t.Errorf("related[1].Symbol = %q, want check_update_version", r.Related[1].Symbol)
	}
}
