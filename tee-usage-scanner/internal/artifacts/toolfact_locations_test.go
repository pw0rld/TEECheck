package artifacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// A ToolFact must always state its locations, even when there are none.
// `locations` was omitempty, so a successful query that matched nothing
// serialised with no locations key at all — on disk indistinguishable from a
// field that was never populated. The fixed half of a vulnerable/fixed
// differential is read entirely on the strength of that reading, so the
// immutable evidence tier has to be able to say "we looked and found
// nothing".
//
// The guarantee belongs to the type, not to each producer: a bare ToolFact
// built anywhere must marshal the same way.
func TestToolFact_NilLocationsMarshalsAsEmptyArray(t *testing.T) {
	data, err := json.Marshal(ToolFact{SchemaVersion: SchemaVersionToolFactV1, Status: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"locations":[]`) {
		t.Fatalf("nil Locations must marshal as an empty array, got: %s", data)
	}
	// null would be rejected by trustir-tool.v1.json, which types locations
	// as an array — the reason this is a marshal hook and not a dropped tag.
	if strings.Contains(string(data), `"locations":null`) {
		t.Fatalf("locations must never marshal as null: %s", data)
	}
}

// Populated locations must survive the hook untouched.
func TestToolFact_PopulatedLocationsAreUnchanged(t *testing.T) {
	data, err := json.Marshal(ToolFact{
		SchemaVersion: SchemaVersionToolFactV1,
		Status:        "success",
		Locations:     []ToolLocation{{Path: "core/crypto/signed_hdr.c", StartLine: 262}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var back ToolFact
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Locations) != 1 || back.Locations[0].StartLine != 262 {
		t.Fatalf("round trip lost locations: %s", data)
	}
}
