package trustirfacts

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// A ToolFact must state a zero result rather than omit it. `locations` was
// `omitempty`, so a successful query that matched nothing serialised with no
// locations key at all — on disk indistinguishable from a field that was
// never populated. The immutable evidence tier has to be able to say "we
// looked and found nothing"; that is the whole basis on which the fixed side
// of a differential is read.
func TestNewFact_LocationsIsAlwaysPresentInJSON(t *testing.T) {
	fact := newFact(Request{Operation: OperationRollbackVersionPropagation, Commit: "abc"})
	data, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"locations":[]`) {
		t.Fatalf("marshaled fact must carry an explicit empty locations array, got: %s", data)
	}
}

// And every status must still validate: the schema types locations as an
// array, so a nil slice serialising to null would be rejected by Persist.
func TestFactStatuses_SerialiseSchemaValid(t *testing.T) {
	base := newFact(Request{Operation: OperationRollbackVersionPropagation, Commit: "abc"})
	base.FactID = "trustir-cpp-test"

	for name, fact := range map[string]any{
		"unsupported": unsupportedFact(base, "no fact table"),
		"unresolved":  unresolvedFact(base, "analyze failed"),
		"error":       errorFact(base, "materialize failed"),
		"success-zero": func() any {
			f := base
			f.Status = StatusSuccess
			f.Locations = toolLocations(nil)
			return f
		}(),
	} {
		data, err := json.Marshal(fact)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if err := schema.Validate(schema.TrustIRToolV1, data); err != nil {
			t.Errorf("%s: %v\n%s", name, err, data)
		}
	}
}
