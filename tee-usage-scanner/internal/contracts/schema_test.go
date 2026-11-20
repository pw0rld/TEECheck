package contracts

import (
	"encoding/json"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
	"testing"
)

func TestContractSchema_StrictPropertiesAndOptionalQuery(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "rev")
	c, _, err := Bind(draft(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(c)
	if err = schema.Validate(schema.CaseInvariantV2, data); err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	json.Unmarshal(data, &obj)
	obj["assessment"] = "violated"
	data, _ = json.Marshal(obj)
	if err = schema.Validate(schema.CaseInvariantV2, data); err == nil {
		t.Fatal("verdict injected into definition accepted")
	}
}
