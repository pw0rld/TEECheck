package contracts

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func fieldWriteContract() artifacts.CaseInvariantV2 {
	return artifacts.CaseInvariantV2{
		Subjects:            []artifacts.ContractSubject{{Path: "state.c", Symbol: "load", StartLine: 10, EndLine: 20}},
		RequiredProperty:    artifacts.ContractProperty{Kind: "direct_struct_field_assignment", Destination: "state.version", TargetFields: []string{"version"}},
		VerificationQueries: []artifacts.ContractQuery{{Backend: "codeql", Operation: StructFieldWriteOperation, Parameters: map[string]string{"type": "state", "field": "version"}}},
	}
}

func TestValidateVerificationQueriesAllowsEmptyPlan(t *testing.T) {
	c := artifacts.CaseInvariantV2{RequiredProperty: artifacts.ContractProperty{Kind: "unsupported_security_property"}}
	if err := ValidateVerificationQueries(c); err != nil {
		t.Fatalf("empty query plan must remain available for source review: %v", err)
	}
	c.VerificationQueries = []artifacts.ContractQuery{}
	if err := ValidateVerificationQueries(c); err != nil {
		t.Fatal(err)
	}
}

func TestValidateVerificationQueriesRejectsInvalidPlans(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*artifacts.CaseInvariantV2)
		want   string
	}{
		{"unknown backend", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Backend = "shell" }, "unsupported verification query"},
		{"unknown operation", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Operation = "cpp.contract.unknown" }, "leave verification_queries empty"},
		{"property kind mismatch", func(c *artifacts.CaseInvariantV2) { c.RequiredProperty.Kind = "dataflow" }, "registered struct-field property"},
		{"no subject", func(c *artifacts.CaseInvariantV2) { c.Subjects = nil }, "registered struct-field property"},
		{"missing field", func(c *artifacts.CaseInvariantV2) { delete(c.VerificationQueries[0].Parameters, "field") }, "registered struct-field property"},
		{"unknown parameter", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Parameters["script"] = "anything" }, "unknown query parameter"},
		{"type injection", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Parameters["type"] = "state\" or true" }, "invalid query identifier"},
		{"field injection", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Parameters["field"] = "version\n}" }, "invalid query identifier"},
		{"symbol injection", func(c *artifacts.CaseInvariantV2) { c.Subjects[0].Symbol = "load\"" }, "invalid query identifier"},
		{"destination mismatch", func(c *artifacts.CaseInvariantV2) { c.RequiredProperty.Destination = "other.version" }, "differ from the declared property"},
		{"target field mismatch", func(c *artifacts.CaseInvariantV2) { c.RequiredProperty.TargetFields = []string{"other"} }, "differ from the declared property"},
		{"stronger source constraint", func(c *artifacts.CaseInvariantV2) { c.RequiredProperty.Source = "input.version" }, "differ from the declared property"},
		{"stronger authority constraint", func(c *artifacts.CaseInvariantV2) { c.RequiredProperty.Authority = "validate" }, "differ from the declared property"},
		{"missing multi-subject selector", func(c *artifacts.CaseInvariantV2) {
			c.Subjects = append(c.Subjects, artifacts.ContractSubject{Path: "consumer.c", Symbol: "consume"})
		}, "unique subject parameter"},
		{"unmatched selector", func(c *artifacts.CaseInvariantV2) { c.VerificationQueries[0].Parameters["subject"] = "other.c::load" }, "unique subject parameter"},
		{"duplicate selector", func(c *artifacts.CaseInvariantV2) {
			c.Subjects = append(c.Subjects, c.Subjects[0])
			c.VerificationQueries[0].Parameters["subject"] = "state.c::load"
		}, "unique subject parameter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fieldWriteContract()
			tc.change(&c)
			if err := ValidateVerificationQueries(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestStructFieldWriteTargetPreservesExplicitSubjectAcrossReordering(t *testing.T) {
	c := fieldWriteContract()
	want := c.Subjects[0]
	q := c.VerificationQueries[0]
	if got, typ, field, err := StructFieldWriteTarget(c, q); err != nil || got != want || typ != "state" || field != "version" {
		t.Fatalf("single subject: target=%+v type=%s field=%s err=%v", got, typ, field, err)
	}
	c.Subjects = append(c.Subjects, artifacts.ContractSubject{Path: "consumer.c", Symbol: "consume", StartLine: 3, EndLine: 7})
	q.Parameters["subject"] = "state.c::load"
	for i := 0; i < 2; i++ {
		if err := ValidateVerificationQueries(c); err != nil {
			t.Fatal(err)
		}
		got, _, _, err := StructFieldWriteTarget(c, q)
		if err != nil || got != want {
			t.Fatalf("order=%d target=%+v err=%v", i, got, err)
		}
		c.Subjects[0], c.Subjects[1] = c.Subjects[1], c.Subjects[0]
	}
}
