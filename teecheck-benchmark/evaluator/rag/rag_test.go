package rag

import "testing"

func TestRetrieveUsesReportAndFileEvidence(t *testing.T) {
	cases := []Case{
		{ID: "TWE-BIND-0001", PrimaryFile: "src/registry.rs", Documents: []Document{{Kind: "oracle", Text: "attested public key is not bound to registered public key"}}},
		{ID: "CVE-OTHER", PrimaryFile: "src/other.c", Documents: []Document{{Kind: "oracle", Text: "integer overflow"}}},
	}
	hits := Retrieve(cases, Report{Findings: []Finding{{Files: []string{"src/registry.rs"}, Summary: "attested public key is not bound to registered key"}}}, 2)
	if len(hits) != 1 || hits[0].CaseID != "TWE-BIND-0001" {
		t.Fatalf("unexpected hits: %#v", hits)
	}
}
