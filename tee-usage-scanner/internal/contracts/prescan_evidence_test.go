package contracts

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPrescanEvidenceLoadsAndBindsImmutableBytes(t *testing.T) {
	ctx, fact, path := taintEvidenceFixture(t)
	fact.Locations = []artifacts.ToolLocation{}
	fact.Operation = artifacts.TaintPrescanOperation
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolFact(path, ctx); err != nil {
		t.Fatalf("prescan evidence was rejected: %v", err)
	}
	ref, err := ResolveEvidence(artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path}, ctx)
	if err != nil || ref.ContentSHA256 == "" {
		t.Fatalf("prescan reference was not frozen: %+v / %v", ref, err)
	}
	fact.CoverageGaps = append(fact.CoverageGaps, "changed metadata")
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveEvidence(ref, ctx); err == nil {
		t.Fatal("rehashed replacement bypassed frozen contract reference")
	}
}

func TestPrescanEvidenceRejectsOtherRunAndUnsuccessfulFact(t *testing.T) {
	ctx, fact, path := taintEvidenceFixture(t)
	fact.Locations = []artifacts.ToolLocation{}
	fact.Operation = artifacts.TaintPrescanOperation
	fact.Status = "unresolved"
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolFact(path, ctx); err == nil {
		t.Fatal("unresolved prescan was accepted as contract evidence")
	}
	fact.Status = "success"
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	ctx.RunDir = t.TempDir()
	if _, err := LoadToolFact(path, ctx); err == nil {
		t.Fatal("foreign-run prescan path was accepted")
	}
}
