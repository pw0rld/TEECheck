package pipeline

import (
	"context"
	"fmt"
	"slices"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// planTWEOperations returns, in stable order, the fact-layer operations this
// run's invariants call for: for each TWE an invariant relates to, the
// operation that answers it, if one exists.
//
// A family with no executable query contributes nothing. That is deliberate —
// running it anyway would persist an "unsupported" ToolFact for a query that
// was never going to execute, which is an artifact describing the tool's
// coverage rather than the code under audit.
func planTWEOperations(invariants []artifacts.ProjectInvariant) []trustirfacts.Operation {
	var out []trustirfacts.Operation
	seen := make(map[trustirfacts.Operation]bool)
	for _, inv := range invariants {
		for _, tweID := range inv.RelatedTWEs {
			op, ok := trustirfacts.OperationForTWE(tweID)
			if !ok || seen[op] {
				continue
			}
			seen[op] = true
			out = append(out, op)
		}
	}
	return out
}

// factRunner is the seam between deciding what to collect and actually
// collecting it. Production passes trustirfacts.RunAndPersist; tests pass a
// stub, because this function's job is choosing operations and filtering
// results — the clone, the database build and the query have their own tests
// in internal/trustirfacts and do not need re-running here.
type factRunner func(context.Context, trustirfacts.Engine, codedb.DatabaseProvider, trustirfacts.Request) (artifacts.ToolFact, string, error)

// prefetchedFact is a collected ToolFact and the files it flagged. Paths is
// empty for a query that matched nothing — a statement about the whole tree
// at this commit rather than about any one file.
type prefetchedFact struct {
	Ref   string
	Paths []string
}

// attachPrefetchedFacts puts each collected fact on the Case Packs it is
// evidence for. CasePack.ToolFactRefs is what expert, challenger, verifier and
// arbiter actually read, and reaching the investigation is not enough: an
// investigation that located no roles yields a pack with no target files, and
// DedupePacks drops those deliberately — handing an agent a case with nothing
// to read asks it to hypothesise about nothing. On 2026-07-31 that is exactly
// what happened: the fact was collected, both investigations carried it, both
// of their packs were dropped, and the surviving candidate-derived pack
// carried nothing.
//
// A fact with locations goes to the packs whose targets include a flagged
// file. A fact with none goes to every pack: "we ran this and matched nothing
// anywhere" is evidence for any case in the run, and it is precisely what the
// fixed half of a differential should produce.
func attachPrefetchedFacts(packs []artifacts.CasePack, facts []prefetchedFact) []artifacts.CasePack {
	if len(facts) == 0 {
		return packs
	}
	for i := range packs {
		targets := make(map[string]bool, len(packs[i].TargetFiles))
		for _, f := range packs[i].TargetFiles {
			targets[f] = true
		}
		for _, fact := range facts {
			relevant := len(fact.Paths) == 0
			for _, p := range fact.Paths {
				if targets[p] {
					relevant = true
					break
				}
			}
			if !relevant {
				continue
			}
			if !slices.Contains(packs[i].ToolFactRefs, fact.Ref) {
				packs[i].ToolFactRefs = append(packs[i].ToolFactRefs, fact.Ref)
			}
		}
	}
	return packs
}

// prefetchFactLayer collects the deterministic evidence this run's invariants
// call for, before the planner starts, and returns the persisted ToolFact
// paths.
//
// Whether an immutable fact gets collected must not depend on the model's
// choice. ToolFact is the one evidence tier that cannot be challenged, and on
// CVE-2026-44362 the query that produces it is right on both revisions — 1 hit
// at core/crypto/signed_hdr.c:262 on the vulnerable side, 0 on the fixed, in
// 106 seconds with no LLM. Across four runs the planner invoked it once, and
// never on the side where the bug lives. The model still interprets the
// ToolFact; it no longer decides whether one exists.
//
// This runs before l3_planner rather than off the case packs: cases.Enrich is
// a later stage, so a pack's related_twes cannot inform the planner that
// produced it. The invariants can — they carry RelatedTWEs and are written by
// the stage before.
//
// A failure here is reported and skipped, never fatal. The planner can still
// call fact_layer_query itself, and a run that produces no ToolFact is a run
// with less evidence, not a broken one.
func prefetchFactLayer(
	ctx context.Context,
	eng trustirfacts.Engine,
	db codedb.DatabaseProvider,
	queryPackDir, runDir, repository, commit string,
	invariants []artifacts.ProjectInvariant,
	run factRunner,
) []prefetchedFact {
	ops := planTWEOperations(invariants)
	if len(ops) == 0 {
		return nil
	}

	var refs []prefetchedFact
	for _, op := range ops {
		fact, path, err := run(ctx, eng, db, trustirfacts.Request{
			RunDir:       runDir,
			Repository:   repository,
			Commit:       commit,
			Operation:    op,
			QueryPackDir: queryPackDir,
		})
		if err != nil {
			fmt.Printf("Warning: fact layer prefetch %s: %v\n", op, err)
			continue
		}
		// Only a success is collected evidence. unsupported/unresolved/error
		// are real answers about the tool's reach, and the planner's own
		// coverage_gaps reporting already carries them — but handing one to
		// downstream agents as a tool_fact_ref would dress "we could not
		// look" up as "we looked".
		if fact.Status != trustirfacts.StatusSuccess {
			fmt.Printf("Fact layer prefetch %s: %s (%s)\n", op, fact.Status, fact.Error)
			continue
		}
		fmt.Printf("Fact layer prefetch %s: %d location(s) -> %s\n", op, len(fact.Locations), path)
		pf := prefetchedFact{Ref: path}
		for _, loc := range fact.Locations {
			if !slices.Contains(pf.Paths, loc.Path) {
				pf.Paths = append(pf.Paths, loc.Path)
			}
		}
		refs = append(refs, pf)
	}
	return refs
}
