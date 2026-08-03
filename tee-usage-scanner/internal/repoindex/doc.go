// Package repoindex builds the deterministic whole-repo program index from
// the run's CodeQL database.
//
// It answers "what structure was observed" and nothing else: no priority, no
// risk label, no TWE mapping. docs/bugs/BUG-003 §3.3 traces what happens
// when the 01 stage decides where the danger is — a lexical "version" hit on
// a UUID comment became a freshness asset, then a role, then a flow, then an
// invariant's anchor, and the Expert only discovered it was a comment after
// the Planner had spent rounds on it. Selecting audit targets is a Planner
// runtime behaviour; this package supplies the material for it.
package repoindex
