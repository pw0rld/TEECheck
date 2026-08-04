// Package observationlimits holds the one byte cap on anything that reaches
// a model as an observation.
//
// It is a package of its own, importing nothing, because three layers need
// the same number and none of them should depend on the others:
// internal/projectmap sizes its function-card pages by it, the planner's
// actions cap their output by it, and the planner core excerpts an
// observation by it. Putting it in planner/actions would make projectmap — a
// deterministic 01B stage — import the planner.
//
// Before this existed the numbers disagreed: pages were built to a 32 KiB
// budget and the planner then cut every observation to 4000 characters with
// no marker, so a page sized for one limit arrived at the model cut by
// another, looking complete.
package observationlimits

// MaxBytes bounds one observation.
//
// Chosen against what a useful answer looks like rather than against a token
// budget: a page of function cards, a function body, a handful of call
// sites. The measured baseline behind it is OP-TEE's capsule set — 6.36 MB
// over 11,301 definitions, median 225 B and p90 734 B, with a 26 KB
// maximum — so a page holding one very large capsule and a page holding two
// hundred small ones are both legal and both fit.
const MaxBytes = 32 * 1024
