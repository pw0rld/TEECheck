/**
 * @name Call site counts
 * @description The four numbers that make the index's own coverage
 *              checkable, so a gap in the edge list is a number rather than
 *              a mystery.
 *
 *              Two identities hold by construction and are asserted in Go:
 *
 *                total    = resolved + unresolved
 *                resolved = edges_possible + external + ambiguous
 *
 *              These are COUNTS, and they are not the lengths of the lists
 *              the other queries return. A QL result is a set, so two calls
 *              at the same line with the same expression collapse to one
 *              row: on OP-TEE@a9386bf the unresolved list holds 1,423 rows
 *              for 1,552 unresolved call sites. The lists are deduplicated
 *              views; these numbers are the multiplicity, and only they can
 *              be checked against each other.
 *
 *              external is a call to a function with no definition in this
 *              tree (memcpy and friends): an edge would carry a callee id
 *              naming no capsule. ambiguous is a call to a function defined
 *              several times, where which definition the linker picks is not
 *              decidable here — emitting one would be a fabrication and
 *              emitting all would claim every implementation is called.
 *
 *              Both are why a function can show no callers while being
 *              called. A consumer that sees only the edge list cannot know
 *              that; these numbers are the scope it needs.
 * @kind table
 * @id teecheck/index/call-site-counts
 *
 * Columns: what, n
 */

import cpp
import Index

from string what, int n
where
  what = "total" and n = count(Call c | exists(c.getFile().getRelativePath()))
  or
  what = "resolved" and
  n = count(Call c | exists(c.getFile().getRelativePath()) and exists(c.getTarget()))
  or
  what = "unresolved" and
  n = count(Call c | exists(c.getFile().getRelativePath()) and not exists(c.getTarget()))
  or
  what = "external" and
  n =
    count(Call c |
      exists(c.getFile().getRelativePath()) and
      exists(c.getTarget()) and
      count(definitionOf(c.getTarget())) = 0
    )
  or
  what = "ambiguous" and
  n =
    count(Call c |
      exists(c.getFile().getRelativePath()) and count(definitionOf(c.getTarget())) > 1
    )
select what, n
