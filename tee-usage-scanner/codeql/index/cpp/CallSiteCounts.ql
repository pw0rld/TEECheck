/**
 * @name Call site counts
 * @description How many call sites there are, and how many have a target the
 *              extractor could name.
 *
 *              These two numbers make the index's own coverage checkable:
 *              total must equal resolved plus the rows UnresolvedCalls.ql
 *              returns. CallEdges.ql is a SUBSET of resolved — it drops
 *              calls whose callee has no definition in this tree (memcpy and
 *              friends) because an edge to a definition that is not in the
 *              index would carry an id pointing at nothing. The difference,
 *              resolved minus the edge count, is that external tail.
 * @kind table
 * @id teecheck/index/call-site-counts
 *
 * Columns: what, n
 */

import cpp

from string what, int n
where
  what = "total" and n = count(Call c | exists(c.getFile().getRelativePath()))
  or
  what = "resolved" and
  n = count(Call c | exists(c.getFile().getRelativePath()) and exists(c.getTarget()))
select what, n
