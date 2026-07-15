# Benchmark Candidates

This directory contains CVE records that are useful for future collection but
are not benchmark cases yet. A candidate can be promoted into
`benchmark/cases/` only after both vulnerable and fixed source snapshots are
materialized, the exact revisions are pinned, file hashes are recorded, and a
reviewed oracle is added.

`source-pending/` currently contains 18 records. They must not be included in
scanner recall, precision, or paired vulnerable/fixed comparisons.
