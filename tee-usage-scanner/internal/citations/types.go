// Package citations defines the byte-citation contract that
// expert / challenger / verifier / arbiter use to anchor every
// claim against a specific region of source bytes.
//
// Why bytes and not just line numbers:
//
//   - Line numbers are for humans. They shift under reformatting,
//     auto-import sorting, comment churn, and any whitespace edit.
//   - Byte ranges + sha256 are for machines. They survive
//     reformatting only if the cited content actually drifted; if
//     the file was merely reformatted around the citation, the
//     bytes move but the hash of the cited region stays the same
//     IF the citation pinpointed an unchanged region.
//
// The validator (see Validate) treats sha256 mismatch as drift —
// the citation's facts may no longer hold. Stage stats use this to
// compute citation_validity_rate without re-reading prose.
package citations

// CitedBytes is the canonical citation shape. All fields except
// File / StartLine / EndLine are optional on input — Resolve fills
// them in by reading the repo. Validate then re-derives them and
// compares against the recorded SHA256 to detect drift.
type CitedBytes struct {
	// File is the repo-relative path. Always populated; it is the
	// only field a human author has to write.
	File string `json:"file"`

	// StartLine / EndLine are 1-indexed inclusive line numbers, the
	// same convention humans use when reading code. Both are
	// required and must satisfy StartLine <= EndLine.
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`

	// StartByte / EndByte are 0-indexed half-open byte offsets into
	// File: bytes[StartByte:EndByte] is the cited region. Resolve
	// computes them; Validate recomputes and checks them.
	StartByte int64 `json:"start_byte,omitempty"`
	EndByte   int64 `json:"end_byte,omitempty"`

	// SHA256 is the hex-encoded sha256 of bytes[StartByte:EndByte].
	// Resolve sets it; Validate compares against the live file. A
	// mismatch means the cited region drifted and the citation
	// should no longer be trusted.
	SHA256 string `json:"sha256,omitempty"`
}

// Valid reports whether the citation's required fields are populated.
// A citation is structurally valid even before Resolve fills in the
// byte/hash fields.
func (c CitedBytes) Valid() bool {
	return c.File != "" && c.StartLine >= 1 && c.EndLine >= c.StartLine
}

// Resolved reports whether Resolve has filled in the
// machine-verifiable fields.
func (c CitedBytes) Resolved() bool {
	return c.SHA256 != "" && c.EndByte > c.StartByte
}

// CitedFact pairs a free-text claim with the source bytes the agent
// is anchoring it to. v1.1.1 introduces this as a parallel field on
// Hypothesis (CitedFacts) and (later) VerificationMemo — the
// existing string-only fact arrays remain for legacy artifacts and
// display fallback.
//
// Semantics:
//   - Cited may be empty: the agent stated a claim but did not
//     produce a citation, OR every citation it produced failed to
//     Resolve against the live repo. Such facts MUST NOT be
//     replicated into SupportingFacts (which becomes reserved for
//     facts whose citations resolved cleanly), so consumers can
//     distinguish "validated" from "asserted-without-evidence" at
//     a glance.
//   - Each entry in Cited is a fully-resolved CitedBytes (StartByte
//     / EndByte / SHA256 populated) — writers call citations.Resolve
//     before persistence and drop citations that fail.
type CitedFact struct {
	Text  string       `json:"text"`
	Cited []CitedBytes `json:"cited,omitempty"`
}

// HasValidCitation reports whether at least one Cited entry is
// resolved and intact. Useful for filtering at report time.
func (f CitedFact) HasValidCitation() bool {
	for _, c := range f.Cited {
		if c.Resolved() {
			return true
		}
	}
	return false
}
