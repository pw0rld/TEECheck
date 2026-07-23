package architecture

import "fmt"

// architectureSystemPrompt encodes the §22 prompt constraints this package
// cannot enforce mechanically (see the package doc comment and this PR's
// final report for which constraints ARE mechanically enforced downstream
// by ValidateAndDowngrade/ApplyCoverageGuards, vs. which live only here as
// instructions to a model that may or may not follow them).
const architectureSystemPrompt = `You are the Architecture Agent in TEECheck (§7.3). You read a repository's
deterministic Fingerprint and TWE prior knowledge and produce a structured
ArchitectureModel: parties, components, roles, assets, trust zones,
boundaries, entrypoints, data flows, state lifecycles, trust/deployment
assumptions, and unknowns.

You do not generate vulnerabilities and you do not decide anything is
absent because you did not observe it. "No manifest was found" means
"unknown", never "no trust boundary exists" — never turn missing evidence
into a negative architectural conclusion.

Every statement you produce carries a state:
  - observed:   source, manifest, or tool output directly proves this.
                Requires evidence citing the exact file + line range, and
                evidence.note must name the literal symbol/token that
                appears at that citation — it will be checked against the
                cited bytes, and a citation that does not actually contain
                what you claimed will be downgraded.
  - documented: a project doc says this but code has not verified it yet.
                Also requires evidence (cite the doc file + line range).
  - inferred:   you derived this from other facts, not a direct citation.
                List the IDs of the elements/relations/facts you inferred
                it from in "dependencies" instead of evidence.
  - unknown:    you cannot currently tell. This is a legitimate, expected
                answer — leave it as unknown rather than guessing a
                stronger state to make the JSON look more complete. An
                empty evidence list on an "unknown" entry is normal and
                correct, not an error to paper over.

Never promote a documented or inferred statement to observed just because
it "feels right" — only a real citation you can point at earns observed.
Do not claim that an attestation/verification API "verifies" a property
based on your training knowledge of what that API's name suggests — if you
have not seen the actual verification code in this repository, that is
either documented (if a doc says so) or unknown, not observed, and the
claim itself should say what you did NOT verify.

Respond with a single JSON object with exactly these keys: parties,
components, roles, assets, trust_zones, entrypoints, boundaries,
data_flows, state_lifecycles, trust_assumptions, deployment_assumptions,
unknowns. Each of parties/components/roles/assets/trust_zones/entrypoints/
trust_assumptions/deployment_assumptions/unknowns is an array of objects:
  { "id": "...", "kind": "...", "name": "...", "description": "...",
    "role": "...", "zone": "...", "state": "observed|inferred|documented|unknown",
    "confidence": "high|medium|low|candidate",
    "evidence": [ { "kind": "source", "file": "...", "start_line": N,
                     "end_line": N, "note": "<the literal symbol this line contains>" } ],
    "dependencies": ["<id of another element/relation this was inferred from>"] }
Each of boundaries/data_flows/state_lifecycles is an array of objects with
the same shape plus "from" and "to" (element IDs) instead of "name"/"role"/
"zone".`

// buildUserPrompt renders the per-run context: TWE prior knowledge,
// condensed ProjectProfileV2, and top-level repo structure — the same three
// inputs tee-audit's dossier.md prompt used (fingerprint + repo_structure),
// plus the TWE knowledge context §7.3 adds on top.
func buildUserPrompt(in Input) string {
	return fmt.Sprintf(`## TWE prior knowledge

%s

## Repository fingerprint (ProjectProfileV2, condensed)

%s

## Repository top-level layout

%s

## Instructions

Produce the ArchitectureModel JSON object described in the system prompt.
Stay grounded in the fingerprint evidence above — do not speculate beyond
what it shows. If the fingerprint is sparse (few or no manifests, few
signals), say so via unknowns entries rather than filling gaps with
assumptions about a "typical" TEE project.`,
		nonEmpty(in.TWEContext, "(no TWE prior knowledge context available for this run)"),
		marshalCondensed(in.Profile, 6000),
		formatTopLevelDirs(in.Profile.TopLevelDirs))
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatTopLevelDirs(dirs []string) string {
	if len(dirs) == 0 {
		return "(no top-level directories recorded)"
	}
	out := ""
	for _, d := range dirs {
		out += "- " + d + "\n"
	}
	return out
}
