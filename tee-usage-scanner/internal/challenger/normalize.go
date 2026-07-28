package challenger

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// The Challenger emits two rating fields on two DIFFERENT scales:
//
//	ChallengerIndependentView.Confidence  low | medium | high
//	Challenge.Exploitability              proven | likely | theoretical | unlikely
//
// They were normalized through one shared helper until 2026-07-28, with
// two consequences. Phase 1 asked the model for a confidence word and
// then checked it against the exploitability vocabulary, so *every*
// legal answer fell through to "theoretical" on every run. Phase 2, on
// an off-vocabulary answer, fell back to the EXPERT's confidence — the
// field whose entire purpose is independent judgement, filled with the
// judgement it exists to challenge, and then rendered back into the
// phase-2 prompt as "your phase-1 independent view" so the model
// reasoned from a premise it never held.
//
// Hence: one vocabulary per field, no cross-agent argument anywhere in
// this file's signatures, and an explicit sentinel for missing data.
var (
	confidenceVocabulary     = []string{"low", "medium", "high"}
	exploitabilityVocabulary = []string{"proven", "likely", "theoretical", "unlikely"}
)

const ratingUnrated = artifacts.RatingUnrated

// normalizeConfidence accepts ONLY the confidence scale.
func normalizeConfidence(value string) (string, bool) {
	return matchRating(value, confidenceVocabulary)
}

// normalizeExploitability accepts ONLY the exploitability scale. It
// takes no other agent's judgement as an argument, and there is no
// parameter it could be given one through.
func normalizeExploitability(value string) (string, bool) {
	return matchRating(value, exploitabilityVocabulary)
}

func matchRating(value string, vocabulary []string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, allowed := range vocabulary {
		if value == allowed {
			return allowed, true
		}
	}
	return "", false
}

// ratingSpec tells generateWithRatingRetry which field of a parsed
// reply carries the rating, and which vocabulary it must belong to.
type ratingSpec[T any] struct {
	field string
	// vocabulary is the legal set, used verbatim in the re-ask prompt.
	vocabulary []string
	// normalize is the field's OWN normalizer — normalizeConfidence or
	// normalizeExploitability, never a shared one that would accept the
	// other field's words.
	normalize func(string) (string, bool)
	get       func(*T) string
	set       func(*T, string)
}

// generateWithRatingRetry issues one LLM call, parses the reply into T,
// and checks the rating field against its vocabulary. On a miss it
// re-asks EXACTLY ONCE, following internal/planner's corrective shape
// ("=== YOUR PREVIOUS REPLY WAS REJECTED ==="): the original prompt plus
// a notice that quotes the offending value back and names the legal
// values.
//
// The bound is one. Two malformed replies in a row is a real failure,
// not something to spend budget on — the field is then recorded as
// artifacts.RatingUnrated, never as a value borrowed from another agent
// and never as a silent default that reads like a judgement.
//
// A rejected re-ask leaves the FIRST reply's substantive fields in
// place (reasoning, narrative, counter-arguments); only the rating is
// replaced, because only the rating was unusable.
//
// Every replacement — recovered or not — is returned as an
// artifacts.NormalizationAdjustment so the caller can persist it.
func generateWithRatingRetry[T any](
	ctx context.Context,
	client llm.Client,
	system, user string,
	temperature float64,
	caseID, parseLabel string,
	spec ratingSpec[T],
) (T, []artifacts.NormalizationAdjustment, error) {
	var zero T

	ask := func(userMsg string) (T, error) {
		var parsed T
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: system,
			Messages:     []llm.Message{{Role: "user", Content: userMsg}},
			Temperature:  temperature,
			JSONMode:     true,
		})
		if err != nil {
			return parsed, err
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return parsed, fmt.Errorf("parse %s json: %w | raw=%s", parseLabel, err, truncate(resp.Text, 400))
		}
		return parsed, nil
	}

	parsed, err := ask(user)
	if err != nil {
		return zero, nil, err
	}
	first := strings.TrimSpace(spec.get(&parsed))
	if legal, ok := spec.normalize(first); ok {
		spec.set(&parsed, legal)
		return parsed, nil, nil
	}

	vocab := strings.Join(spec.vocabulary, " | ")
	retryUser := user + "\n\n=== YOUR PREVIOUS REPLY WAS REJECTED ===\n" +
		fmt.Sprintf("Your %q field was %q, which is not on the scale this field uses.\n", spec.field, truncate(first, 120)) +
		fmt.Sprintf("Reply with the same JSON object, but %q MUST be exactly one of: %s.\n", spec.field, vocab) +
		"Do not invent a different scale, do not qualify or hedge the value, do not add prose around the JSON.\n"

	second := ""
	if retried, retryErr := ask(retryUser); retryErr == nil {
		second = strings.TrimSpace(spec.get(&retried))
		if legal, ok := spec.normalize(second); ok {
			spec.set(&retried, legal)
			return retried, []artifacts.NormalizationAdjustment{{
				CaseID: caseID,
				Field:  spec.field,
				Kind:   "reask_recovered",
				From:   first,
				To:     legal,
				Reason: fmt.Sprintf("challenger returned %q for %s, which is not one of %s; one corrective re-ask returned %q, which was used",
					first, spec.field, vocab, legal),
			}}, nil
		}
	}

	spec.set(&parsed, ratingUnrated)
	reason := fmt.Sprintf("challenger returned %q for %s", first, spec.field)
	if second != "" {
		reason += fmt.Sprintf(" and %q on the corrective re-ask", second)
	} else {
		reason += " and the corrective re-ask produced no usable reply"
	}
	reason += fmt.Sprintf("; neither is one of %s, so the field is recorded as %s — missing data, not another agent's judgement",
		vocab, ratingUnrated)

	return parsed, []artifacts.NormalizationAdjustment{{
		CaseID: caseID,
		Field:  spec.field,
		Kind:   "unrated_fallback",
		From:   first,
		To:     ratingUnrated,
		Reason: reason,
	}}, nil
}
