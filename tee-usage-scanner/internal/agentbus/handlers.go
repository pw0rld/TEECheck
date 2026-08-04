package agentbus

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// NewLLMHandler builds a bus agent backed by an LLM.
//
// A bus agent has no file access, no tools and no case context of its own —
// it sees a short system prompt and whatever the query carries. So a query
// with no Evidence is refused rather than answered: the only answer available
// would be invented.
//
// That is enforced here rather than asked for in the prompt because the
// prompt route has already failed. The stage prompts said "ToolFacts …
// immutable — cite by fact_id, do not restate as your own finding", and on
// 2026-08-01 reviewer-001 was asked to trace callers of shdr_load_pub_key
// with nothing to read, answered with a call graph containing four functions
// that do not exist in the repository, and that answer alone moved the
// arbiter from needs_review to no_issue_observed over a CodeQL ToolFact
// stating the opposite.
func NewLLMHandler(client llm.Client, systemPrompt string, temperature float64) AgentHandler {
	return func(ctx context.Context, q Query) (Response, error) {
		if strings.TrimSpace(q.Evidence) == "" {
			return Response{}, fmt.Errorf(
				"agent %s has no case evidence to answer from: a bus agent cannot read "+
					"source or run tools, so an answer here would be invented", q.ToAgent)
		}

		userMsg := fmt.Sprintf("Agent %s asks (%s):\n%s", q.FromAgent, q.Kind, q.Question)
		userMsg += "\n\n=== EVIDENCE (this is everything you can see) ===\n" + q.Evidence
		if q.Context != nil {
			userMsg += fmt.Sprintf("\n\nAdditional context: %v", q.Context)
		}

		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt +
				"\n\nYou have NO file access and NO tools. Answer only from the EVIDENCE block " +
				"below; there is no other source available to you. If the question asks for " +
				"something the evidence does not contain — a call graph, a caller list, the body " +
				"of a function you were not shown — say so plainly and answer nothing further. " +
				"Naming a symbol that does not appear in the evidence is a fabrication, not an " +
				"inference." +
				"\n\nReturn a JSON object with fields: answer (string), facts (array of strings).",
			Messages: []llm.Message{
				{Role: "user", Content: userMsg},
			},
			Temperature: temperature,
			JSONMode:    true,
		})
		if err != nil {
			return Response{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return Response{
				QueryID:   q.QueryID,
				FromAgent: q.ToAgent,
				Answer:    resp.Text,
			}, nil
		}

		return Response{
			QueryID:   q.QueryID,
			FromAgent: q.ToAgent,
			Answer:    parsed.Answer,
			Facts:     parsed.Facts,
		}, nil
	}
}

func NewToolHandler(name string, fn func(ctx context.Context, q Query) (Response, error)) AgentHandler {
	return func(ctx context.Context, q Query) (Response, error) {
		return fn(ctx, q)
	}
}
