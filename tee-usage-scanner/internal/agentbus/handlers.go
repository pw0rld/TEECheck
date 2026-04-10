package agentbus

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func NewLLMHandler(client llm.Client, systemPrompt string, temperature float64) AgentHandler {
	return func(ctx context.Context, q Query) (Response, error) {
		userMsg := fmt.Sprintf("Agent %s asks (%s):\n%s", q.FromAgent, q.Kind, q.Question)
		if q.Context != nil {
			userMsg += fmt.Sprintf("\n\nAdditional context: %v", q.Context)
		}

		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt + "\n\nReturn a JSON object with fields: answer (string), facts (array of strings).",
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
