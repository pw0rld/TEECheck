package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type LLMHotspotRequest struct {
	RepoRoot       string
	CodeContext    string // Repomix compressed output
	Focus          string
	MaxHotspots    int
	ProjectProfile artifacts.ProjectProfile
}

func IdentifyHotspotsLLM(ctx context.Context, client llm.Client, req LLMHotspotRequest, temperature float64) ([]artifacts.Hotspot, error) {
	if req.MaxHotspots <= 0 {
		req.MaxHotspots = 12
	}

	systemPrompt := `You are an expert security auditor. Analyze the provided codebase and identify security-relevant hotspots.

You should look for ALL categories of security concerns, including but not limited to:
- Input validation and injection (XSS, SQL injection, command injection, path traversal)
- Authentication and session management (weak auth, token handling, session fixation)
- Authorization and access control (IDOR, privilege escalation, missing checks)
- Cryptography and key management (weak algorithms, hardcoded keys, improper key storage)
- Sensitive data exposure (logging secrets, hardcoded credentials, PII leaks)
- Security misconfiguration (CORS, CSP, debug mode, default credentials)
- Dependency and supply chain risks (known vulnerable packages)
- Trust boundary violations (TEE, enclave, attestation, caller binding)
- State management (race conditions, replay attacks, TOCTOU)
- Error handling (information leaks, fail-open behavior, unhandled errors)
- API security (rate limiting, mass assignment, broken object level auth)

Return a JSON object with a single field:
{
  "hotspots": [
    {
      "hotspot_id": "hotspot-001",
      "kind": "category string (e.g. injection, auth_bypass, key_management, xss, idor, etc.)",
      "priority": "high|medium|low",
      "paths": ["file/path.ts"],
      "symbols": ["functionName"],
      "why_selected": ["reason 1", "reason 2"]
    }
  ]
}

Be thorough. Look at actual code patterns, not just file names. Identify concrete security concerns, not hypothetical ones. Each hotspot should reference specific files and ideally specific functions.`

	focusHint := ""
	if req.Focus != "" && req.Focus != "tee" {
		focusHint = fmt.Sprintf("\n\nPrimary audit focus: %s (but do not limit yourself to this area)", req.Focus)
	}

	languages := "unknown"
	if len(req.ProjectProfile.Languages) > 0 {
		languages = strings.Join(req.ProjectProfile.Languages, ", ")
	}

	userMsg := fmt.Sprintf(`Analyze this codebase for security hotspots. Return up to %d hotspots.

Project info:
- Languages: %s
- Framework hints: %s%s

Codebase (compressed):
%s`,
		req.MaxHotspots,
		languages,
		strings.Join(req.ProjectProfile.FrameworkHints, ", "),
		focusHint,
		req.CodeContext)

	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: systemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userMsg},
		},
		Temperature: temperature,
		JSONMode:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("llm hotspot identification: %w", err)
	}

	var parsed struct {
		Hotspots []struct {
			HotspotID   string   `json:"hotspot_id"`
			Kind        string   `json:"kind"`
			Priority    string   `json:"priority"`
			Paths       []string `json:"paths"`
			Symbols     []string `json:"symbols"`
			WhySelected []string `json:"why_selected"`
		} `json:"hotspots"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return nil, fmt.Errorf("parse hotspot json: %w | raw=%s", err, truncateLLM(resp.Text, 500))
	}

	hotspots := make([]artifacts.Hotspot, 0, len(parsed.Hotspots))
	for i, h := range parsed.Hotspots {
		id := h.HotspotID
		if id == "" {
			id = fmt.Sprintf("hotspot-%03d", i+1)
		}
		hotspots = append(hotspots, artifacts.Hotspot{
			HotspotID:   id,
			Kind:        h.Kind,
			Priority:    normalizePriority(h.Priority),
			Paths:       h.Paths,
			Symbols:     h.Symbols,
			WhySelected: h.WhySelected,
		})
	}

	return hotspots, nil
}

func normalizePriority(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func truncateLLM(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
