package twexpert

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

type stubClient struct {
	reply   string
	lastReq llm.GenerateRequest
}

func (s *stubClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.lastReq = req
	return llm.GenerateResponse{Text: s.reply}, nil
}

func bindingEntry() twe.Entry {
	return twe.Entry{
		ID:              "TWE-BIND-001",
		Family:          twe.FamilyBinding,
		Summary:         "verifies a quote but grants authority to an unbound subject",
		RequiredTrustIR: []string{"claim_field", "authority_subject"},
		AllowedEnums: map[string][]string{
			"claim_field":       {"attested_public_key", "runtime_public_key"},
			"authority_subject": {"registered_worker"},
		},
	}
}

func TestExtractCandidate(t *testing.T) {
	// The model replies with a fenced JSON object (as GLM often does).
	reply := "```json\n{\n  \"site_id\": \"reg-1\",\n  \"roles\": {\n" +
		"    \"claim_field\": { \"enum\": \"attested_public_key\", \"path\": \"src/registry.rs\", \"line\": 9, \"symbol\": \"report.pubkey\" },\n" +
		"    \"authority_subject\": { \"enum\": \"registered_worker\", \"line\": 10, \"symbol\": \"pubkey\" }\n" +
		"  }\n}\n```"
	client := &stubClient{reply: reply}

	cand, err := ExtractCandidate(context.Background(), client, bindingEntry(), "src/registry.rs", "let report = verify_quote(q)?;\nworkers.push(pubkey);", 0.2)
	if err != nil {
		t.Fatal(err)
	}
	if cand.TWEID != "TWE-BIND-001" || cand.SiteID != "reg-1" {
		t.Fatalf("candidate header wrong: %+v", cand)
	}
	claim, ok := cand.Roles["claim_field"]
	if !ok || claim.Enum != "attested_public_key" || claim.Loc.Line != 9 || claim.Loc.Symbol != "report.pubkey" {
		t.Fatalf("claim_field wrong: %+v", claim)
	}
	// authority_subject omitted the path → defaults to the scanned file
	auth := cand.Roles["authority_subject"]
	if auth.Loc.Path != "src/registry.rs" || auth.Loc.Line != 10 {
		t.Fatalf("authority_subject path/line wrong: %+v", auth)
	}
	// the prompt must carry the allowed enums and the line-numbered source
	if !strings.Contains(client.lastReq.Messages[0].Content, "attested_public_key") {
		t.Error("prompt missing allowed enums")
	}
	if !strings.Contains(client.lastReq.Messages[0].Content, "1: let report") {
		t.Error("prompt missing line-numbered source")
	}
}

func TestExtractCandidateBadJSON(t *testing.T) {
	client := &stubClient{reply: "not json at all"}
	if _, err := ExtractCandidate(context.Background(), client, bindingEntry(), "f.rs", "x", 0.2); err == nil {
		t.Fatal("expected parse error on non-JSON reply")
	}
}
