package llm_test

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// arrayWrapped is the exact reply shape that killed a live glm-5.2 run on
// 2026-07-29: a perfectly good object, wrapped in an array next to a stray
// string list. agentutil.ExtractJSONObject refuses to mine an object out of a
// top-level array (silently unwrapping one is a guess), so this is a parse
// failure — and before the shared re-ask it was a dead stage and a dead
// pipeline.
const arrayWrapped = `[["hash_idx"], {"issue_present": true, "reasoning": "hash_is_valid(hash_idx) at lines 58-63 is inside the guarded branch"}]`

const cleanObject = `{"issue_present": true, "reasoning": "recovered on the re-ask"}`

type reply struct {
	IssuePresent bool   `json:"issue_present"`
	Reasoning    string `json:"reasoning"`
}

func askJSON(t *testing.T, fake *llmtest.FakeClient, out *reply) (llm.GenerateResponse, error) {
	t.Helper()
	return llm.GenerateJSON(context.Background(), fake, "challenger phase-1", llm.GenerateRequest{
		SystemPrompt: "you are a test agent",
		Messages:     []llm.Message{{Role: "user", Content: "ORIGINAL-PROMPT-MARKER"}},
		JSONMode:     true,
	}, out)
}

// The failure that motivated the whole change: the recovered value — not the
// rejected one, and not a zero value — is what the caller gets back.
func TestGenerateJSON_RecoversFromArrayWrappedObject(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrapped, cleanObject}}

	var out reply
	resp, err := askJSON(t, fake, &out)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (first reply + one corrective re-ask)", len(fake.Calls))
	}
	if !out.IssuePresent || out.Reasoning != "recovered on the re-ask" {
		t.Errorf("parsed value = %+v, want the re-asked reply's fields", out)
	}
	if resp.Text != cleanObject {
		t.Errorf("returned response = %q, want the recovered reply (callers echo it back into the dialog)", resp.Text)
	}
}

// Other shapes models actually produce. Some are recoverable by extraction
// alone (prose, fence) and must NOT cost a second call; the rest must.
func TestGenerateJSON_RealReplyShapes(t *testing.T) {
	tests := []struct {
		name      string
		responses []string
		wantCalls int
		wantText  string
	}{
		{
			name:      "prose before the object parses on the first reply",
			responses: []string{"Let me continue reading.\n" + `{"issue_present": true, "reasoning": "recovered on the re-ask"}`},
			wantCalls: 1,
			wantText:  "recovered on the re-ask",
		},
		{
			name:      "json fence parses on the first reply",
			responses: []string{"```json\n" + cleanObject + "\n```"},
			wantCalls: 1,
			wantText:  "recovered on the re-ask",
		},
		{
			name:      "bare array is re-asked",
			responses: []string{`["hash_idx", "hash_len"]`, cleanObject},
			wantCalls: 2,
			wantText:  "recovered on the re-ask",
		},
		{
			name:      "empty reply is re-asked",
			responses: []string{"   ", cleanObject},
			wantCalls: 2,
			wantText:  "recovered on the re-ask",
		},
		{
			name:      "re-ask itself may arrive fenced or prose-wrapped",
			responses: []string{arrayWrapped, "Here you go:\n```json\n" + cleanObject + "\n```"},
			wantCalls: 2,
			wantText:  "recovered on the re-ask",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &llmtest.FakeClient{Responses: tc.responses}
			var out reply
			if _, err := askJSON(t, fake, &out); err != nil {
				t.Fatalf("GenerateJSON: %v", err)
			}
			if len(fake.Calls) != tc.wantCalls {
				t.Errorf("llm calls = %d, want %d", len(fake.Calls), tc.wantCalls)
			}
			if out.Reasoning != tc.wantText {
				t.Errorf("reasoning = %q, want %q", out.Reasoning, tc.wantText)
			}
		})
	}
}

// The bound is one re-ask. Asserting the exact count fails in both
// directions: at 1 the re-ask is gone, at 3 the bound has been raised.
func TestGenerateJSON_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrapped, `["still", "an", "array"]`}, Default: cleanObject}

	var out reply
	_, err := askJSON(t, fake, &out)
	if err == nil {
		t.Fatal("want an error after two malformed replies, got nil")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2 (one reply + one re-ask, never more)", len(fake.Calls))
	}
	if !strings.Contains(err.Error(), "parse challenger phase-1 json") {
		t.Errorf("error = %q, want it to name the agent label", err)
	}
	if !strings.Contains(err.Error(), "raw=") {
		t.Errorf("error = %q, want the rejected raw reply quoted for diagnosis", err)
	}
}

// No gratuitous second call when the model complied.
func TestGenerateJSON_CleanReplyCostsExactlyOneCall(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{cleanObject}, Default: cleanObject}

	var out reply
	if _, err := askJSON(t, fake, &out); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("llm calls = %d, want exactly 1 (a compliant reply must not be re-asked)", len(fake.Calls))
	}
}

// The re-ask has to actually correct the model: it keeps the original
// prompt, says the previous reply was rejected, quotes it back, and demands
// the bare object. This is the planner's wording, reused verbatim where it
// fits, so the system speaks with one voice.
func TestGenerateJSON_ReAskPromptCarriesTheRejectionNotice(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrapped, cleanObject}}

	var out reply
	if _, err := askJSON(t, fake, &out); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2", len(fake.Calls))
	}
	second := fake.Calls[1]
	if second.SystemPrompt != fake.Calls[0].SystemPrompt {
		t.Errorf("re-ask changed the system prompt: %q", second.SystemPrompt)
	}
	body := second.Messages[len(second.Messages)-1].Content
	for _, want := range []string{
		"ORIGINAL-PROMPT-MARKER",
		"=== YOUR PREVIOUS REPLY WAS REJECTED ===",
		"no markdown fence",
		"Your rejected reply began:",
		`[["hash_idx"]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("re-ask prompt missing %q:\n%s", want, body)
		}
	}
}

// A transport error is not a parse failure: the retry layer in NewClient
// already owns those, and re-asking on top of it would multiply the calls.
func TestGenerateJSON_TransportErrorIsNotReAsked(t *testing.T) {
	fake := &llmtest.FakeClient{Err: context.DeadlineExceeded}

	var out reply
	if _, err := askJSON(t, fake, &out); err == nil {
		t.Fatal("want the transport error surfaced")
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("llm calls = %d, want exactly 1", len(fake.Calls))
	}
}

// The re-ask must attach to the LAST user turn, not clobber an ongoing
// dialog: verifier and arbiter accumulate assistant/user rounds and echo
// replies back into the conversation.
func TestGenerateJSON_ReAskPreservesMultiTurnDialog(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrapped, cleanObject}}
	original := []llm.Message{
		{Role: "user", Content: "round-1 question"},
		{Role: "assistant", Content: "round-1 answer"},
		{Role: "user", Content: "round-2 question"},
	}

	var out reply
	if _, err := llm.GenerateJSON(context.Background(), fake, "verifier", llm.GenerateRequest{
		SystemPrompt: "sys",
		Messages:     original,
	}, &out); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	second := fake.Calls[1]
	if len(second.Messages) != 3 {
		t.Fatalf("re-ask messages = %d, want the same 3 turns with the notice appended", len(second.Messages))
	}
	if second.Messages[1].Content != "round-1 answer" || second.Messages[1].Role != "assistant" {
		t.Errorf("re-ask disturbed the earlier turns: %+v", second.Messages)
	}
	if !strings.HasPrefix(second.Messages[2].Content, "round-2 question") {
		t.Errorf("re-ask did not build on the last user turn: %q", second.Messages[2].Content)
	}
	if original[2].Content != "round-2 question" {
		t.Errorf("caller's own message slice was mutated: %q", original[2].Content)
	}
}
