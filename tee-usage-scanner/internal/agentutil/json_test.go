package agentutil

import (
	"strings"
	"testing"
)

// probeA is the shape of reply that made the extractor silently return a
// wrong answer in production: a JSON array whose string elements contain C
// source. The raw newlines inside the strings make the whole text invalid
// JSON, so the extractor falls through to brace scanning, where the first
// `{` byte belongs to `if (x) { ok(); }` — balanced, but not JSON.
const probeA = `[["return CRYPT_INVALID_PACKET;
}

if (x) { ok(); }", "more"]]`

// probeAValidArray is the same shape, but with the newlines escaped so the
// whole text is a syntactically valid JSON array. Callers want an object.
const probeAValidArray = `[["return CRYPT_INVALID_PACKET;\n}\n\nif (x) { ok(); }", "more"]]`

// probeB killed a live challenger run: prose containing C source with an
// unbalanced `{`, followed by the real JSON object.
const probeB = "Here is my analysis of `foo() {` in the source.\n" +
	"The call `ltc_mp.rsa_me(sig, siglen, ...)` returns early.\n" +
	`{"claim":"x"}`

const probeC = "Sure, here you go:\n" + `{"claim":"x"}`

func TestExtractJSONObject(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		// errContains, when non-empty, requires an error whose message
		// contains this substring.
		errContains string
	}{
		{
			name:        "probe A: code fragment inside an array string is not an object",
			in:          probeA,
			errContains: "none parsed as json",
		},
		{
			name:        "probe A variant: syntactically valid array is rejected as an array",
			in:          probeAValidArray,
			errContains: "json array",
		},
		{
			name: "probe B: prose with unbalanced brace before the real object",
			in:   probeB,
			want: `{"claim":"x"}`,
		},
		{
			name: "probe C: prose prefix then object",
			in:   probeC,
			want: `{"claim":"x"}`,
		},
		{
			// The dangerous shape: a balanced-but-not-JSON brace span sits
			// *before* the real answer. An extractor that commits to the
			// first "{" either returns the C fragment or gives up, and in
			// both cases the model's actual reply is thrown away.
			name: "balanced code fragment before the real object is skipped",
			in:   "The guard is `if (x) { ok(); }` in the source.\n" + `{"claim":"x"}`,
			want: `{"claim":"x"}`,
		},
		{
			// Two balanced-but-invalid spans before the answer: scanning
			// must keep going, not merely advance by one.
			name: "several code fragments before the real object are all skipped",
			in: "First `{ a(); }` then `{ b(); }` and finally:\n" +
				`{"claim":"x","score":1}`,
			want: `{"claim":"x","score":1}`,
		},
		{
			name: "whole text is already a JSON object",
			in:   `{"claim":"x","score":3}`,
			want: `{"claim":"x","score":3}`,
		},
		{
			name: "whole text is a JSON object with surrounding whitespace",
			in:   "\n\t  " + `{"claim":"x"}` + "  \n",
			want: `{"claim":"x"}`,
		},
		{
			name: "fenced json block",
			in:   "```json\n" + `{"claim":"x"}` + "\n```",
			want: `{"claim":"x"}`,
		},
		{
			name: "bare fenced block",
			in:   "```\n" + `{"claim":"x"}` + "\n```",
			want: `{"claim":"x"}`,
		},
		{
			name: "fenced block with prose before and after",
			in: "Based on the code, here is the result:\n\n```json\n" +
				`{"claim":"x","score":3}` +
				"\n```\n\nLet me know if you need anything else.",
			want: `{"claim":"x","score":3}`,
		},
		{
			name:        "fenced json array is rejected as an array, not mined for its first object",
			in:          "```json\n" + `[{"claim":"x"},{"claim":"y"}]` + "\n```",
			errContains: "json array",
		},
		{
			name:        "bare json array is rejected",
			in:          `[{"claim":"x"},{"claim":"y"}]`,
			errContains: "json array",
		},
		{
			name: "nested objects",
			in:   "Result:\n" + `{"a":{"b":{"c":1}},"d":2}`,
			want: `{"a":{"b":{"c":1}},"d":2}`,
		},
		{
			name: "string value containing escaped quotes and stray braces",
			in:   "Here:\n" + `{"note":"he said \"hi\" and left a { unclosed"}` + "\nDone.",
			want: `{"note":"he said \"hi\" and left a { unclosed"}`,
		},
		{
			name: "object with raw newlines in a string value is returned unrepaired",
			in:   "{\"summary\":\"line one\nline two\"}",
			want: "{\"summary\":\"line one\nline two\"}",
		},
		{
			name: "object with raw newlines in a string value, embedded in prose",
			in:   "Analysis follows.\n{\"summary\":\"line one\nline two\"}\nEnd.",
			want: "{\"summary\":\"line one\nline two\"}",
		},
		{
			name:        "empty input",
			in:          "",
			errContains: "empty",
		},
		{
			name:        "whitespace-only input",
			in:          "   \n\t  \n",
			errContains: "empty",
		},
		{
			name:        "prose with no brace at all",
			in:          "I could not complete this task, sorry.",
			errContains: "no '{'",
		},
		{
			name:        "unterminated object",
			in:          `{"claim":"x"`,
			errContains: "none parsed as json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractJSONObject(tt.in)
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("ExtractJSONObject(%q) = %q, want error containing %q",
						tt.in, got, tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("ExtractJSONObject(%q) error = %q, want it to contain %q",
						tt.in, err.Error(), tt.errContains)
				}
				if got != "" {
					t.Fatalf("ExtractJSONObject(%q) returned %q alongside error; want empty string",
						tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractJSONObject(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ExtractJSONObject(%q)\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestExtractJSONObjectNeverReturnsNonJSON is the invariant that the old
// implementation violated: whatever comes back must parse. Without it, a
// caller's json.Unmarshal is handed a C fragment.
func TestExtractJSONObjectNeverReturnsNonJSON(t *testing.T) {
	inputs := []string{
		probeA,
		probeAValidArray,
		probeB,
		probeC,
		"no braces here",
		"{ ok(); }",
		"if (x) { do(); } else { undo(); }",
		"```json\n" + `{"a":1}` + "\n```",
	}
	for _, in := range inputs {
		got, err := ExtractJSONObject(in)
		if err != nil {
			continue
		}
		var sink map[string]any
		if err := UnmarshalJSONObject(got, &sink); err != nil {
			t.Errorf("ExtractJSONObject(%q) returned %q, which does not parse as a JSON object: %v",
				in, got, err)
		}
	}
}

func TestUnmarshalJSONObject(t *testing.T) {
	type payload struct {
		Claim   string `json:"claim"`
		Summary string `json:"summary"`
		Score   int    `json:"score"`
	}

	t.Run("probe B parses into a struct", func(t *testing.T) {
		var got payload
		if err := UnmarshalJSONObject(probeB, &got); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Claim != "x" {
			t.Fatalf("Claim = %q, want %q", got.Claim, "x")
		}
	})

	t.Run("probe A does not yield a payload", func(t *testing.T) {
		var got payload
		err := UnmarshalJSONObject(probeA, &got)
		if err == nil {
			t.Fatalf("UnmarshalJSONObject(probeA) = nil error, got payload %+v; "+
				"a C fragment must never be accepted as the model's answer", got)
		}
	})

	t.Run("raw newlines in string values are repaired", func(t *testing.T) {
		var got payload
		in := "Here you go:\n```json\n{\"summary\":\"line one\nline two\",\"score\":7}\n```"
		if err := UnmarshalJSONObject(in, &got); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Summary != "line one\nline two" {
			t.Fatalf("Summary = %q, want %q", got.Summary, "line one\nline two")
		}
		if got.Score != 7 {
			t.Fatalf("Score = %d, want 7", got.Score)
		}
	})

	t.Run("fenced block with prose on both sides", func(t *testing.T) {
		var got payload
		in := "Sure.\n\n```json\n" + `{"claim":"c","score":2}` + "\n```\n\nHope that helps."
		if err := UnmarshalJSONObject(in, &got); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Claim != "c" || got.Score != 2 {
			t.Fatalf("got %+v, want {Claim:c Score:2}", got)
		}
	})

	t.Run("empty input errors", func(t *testing.T) {
		var got payload
		if err := UnmarshalJSONObject("", &got); err == nil {
			t.Fatal("expected an error for empty input")
		}
	})
}

// FuzzExtractJSONObject pins the invariant that the old implementation
// violated: a successful extraction must return something that actually
// parses as a JSON object. Anything else means a caller is handed prose or
// source code and told it is the model's answer.
//
// In ordinary `go test` runs this exercises the seed corpus only; run it
// with -fuzz to search further.
func FuzzExtractJSONObject(f *testing.F) {
	seeds := []string{
		probeA, probeAValidArray, probeB, probeC,
		`{"a":1}`,
		`{"a":{"b":[1,2,{"c":"}"}]}}`,
		`[{"a":1}]`,
		"```json\n" + `{"a":1}` + "\n```",
		"```\n[1,2]\n```",
		"```json\n```",
		"{\"s\":\"raw\nnewline\"}",
		"prose { not json } more",
		"if (x) { do(); } else { undo(); }",
		"{", "}", "{}", "", "   ",
		`{"a":"\"{"}`,
		`x{"a":1}y{"b":2}z`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ExtractJSONObject(in)
		if err != nil {
			if got != "" {
				t.Fatalf("ExtractJSONObject(%q) returned both %q and error %v", in, got, err)
			}
			return
		}
		if !strings.HasPrefix(got, "{") {
			t.Fatalf("ExtractJSONObject(%q) = %q, which is not an object", in, got)
		}
		var sink map[string]any
		if err := UnmarshalJSONObject(got, &sink); err != nil {
			t.Fatalf("ExtractJSONObject(%q) = %q, which does not parse: %v", in, got, err)
		}
	})
}
