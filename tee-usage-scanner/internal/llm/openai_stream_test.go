package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func streamTestData(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return "data: " + string(b) + "\n\n"
}

func streamTestDelta(content string) string {
	return streamTestData(map[string]any{"choices": []any{map[string]any{
		"index": 0, "delta": map[string]string{"content": content}, "finish_reason": nil,
	}}, "usage": nil})
}

func streamTestFinish(reason string) string {
	return streamTestData(map[string]any{"choices": []any{map[string]any{
		"index": 0, "delta": map[string]any{}, "finish_reason": reason,
	}}})
}

func streamTestUsage(prompt, completion int) string {
	return streamTestData(map[string]any{"choices": []any{}, "usage": map[string]int{
		"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion,
	}})
}

func streamTestClient(body io.ReadCloser) *OpenAIClient {
	client := NewOpenAIClient(config.Config{
		LLMBaseURL: "https://example.test/v1", LLMAPIKey: "test-key", LLMModel: "test-model",
		LLMStream: true, LLMTimeoutSec: 5,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body}, nil
	})}
	return client
}

func TestOpenAIStreamRequestPreservesWhitespaceAndUsage(t *testing.T) {
	var wire strings.Builder
	wire.WriteString("data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"private reasoning\"}}],\"usage\":null}\n\n")
	for _, part := range []string{`{"a":`, " ", `"two`, " ", `words"}`, "\n"} {
		wire.WriteString(streamTestDelta(part))
	}
	wire.WriteString(streamTestFinish("stop"))
	wire.WriteString(streamTestUsage(11, 27))
	wire.WriteString("data: [DONE]\n\n")
	client := streamTestClient(io.NopCloser(strings.NewReader(wire.String())))
	transport := client.httpClient.Transport
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("Accept = %q", req.Header.Get("Accept"))
		}
		var payload struct {
			Stream        bool `json:"stream"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !payload.Stream || payload.StreamOptions == nil || !payload.StreamOptions.IncludeUsage {
			t.Errorf("missing stream/usage controls: %+v", payload)
		}
		return transport.RoundTrip(req)
	})
	resp, err := client.Generate(context.Background(), GenerateRequest{JSONMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "{\"a\": \"two words\"}\n" {
		t.Fatalf("stream whitespace was lost: %q", resp.Text)
	}
	if resp.Usage != (Usage{PromptTokens: 11, CompletionTokens: 27, TotalTokens: 38}) {
		t.Fatalf("usage trailer was lost: %+v", resp.Usage)
	}
	if resp.Raw != wire.String() || !strings.Contains(resp.RawRequest, `"include_usage":true`) {
		t.Fatalf("wire evidence was lost: raw=%q request=%s", resp.Raw, resp.RawRequest)
	}
}

func TestParseOpenAIStreamFramingAndLargeChunk(t *testing.T) {
	t.Run("comments CRLF and multiline data", func(t *testing.T) {
		raw := ": keepalive\r\nid: 42\r\nevent: message\r\n" +
			"data: {\"choices\":\r\ndata: [{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\r\n\r\n" +
			streamTestFinish("stop") +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n" +
			"data: [DONE]\n\n"
		got, usage, err := parseOpenAIStream(raw)
		if err != nil || got != "hello" || usage.TotalTokens != 7 {
			t.Fatalf("text=%q usage=%+v err=%v", got, usage, err)
		}
	})
	t.Run("chunk over scanner default limit", func(t *testing.T) {
		want := strings.Repeat("x", 100*1024)
		got, _, err := parseOpenAIStream(streamTestDelta(want) + streamTestFinish("stop") + "data: [DONE]\n\n")
		if err != nil || got != want {
			t.Fatalf("large valid chunk: length=%d err=%v", len(got), err)
		}
	})
	t.Run("BOM and CR delimiters split across reads", func(t *testing.T) {
		raw := "\ufeff" + streamTestDelta("字") + streamTestFinish("stop") + "data: [DONE]\n\n"
		raw = strings.ReplaceAll(raw, "\n", "\r")
		got, _, err := parseOpenAIStreamReader(iotest.OneByteReader(strings.NewReader(raw)))
		if err != nil || got != "字" {
			t.Fatalf("byte-split framing text=%q err=%v", got, err)
		}
	})
}

func TestOpenAIStreamPolicyRefusalWithSuccessfulHTTPStatus(t *testing.T) {
	for name, ending := range map[string]string{
		"structured error event": "event: error\ndata: {\"error\":{\"code\":\"content_filter\",\"message\":\"upstream policy refused\"}}\n\n",
		"finish reason":          streamTestFinish("content_filter") + "data: [DONE]\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			raw := streamTestDelta("partial") + streamTestUsage(2, 5) + ending
			resp, err := streamTestClient(io.NopCloser(strings.NewReader(raw))).Generate(context.Background(), GenerateRequest{})
			if err == nil || !IsPolicyRefusal(err) || IsTransient(err) {
				t.Fatalf("policy refusal must not retry: %v", err)
			}
			if resp.Text != "partial" || resp.Usage.TotalTokens != 7 {
				t.Fatalf("refusal lost evidence: %+v", resp)
			}
		})
	}
}

func TestOpenAIStreamErrorEventClassifiesPayloadBeyondRawPreview(t *testing.T) {
	text := strings.Repeat("source evidence ", 40)
	raw := streamTestDelta(text) + "event: error\ndata: {\"code\":\"content_filter\",\"message\":\"upstream refused\"}\n\n"
	resp, err := streamTestClient(io.NopCloser(strings.NewReader(raw))).Generate(context.Background(), GenerateRequest{})
	if err == nil || !IsPolicyRefusal(err) || IsTransient(err) {
		t.Fatalf("error event classification relied on the raw preview: %v", err)
	}
	if resp.Text != text {
		t.Fatal("error event discarded preceding response")
	}
}

func TestOpenAIStreamLengthKeepsReasoningDiagnosticsAndUsage(t *testing.T) {
	for _, text := range []string{"", "partial answer"} {
		t.Run(text, func(t *testing.T) {
			raw := "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n"
			if text != "" {
				raw += streamTestDelta(text)
			}
			raw += streamTestFinish("length") +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":20,\"total_tokens\":29,\"completion_tokens_details\":{\"reasoning_tokens\":18}}}\n\n" +
				"data: [DONE]\n\n"
			client := streamTestClient(io.NopCloser(strings.NewReader(raw)))
			resp, err := client.Generate(context.Background(), GenerateRequest{})
			if err == nil {
				t.Fatal("length-terminated completion must not be treated as a complete response")
			}
			for _, want := range []string{"length", "llm-max-tokens"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("missing %q diagnosis: %v", want, err)
				}
			}
			if text == "" && (!strings.Contains(err.Error(), "reasoning") || !strings.Contains(err.Error(), "18")) {
				t.Errorf("reasoning exhaustion lost detail: %v", err)
			}
			if resp.Text != text || resp.Usage.TotalTokens != 29 || resp.Raw != raw {
				t.Fatalf("error discarded partial response/usage: %+v", resp)
			}
		})
	}
}

func TestOpenAIStreamRejectsMalformedOrTruncatedCompletion(t *testing.T) {
	for name, suffix := range map[string]string{
		"malformed event":  "data: {not valid JSON}\n\n" + streamTestFinish("stop") + "data: [DONE]\n\n",
		"missing DONE":     streamTestFinish("stop"),
		"incomplete event": "data: {\"choices\":[{\"delta\":{\"content\":\"uncommitted\"}}]}",
	} {
		t.Run(name, func(t *testing.T) {
			raw := streamTestDelta("partial") + streamTestUsage(2, 5) + suffix
			resp, err := streamTestClient(io.NopCloser(strings.NewReader(raw))).Generate(context.Background(), GenerateRequest{})
			if err == nil {
				t.Fatal("malformed/truncated stream was accepted")
			}
			if resp.Text != "partial" || resp.Usage.TotalTokens != 7 || resp.Raw == "" {
				t.Fatalf("partial evidence lost: %+v, err=%v", resp, err)
			}
		})
	}
}

func TestOpenAIStreamDONECompletesBeforeHTTPBodyEOF(t *testing.T) {
	for name, separator := range map[string]string{"LF": "\n", "CR": "\r", "CRLF": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			client := streamTestClient(reader)
			type result struct {
				response GenerateResponse
				err      error
			}
			done := make(chan result, 1)
			go func() {
				response, err := client.Generate(context.Background(), GenerateRequest{})
				done <- result{response, err}
			}()
			go func() {
				wire := streamTestDelta("done") + streamTestFinish("stop") + streamTestUsage(2, 3) + "data: [DONE]\n\n"
				_, _ = io.WriteString(writer, strings.ReplaceAll(wire, "\n", separator))
				// Keep writer open; the SSE terminal event must finish Generate.
			}()
			select {
			case got := <-done:
				if got.err != nil || got.response.Text != "done" || got.response.Usage.TotalTokens != 5 {
					t.Fatalf("terminal event: %+v, err=%v", got.response, got.err)
				}
			case <-time.After(2 * time.Second):
				_ = writer.Close()
				<-done
				t.Fatal("Generate waited for EOF after [DONE]")
			}
		})
	}
}

func TestOpenAIStreamReadCancellationPreservesPartialEvidence(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	client := streamTestClient(reader)
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		go func() {
			_, _ = io.WriteString(writer, streamTestDelta("partial"))
			<-req.Context().Done()
			_ = writer.CloseWithError(req.Context().Err())
		}()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err := client.Generate(ctx, GenerateRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request cancellation did not propagate: %v", err)
	}
	if resp.Text != "partial" || !strings.Contains(resp.Raw, "partial") {
		t.Fatalf("read failure discarded partial evidence: %+v", resp)
	}
}
