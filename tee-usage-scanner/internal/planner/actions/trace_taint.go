package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/taint"
)

const TraceTaintAction = "trace_taint"

type TraceTaintHandler struct {
	Service *taint.Service
	mu      sync.Mutex
}

func (*TraceTaintHandler) Name() string { return TraceTaintAction }

func (h *TraceTaintHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	// One registry shares one handler. Keep cache lookup, quota claim and
	// dispatch together so duplicate concurrent requests spend only once.
	h.mu.Lock()
	defer h.mu.Unlock()
	policy := req.TracePolicy
	if policy == nil || policy.ObservedSymbol == nil || policy.TakeQuery == nil {
		return fail(TraceTaintAction, "trace_taint requires the current planner sample's observation and budget policy")
	}
	if h.Service == nil {
		return fail(TraceTaintAction, "taint service unavailable")
	}
	input := taint.Request{Parameters: taint.Parameters{SourceParamIndex: -1}}
	decoder := json.NewDecoder(bytes.NewReader(req.Args))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return fail(TraceTaintAction, "invalid trace_taint args: "+err.Error())
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fail(TraceTaintAction, "trace_taint accepts exactly one argument object")
	}
	prepared, err := h.Service.Prepare(req.RunDir, req.RepoRoot, req.Repository, req.Commit, input)
	if err != nil {
		return fail(TraceTaintAction, err.Error())
	}
	observed := policy.ObservedSymbol(prepared.Source.SymbolID)
	if !observed && prepared.Request.SinkFunc != "" {
		var facts artifacts.RepoFacts
		if err := runfs.ReadJSON(runfs.RepoFactsPath(req.RunDir), &facts); err != nil {
			return fail(TraceTaintAction, "load observed sink definitions: "+err.Error())
		}
		for _, symbol := range facts.Symbols {
			if symbol.Name == prepared.Request.SinkFunc && policy.ObservedSymbol(symbol.SymbolID) {
				observed = true
				break
			}
		}
	}
	if !observed {
		return fail(TraceTaintAction, "source_func or sink_func must identify a definition observed in this planner sample")
	}
	fact, path, hit := h.Service.Cached(prepared)
	if !hit {
		if err := ctx.Err(); err != nil {
			return fail(TraceTaintAction, err.Error())
		}
		if !policy.TakeQuery() {
			return fail(TraceTaintAction, "taint query budget exhausted; cached queries and source inspection remain available")
		}
		timeout := policy.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		fact, path, err = h.Service.Run(queryCtx, prepared)
		if err != nil {
			return fail(TraceTaintAction, "taint query failed: "+err.Error())
		}
	}
	body := taint.RenderSummary(fact, path, prepared.Request.MaxPaths, prepared.Request.MaxHops)
	// Cache metadata is optional only when the already bounded view has no
	// bytes left. Never make the observation exceed the shared 32 KiB cap.
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &fields) == nil {
		fields["cache_hit"] = json.RawMessage(fmt.Sprint(hit))
		if withCache, e := json.Marshal(fields); e == nil && len(withCache) <= observationlimits.MaxBytes {
			body = string(withCache)
		}
	}
	return ActionResult{Name: TraceTaintAction, OK: true, Output: body}
}
