package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contractformal"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type formalVerifyFakeClient struct {
	mu              sync.Mutex
	verifierSawFact bool
	contractID      string
	cSourceHarness  string
	sourceSupported bool
}

func (f *formalVerifyFakeClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	msg := req.Messages[0].Content
	if strings.Contains(req.SystemPrompt, "bounded property harness") {
		spec, _ := json.Marshal(contractformal.TranslationSpec{
			Applicable:   true,
			Reason:       "page stepping range check",
			PropertyKind: "range_iteration",
			Assumptions:  []string{"len > 0", "uaddr + len does not overflow"},
			CSource:      f.cSourceHarness,
		})
		return llm.GenerateResponse{Text: string(spec)}, nil
	}
	f.mu.Lock()
	if strings.Contains(msg, "cpp.contract.formal_property") && strings.Contains(msg, "sandbox_unavailable") && strings.Contains(msg, "model_translation") && strings.Contains(msg, "content_sha256") {
		f.verifierSawFact = true
	}
	f.mu.Unlock()
	position, reason := "unresolved", "The translated harness was not executed and is not source proof."
	if f.sourceSupported {
		position, reason = "supported", "The independently reviewed source supports the proposed violation under its preconditions."
	}
	rev, _ := json.Marshal(artifacts.ContractReview{
		InvariantID:            f.contractID,
		Position:               position,
		Reason:                 reason,
		PreconditionsSatisfied: f.sourceSupported,
		AttackChainComplete:    f.sourceSupported,
		Witness:                []artifacts.ContractSubject{{Path: "tee_mmu.c", Symbol: "tee_mmu_check_access_rights", StartLine: 1, EndLine: 3}},
		CounterEvidence:        []string{},
	})
	return llm.GenerateResponse{Text: string(rev)}, nil
}

// An enabled translation contributes an immutable coverage-gap observation;
// model-generated C and its printed claims cannot become verification results.
func TestBuildContractMemo_FormalTranslationRecordsUnavailableSandbox(t *testing.T) {
	root := t.TempDir()
	run := t.TempDir()
	src := "int tee_mmu_check_access_rights(unsigned long uaddr, unsigned long len) {\n    return 0;\n}\n"
	if err := os.WriteFile(filepath.Join(root, "tee_mmu.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture-formal", "rev1", root)
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "formal-verifier-test",
		RepoURL:       "fixture-formal",
		LocalPath:     root,
		Commit:        "rev1",
		Scope:         scope,
	}
	binding := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: scope}
	draft := artifacts.CaseInvariantV2{
		Origin:           "planner",
		Subjects:         []artifacts.ContractSubject{{Path: "tee_mmu.c", Symbol: "tee_mmu_check_access_rights", StartLine: 1, EndLine: 3}},
		Preconditions:    []string{"len > 0 and uaddr + len does not overflow"},
		RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "every page in [uaddr, uaddr + len) must be checked before access proceeds"},
		SecurityEffect:   "memory access control",
	}
	draft.InvariantID = "case-inv-" + contracts.DefinitionHash(draft)
	bound, diags, err := contracts.Bind(draft, binding)
	if err != nil || len(diags) != 0 {
		t.Fatalf("Bind failed: err=%v diags=%v", err, diags)
	}

	harness := `#include <stdint.h>
#include <stdio.h>
#define PAGE_SIZE 4096ULL
int main(void) {
    uint64_t uaddr = 0x1, len = 0x1000;
    uint64_t end_page = (uaddr + len - 1) / PAGE_SIZE;
    uint64_t last_checked = 0;
    for (uint64_t a = uaddr; a < uaddr + len; a += PAGE_SIZE) {
        last_checked = a / PAGE_SIZE;
    }
    if (last_checked < end_page) {
        printf("COUNTEREXAMPLE: uaddr=0x%llx len=0x%llx missed_page=%llu\n",
               (unsigned long long)uaddr, (unsigned long long)len, (unsigned long long)end_page);
        return 1;
    }
    printf("VERIFIED_UNDER_ASSUMPTIONS\n");
    return 0;
}`
	peerReview := artifacts.ContractReview{
		InvariantID:            bound.InvariantID,
		Position:               "supported",
		Reason:                 "Unaligned stepping skips final page.",
		PreconditionsSatisfied: true,
		AttackChainComplete:    true,
		Witness:                bound.Subjects,
	}
	pack := artifacts.CasePack{CaseID: "case-001", ContractRequired: true, CaseInvariants: []artifacts.CaseInvariantV2{bound}}
	cfg := config.Config{RunDir: run, AgentID: "verifier", EnableFormalVerify: true}

	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprintf("independent-source-supported=%t", supported), func(t *testing.T) {
			client := &formalVerifyFakeClient{contractID: bound.InvariantID, cSourceHarness: harness, sourceSupported: supported}
			memo, err := buildContractMemo(
				context.Background(), cfg, client, manifest, pack,
				artifacts.Hypothesis{ContractReviews: []artifacts.ContractReview{peerReview}},
				artifacts.Challenge{ContractReviews: []artifacts.ContractReview{peerReview}}, nil,
			)
			if err != nil {
				t.Fatalf("buildContractMemo failed: %v", err)
			}
			if !client.verifierSawFact || !strings.Contains(strings.Join(memo.Notes, " "), "No OS-enforced sandbox") {
				t.Fatalf("sandbox gap was not supplied and recorded: %+v", memo.Notes)
			}
			if len(memo.InvariantAssessments) != 1 || memo.InvariantAssessments[0].SourceCorroborated != supported {
				t.Fatalf("translation overrode independent source assessment: %+v", memo.InvariantAssessments)
			}
			if !supported && memo.InvariantAssessments[0].Assessment != "unresolved" {
				t.Fatalf("unexecuted translation became a conclusive assessment: %+v", memo.InvariantAssessments)
			}
		})
	}
}
