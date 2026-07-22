package preprocessor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// realKnowledgeRoot points at the repo's own shipped knowledge/ directory
// (relative to internal/preprocessor), the same one PR-02's exclusion.yml
// lives under. Tests that don't care about exclusion marking still pass it
// so the normal (found) code path is exercised rather than the
// missing-knowledge-root fallback.
const realKnowledgeRoot = "../../knowledge"

func TestBuildProfileV2DetectsTEEWeb3TrustAndStateSignals(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "Cargo.toml", "[package]\nname = \"fixture\"\n")
	writeRepoFile(t, repo, "enclave/api.edl", "trusted { public void ecall_restore_wallet(); };\nuntrusted { void ocall_write_state(); };\n")
	writeRepoFile(t, repo, "enclave/Enclave.config.xml", "<EnclaveConfiguration/>\n")
	writeRepoFile(t, repo, "enclave/state.rs", `
use sgx_types::sgx_status_t;
fn restore_wallet(sealed_snapshot: &[u8], epoch: u64) {
    verify_attestation_quote();
    check_rollback_counter(epoch);
    signer_release_key();
}
`)

	manifest := artifacts.Manifest{RunID: "run-1", RepoURL: "fixture", LocalPath: repo, Commit: "abc", Focus: "tee"}
	legacy, err := buildProfile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := buildProfileV2(manifest, legacy, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}

	assertSignal(t, profile.TEEPlatforms, "platform:sgx")
	assertSignal(t, profile.CandidateRoles, "role:key-manager-signer")
	assertSignal(t, profile.TrustArtifacts, "artifact:attestation")
	assertSignal(t, profile.BoundarySignals, "boundary:ecall-ocall")
	assertSignal(t, profile.StateSignals, "state:rollback")
	if len(profile.Manifests) != 2 {
		t.Fatalf("manifests = %#v, want EDL and Enclave.config.xml", profile.Manifests)
	}
	if !reflect.DeepEqual(profile.BuildSystems, []string{"cargo"}) {
		t.Fatalf("build systems = %v", profile.BuildSystems)
	}
	if profile.SchemaVersion != "teecheck.project_profile.v2" || profile.Repo.Commit != "abc" {
		t.Fatalf("profile identity not preserved: %#v", profile)
	}
}

func TestBuildProfileV2IsDeterministicAndCapsEvidence(t *testing.T) {
	repo := t.TempDir()
	content := ""
	for i := 0; i < maxEvidencePerSignal+5; i++ {
		content += "sgx quote dcap\n"
	}
	writeRepoFile(t, repo, "src/a.rs", content)
	manifest := artifacts.Manifest{RunID: "run", LocalPath: repo}
	legacy := artifacts.ProjectProfile{Languages: []string{"rust"}}
	first, err := buildProfileV2(manifest, legacy, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildProfileV2(manifest, legacy, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("fingerprint output is not deterministic")
	}
	for _, signal := range first.TEEPlatforms {
		if len(signal.Evidence) > maxEvidencePerSignal {
			t.Fatalf("signal %s has %d evidence records", signal.ID, len(signal.Evidence))
		}
	}
}

func assertSignal(t *testing.T, signals []artifacts.ProfileSignal, id string) {
	t.Helper()
	for _, signal := range signals {
		if signal.ID == id {
			if len(signal.Evidence) == 0 {
				t.Fatalf("signal %s has no evidence", id)
			}
			return
		}
	}
	t.Fatalf("signal %s missing from %#v", id, signals)
}

func assertNoSignal(t *testing.T, signals []artifacts.ProfileSignal, id string) {
	t.Helper()
	for _, signal := range signals {
		if signal.ID == id {
			t.Fatalf("signal %s unexpectedly present: %#v", id, signal)
		}
	}
}

// TestBuildProfileV2DetectsOPTEESignals fixtures the OP-TEE-specific header
// and include-path vocabulary actually seen in the benchmark corpus
// (teecheck-benchmark/datasets/CVE-2019-1010296 et al.), not an invented one
// — see the OP-TEE survey in this PR's implementation notes. platform:optee
// must fire and, per §21, must stay a distinct signal from the generic
// platform:trustzone rather than collapsing into it.
func TestBuildProfileV2DetectsOPTEESignals(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "core/tee/tee_svc_cryp.c", `
#include <kernel/tee_ta_manager.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <tee/tee_svc_cryp.h>

TEE_Result tee_svc_cryp_obj_generate_key(void)
{
	return crypto_aes_encrypt(ctx);
}
`)
	manifest := artifacts.Manifest{RunID: "run-optee", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	assertSignal(t, profile.TEEPlatforms, "platform:optee")
	assertSignal(t, profile.TrustArtifacts, "artifact:crypto-operation")
}

// TestBuildProfileV2DetectsOPTEEPathOnlyLibrary covers OP-TEE's own bignum
// library (lib/libmpa), whose source (as vendored in
// teecheck-benchmark/datasets/CVE-2017-1000413) carries no OP-TEE token in
// its body — only the vendoring path identifies it. This is the path-based
// signal scanPathSignals adds.
func TestBuildProfileV2DetectsOPTEEPathOnlyLibrary(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "lib/libmpa/mpa_expmod.c", `
#include "mpa.h"
void mpa_expmod(void) {}
`)
	manifest := artifacts.Manifest{RunID: "run-optee-path", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	assertSignal(t, profile.TEEPlatforms, "platform:optee")
	for _, ev := range signalEvidence(profile.TEEPlatforms, "platform:optee") {
		if ev.Kind == "path" {
			return
		}
	}
	t.Fatal("expected at least one path-kind evidence for platform:optee")
}

// TestBuildProfileV2DetectsTFMSignals fixtures Trusted Firmware-M's own
// source layout and module-prefixed header names (secure_fw/partitions/,
// tfm_crypto_api.h, tfm_hal_*), as seen in
// teecheck-benchmark/datasets/CVE-2021-40327 and CVE-2021-27562.
func TestBuildProfileV2DetectsTFMSignals(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "secure_fw/partitions/crypto/crypto_key.c", `
#include "tfm_crypto_api.h"
#include "tfm_hal_spm_logdev.h"

psa_status_t tfm_crypto_key_derivation(void)
{
	return PSA_SUCCESS;
}
`)
	manifest := artifacts.Manifest{RunID: "run-tfm", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	assertSignal(t, profile.TEEPlatforms, "platform:tfm")
}

// TestBuildProfileV2OPTEEAndTFMDoNotCrossFire is the precision half of the
// two new platform detectors: OP-TEE's vendored libtomcrypt defines an
// unrelated TFM_LTC_DESC build macro (Toom-Cook fast multiplication, nothing
// to do with Trusted Firmware-M), and TF-M content carries no OP-TEE tokens.
// A bare "tfm_" prefix would have wrongly fired platform:tfm here.
func TestBuildProfileV2OPTEEAndTFMDoNotCrossFire(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "core/lib/libtomcrypt/include/tomcrypt_custom.h", `
#include <tee_api_types.h>
#if defined(TFM_LTC_DESC) && defined(LTC_MECC)
#define TAB_SIZE 256
#endif
`)
	manifest := artifacts.Manifest{RunID: "run-crossfire", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	assertSignal(t, profile.TEEPlatforms, "platform:optee")
	assertNoSignal(t, profile.TEEPlatforms, "platform:tfm")
}

// TestBuildProfileV2MarksVendorScopeInsteadOfDropping is §21's third rule:
// vendor/generated/test scope is marked, not silently excluded. The same
// OP-TEE evidence must still be emitted from a vendor/ path — just annotated.
func TestBuildProfileV2MarksVendorScopeInsteadOfDropping(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "third_party/vendor/optee_os/core/tee/tee_svc.c", "TEE_Result tee_ta_manager_open(void) { return TEE_SUCCESS; }\n")
	writeRepoFile(t, repo, "core/tee/tee_svc.c", "TEE_Result tee_ta_manager_open(void) { return TEE_SUCCESS; }\n")
	manifest := artifacts.Manifest{RunID: "run-vendor", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	var vendorNoted, firstPartyUnnoted bool
	for _, ev := range signalEvidence(profile.TEEPlatforms, "platform:optee") {
		switch ev.File {
		case "third_party/vendor/optee_os/core/tee/tee_svc.c":
			if ev.Note != excludedScopeNote {
				t.Fatalf("vendor-scope evidence not marked: %#v", ev)
			}
			vendorNoted = true
		case "core/tee/tee_svc.c":
			if ev.Note != "" {
				t.Fatalf("first-party evidence unexpectedly marked: %#v", ev)
			}
			firstPartyUnnoted = true
		}
	}
	if !vendorNoted || !firstPartyUnnoted {
		t.Fatalf("expected both vendor and first-party evidence, got %#v", profile.TEEPlatforms)
	}
	found := false
	for _, warning := range profile.CoverageWarnings {
		if strings.Contains(warning, "exclusion.yml") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a coverage warning noting exclusion.yml matches, got %v", profile.CoverageWarnings)
	}
}

// TestBuildProfileV2RolesAreAlwaysCandidate enforces §21's first rule: a role
// keyword may only ever produce a candidate role, never a confirmed one.
func TestBuildProfileV2RolesAreAlwaysCandidate(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "src/validator.rs", "fn run_validator_consensus() {}\n")
	manifest := artifacts.Manifest{RunID: "run-roles", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.CandidateRoles) == 0 {
		t.Fatal("expected at least one candidate role signal")
	}
	for _, signal := range profile.CandidateRoles {
		if signal.Kind != "candidate_role" {
			t.Fatalf("role signal %s has kind %q, want candidate_role", signal.ID, signal.Kind)
		}
		if signal.Confidence != "candidate" {
			t.Fatalf("role signal %s has confidence %q, want candidate", signal.ID, signal.Confidence)
		}
	}
}

// TestBuildProfileV2SignalsAlwaysCarryProvenance enforces §21's fourth rule
// across every signal group: every signal traces to a detector and a file
// location, and accumulatedSignals never emits a signal with zero evidence
// (which would otherwise be indistinguishable from an unfounded claim).
func TestBuildProfileV2SignalsAlwaysCarryProvenance(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "core/tee/tee_svc_cryp.c", "TEE_Result verify_attestation_quote(void) { return TEE_SUCCESS; }\n")
	writeRepoFile(t, repo, "enclave/api.edl", "trusted { public void ecall_run(); };\n")
	manifest := artifacts.Manifest{RunID: "run-provenance", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	groups := [][]artifacts.ProfileSignal{
		profile.TEEPlatforms, profile.CandidateRoles, profile.TrustArtifacts,
		profile.Manifests, profile.BoundarySignals, profile.StateSignals,
	}
	total := 0
	for _, group := range groups {
		for _, signal := range group {
			total++
			if len(signal.Evidence) == 0 {
				t.Fatalf("signal %s has no evidence — a signal with no location must not be emitted", signal.ID)
			}
			for _, ev := range signal.Evidence {
				if ev.File == "" {
					t.Fatalf("signal %s has evidence with no file location: %#v", signal.ID, ev)
				}
				if ev.Tool == "" {
					t.Fatalf("signal %s has evidence with no detector name: %#v", signal.ID, ev)
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("expected at least one signal across all groups")
	}
}

// TestDetectManifestKindPortedFormats covers the manifest_parsers.py formats
// ported into detectManifestKind: EDL (shared by SGX and Open Enclave, hence
// the platform-neutral label) and Gramine's own manifest extension.
func TestDetectManifestKindPortedFormats(t *testing.T) {
	cases := map[string]string{
		"enclave/api.edl":            "EDL trust boundary definition",
		"app.manifest":               "Gramine manifest",
		"app.manifest.template":      "Gramine manifest",
		"enclave/Enclave.config.xml": "SGX enclave configuration",
	}
	for rel, want := range cases {
		if got := detectManifestKind(rel); got != want {
			t.Errorf("detectManifestKind(%q) = %q, want %q", rel, got, want)
		}
	}
}

// TestBuildProfileV2DetectsDockerfileTEEBaseImage ports
// DockerfileParser._TEE_BASE_IMAGE_PATTERNS (tee-audit's
// utils/manifest_parsers.py): a Dockerfile only becomes a manifest signal
// when its FROM image is a known TEE base image, not for every Dockerfile in
// the repo — the benchmark corpus has none to validate against (see this
// PR's report), so this is a synthetic fixture for the parser itself.
func TestBuildProfileV2DetectsDockerfileTEEBaseImage(t *testing.T) {
	repo := t.TempDir()
	writeRepoFile(t, repo, "docker/Dockerfile.oe", "FROM openenclave/openenclave:0.17\nRUN cargo build --bin enclave\n")
	writeRepoFile(t, repo, "docker/Dockerfile", "FROM ubuntu:22.04\nRUN apt-get update\n")
	manifest := artifacts.Manifest{RunID: "run-dockerfile", LocalPath: repo}
	profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	foundTEE, foundPlain := false, false
	for _, m := range profile.Manifests {
		switch m.Scope {
		case "docker/Dockerfile.oe":
			foundTEE = true
		case "docker/Dockerfile":
			foundPlain = true
		}
	}
	if !foundTEE {
		t.Fatalf("expected a manifest signal for the TEE-base-image Dockerfile, got %#v", profile.Manifests)
	}
	if foundPlain {
		t.Fatalf("plain Dockerfile with no TEE base image must not produce a manifest signal, got %#v", profile.Manifests)
	}
}

func signalEvidence(signals []artifacts.ProfileSignal, id string) []artifacts.EvidenceReference {
	for _, signal := range signals {
		if signal.ID == id {
			return signal.Evidence
		}
	}
	return nil
}

func writeRepoFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
