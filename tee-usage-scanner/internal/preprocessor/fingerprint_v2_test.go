package preprocessor

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

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
	profile, err := buildProfileV2(manifest, legacy)
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
	first, err := buildProfileV2(manifest, legacy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildProfileV2(manifest, legacy)
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
