package preprocessor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// benchmarkDatasetsDir is teecheck-benchmark/datasets, a sibling of the Go
// module root. This test proves the platform/artifact/manifest signals
// required by §21's acceptance criteria against the real, source-backed
// benchmark corpus — not invented fixtures — and measures the platform
// detectors' precision (false-fire rate across non-matching platforms and
// the two non-TEE control datasets) the same way the PR report does.
const benchmarkDatasetsDir = "../../../teecheck-benchmark/datasets"

// benchmarkCase is the subset of case.yaml (which is JSON despite its
// extension — see teecheck-benchmark/datasets/*/case.yaml) this test reads.
type benchmarkCase struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
}

func TestBuildProfileV2AgainstBenchmarkCorpus(t *testing.T) {
	entries, err := os.ReadDir(benchmarkDatasetsDir)
	if err != nil {
		t.Skipf("benchmark datasets not present at %s: %v", benchmarkDatasetsDir, err)
	}

	type observation struct {
		id            string
		platform      string
		hits          map[string]bool
		manifestCount int
		artifactCount int
	}
	var observations []observation

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dsDir := filepath.Join(benchmarkDatasetsDir, entry.Name())
		caseData, err := os.ReadFile(filepath.Join(dsDir, "case.yaml"))
		if err != nil {
			continue
		}
		var bc benchmarkCase
		if err := json.Unmarshal(caseData, &bc); err != nil {
			t.Fatalf("%s: parse case.yaml: %v", entry.Name(), err)
		}

		hits := map[string]bool{}
		obs := observation{id: bc.ID, platform: bc.Platform, hits: hits}
		for _, tree := range []string{"vulnerable", "fixed"} {
			root := filepath.Join(dsDir, tree)
			if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
				continue
			}
			manifest := artifacts.Manifest{RunID: "bench-" + entry.Name() + "-" + tree, LocalPath: root}
			profile, err := buildProfileV2(manifest, artifacts.ProjectProfile{}, realKnowledgeRoot)
			if err != nil {
				t.Fatalf("%s/%s: buildProfileV2: %v", entry.Name(), tree, err)
			}
			for _, s := range profile.TEEPlatforms {
				hits[s.ID] = true
			}
			obs.manifestCount += len(profile.Manifests)
			obs.artifactCount += len(profile.TrustArtifacts)
		}
		observations = append(observations, obs)
	}

	if len(observations) == 0 {
		t.Fatal("no benchmark datasets with a case.yaml were found")
	}

	// §21 acceptance: platform, artifact and manifest signals must be
	// produced on the OP-TEE / TF-M / Open Enclave fixtures.
	byPlatform := map[string][]observation{}
	for _, o := range observations {
		byPlatform[o.platform] = append(byPlatform[o.platform], o)
	}

	assertRecall := func(platform, signalID string, minHits int) {
		t.Helper()
		group := byPlatform[platform]
		hitCount := 0
		var missed []string
		for _, o := range group {
			if o.hits[signalID] {
				hitCount++
			} else {
				missed = append(missed, o.id)
			}
		}
		t.Logf("%s: %s fired on %d/%d datasets (missed: %v)", signalID, platform, hitCount, len(group), missed)
		if hitCount < minHits {
			t.Errorf("%s fired on only %d/%d %s datasets, want >= %d", signalID, hitCount, len(group), platform, minHits)
		}
	}

	// Thresholds reflect the corpus's own partial-checkout limitation (some
	// datasets ship only one or two vendored, TEE-token-free files — see
	// this PR's report) rather than 100%.
	assertRecall("OP-TEE", "platform:optee", 24)
	assertRecall("Trusted Firmware-M", "platform:tfm", 8)
	assertRecall("Open Enclave", "platform:open-enclave", 4)
	assertRecall("Intel SGX", "platform:sgx", 1)
	assertRecall("AMD SEV-SNP", "platform:sev-snp", 1)

	// §21 also requires artifact and manifest signals on these fixtures, not
	// just platform signals. artifact:crypto-operation (and the older
	// artifact:cryptographic-key) make trust-artifact evidence near-universal
	// across the crypto-heavy OP-TEE/TF-M CVEs; manifest evidence is rarer in
	// this corpus (most datasets are single/few-file partial checkouts with
	// no .edl or enclave-config file included — see this PR's report) so
	// only a repo-wide minimum is asserted, not a per-dataset one.
	for _, platform := range []string{"OP-TEE", "Trusted Firmware-M", "Open Enclave"} {
		artifactDatasets := 0
		manifestDatasets := 0
		for _, o := range byPlatform[platform] {
			if o.artifactCount > 0 {
				artifactDatasets++
			}
			if o.manifestCount > 0 {
				manifestDatasets++
			}
		}
		t.Logf("%s: %d/%d datasets produced >=1 trust-artifact signal, %d/%d produced >=1 manifest signal",
			platform, artifactDatasets, len(byPlatform[platform]), manifestDatasets, len(byPlatform[platform]))
		if artifactDatasets == 0 {
			t.Errorf("%s: no dataset produced any trust-artifact signal", platform)
		}
	}
	// Not a per-dataset claim across the whole OE group — just proves the
	// EDL parser fires on the one dataset in this corpus that actually ships
	// an .edl file (CVE-2020-15224).
	openEnclaveManifests := 0
	for _, o := range byPlatform["Open Enclave"] {
		openEnclaveManifests += o.manifestCount
	}
	if openEnclaveManifests == 0 {
		t.Error("Open Enclave: no dataset produced any manifest signal (expected the .edl fixture to fire)")
	}

	// Precision: platform:optee and platform:tfm must never fire on a
	// dataset labelled as a different platform — a detector that also fires
	// on everything else is worse than no detector (per this PR's brief).
	//
	// CVE-2020-15107 (Open Enclave) is a verified exception, not a detector
	// defect: enclave/core/CMakeLists.txt in that dataset genuinely lists an
	// "optee/*.c" source set and a comment reading "OP-TEE header
	// 3rdparty/optee/libutee/liboeutee/user_ta_header.h" — Open Enclave
	// really does support OP-TEE as an alternate backend, and case.yaml's
	// single "platform" field just doesn't capture that. The evidence is
	// real, traceable (CMakeLists.txt:136 etc.), and correctly a candidate
	// signal — grounding whether OP-TEE is actually in play for this CVE is
	// the Architecture Agent's job, not the fingerprint's.
	knownMultiPlatformExceptions := map[string]bool{"CVE-2020-15107": true}

	falsePositives := map[string][]string{}
	for _, o := range observations {
		if knownMultiPlatformExceptions[o.id] {
			continue
		}
		if o.hits["platform:optee"] && o.platform != "OP-TEE" {
			falsePositives["platform:optee"] = append(falsePositives["platform:optee"], o.id+" ("+o.platform+")")
		}
		if o.hits["platform:tfm"] && o.platform != "Trusted Firmware-M" {
			falsePositives["platform:tfm"] = append(falsePositives["platform:tfm"], o.id+" ("+o.platform+")")
		}
	}
	for id, offenders := range falsePositives {
		sort.Strings(offenders)
		t.Errorf("%s false-fired on non-matching datasets: %v", id, offenders)
	}

	// The two unlabelled control datasets (Rust regex / RustCrypto AEADs)
	// are not TEE projects at all; no platform signal should fire on them.
	for _, o := range byPlatform[""] {
		var fired []string
		for id := range o.hits {
			fired = append(fired, id)
		}
		if len(fired) > 0 {
			sort.Strings(fired)
			t.Errorf("control dataset %s unexpectedly produced platform signals: %v", o.id, fired)
		}
	}
}
