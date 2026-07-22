package preprocessor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

const (
	maxFingerprintFileBytes = 2 << 20
	maxEvidencePerSignal    = 8
)

type signalDetector struct {
	id      string
	name    string
	kind    string
	pattern *regexp.Regexp
}

var fingerprintDetectors = struct {
	platforms []signalDetector
	roles     []signalDetector
	artifacts []signalDetector
	boundary  []signalDetector
	state     []signalDetector
}{
	platforms: []signalDetector{
		newDetector("platform:sgx", "SGX", "tee_platform", `sgx|mrenclave|mrsigner|report_data|quote3|dcap|isv_svn|edger8r`),
		newDetector("platform:tdx", "TDX", "tee_platform", `tdx|mrtd|tdx[_-]?(quote|attest|report)`),
		newDetector("platform:nitro", "AWS Nitro Enclaves", "tee_platform", `nitro.?enclave|attestation.?document|aws.?enclave`),
		newDetector("platform:sev-snp", "AMD SEV-SNP", "tee_platform", `sev.?snp|guest.?report|launch.?digest|snp.?cert`),
		newDetector("platform:trustzone", "Arm TrustZone / OP-TEE", "tee_platform", `trustzone|op-tee|optee|secure.?world|normal.?world|smc.?call`),
		newDetector("platform:open-enclave", "Open Enclave", "tee_platform", `open.?enclave|oe_enclave|oe_result_t`),
		newDetector("platform:gramine", "Gramine", "tee_platform", `gramine|sgx\.manifest|protected_files`),
	},
	roles: []signalDetector{
		newDetector("role:validator-consensus", "Validator or consensus", "candidate_role", `validator|consensus|quorum|tendermint|cometbft|paratime`),
		newDetector("role:key-manager-signer", "Key manager or signer", "candidate_role", `key.?manager|signer|signing|release.?key|threshold.?sign|multisig|kms`),
		newDetector("role:oracle-bridge-worker", "Oracle, bridge, relayer, or off-chain worker", "candidate_role", `oracle|bridge|relayer|worker|coprocessor|offchain|cross.?chain|light.?client`),
		newDetector("role:defi", "DeFi or AMM", "candidate_role", `liquidity.?pool|automated.?market|yield.?vault|staking.?contract|\bdefi\b|\bdex\b`),
		newDetector("role:governance", "Governance or DAO", "candidate_role", `governance|\bdao\b|proposal|vote.?power|committee.?vote`),
	},
	artifacts: []signalDetector{
		newDetector("artifact:attestation", "Attestation artifacts", "trust_artifact", `attest|quote|verification.?report|collateral|tee.?evidence`),
		newDetector("artifact:identity", "TEE identity artifacts", "trust_artifact", `measurement|mrenclave|mrsigner|\bpcr[0-9]*\b|report_data|mr_signer|mr_enclave`),
		newDetector("artifact:cryptographic-key", "Cryptographic keys and certificates", "trust_artifact", `public.?key|private.?key|certificate.?chain|x509|key.?deriv|key.?gen`),
	},
	boundary: []signalDetector{
		newDetector("boundary:ecall-ocall", "ECALL / OCALL boundary", "boundary", `\becall(?:\b|_)|\bocall(?:\b|_)|sgx_ecall|sgx_ocall`),
		newDetector("boundary:edl", "EDL boundary definition", "boundary", `\.edl\b|from\s+"[^"]+"\s+import|trusted\s*\{|untrusted\s*\{`),
		newDetector("boundary:rpc", "RPC or message boundary", "boundary", `json.?rpc|grpc|protobuf|\brpc\b|vsock|mailbox|ioctl`),
		newDetector("boundary:ffi", "FFI boundary", "boundary", `extern\s+"C"|cgo|\bffi\b|bindgen`),
	},
	state: []signalDetector{
		newDetector("state:persistence", "Persistent or restorable state", "state", `seal|unseal|restore|recovery|snapshot|journal|persist`),
		newDetector("state:freshness", "Freshness or continuity value", "state", `epoch|counter|sequence|version|block.?height|nonce|monotonic`),
		newDetector("state:rollback", "Rollback or replay handling", "state", `rollback|anti.?rollback|replay|downgrade|stale.?state`),
	},
}

func newDetector(id, name, kind, expression string) signalDetector {
	return signalDetector{id: id, name: name, kind: kind, pattern: regexp.MustCompile(`(?i)` + expression)}
}

type signalAccumulator struct {
	detector signalDetector
	evidence []artifacts.EvidenceReference
}

func buildProfileV2(manifest artifacts.Manifest, legacy artifacts.ProjectProfile) (artifacts.ProjectProfileV2, error) {
	groups := [][]signalDetector{
		fingerprintDetectors.platforms,
		fingerprintDetectors.roles,
		fingerprintDetectors.artifacts,
		fingerprintDetectors.boundary,
		fingerprintDetectors.state,
	}
	accumulators := make([]map[string]*signalAccumulator, len(groups))
	for i, detectors := range groups {
		accumulators[i] = make(map[string]*signalAccumulator, len(detectors))
		for _, detector := range detectors {
			d := detector
			accumulators[i][d.id] = &signalAccumulator{detector: d}
		}
	}

	var manifests []artifacts.ProfileSignal
	buildSystems := map[string]bool{}
	var skippedLarge, skippedUnreadable int
	err := filepath.Walk(manifest.LocalPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			skippedUnreadable++
			return nil
		}
		rel, err := filepath.Rel(manifest.LocalPath, path)
		if err != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if skipPath(rel, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if system := detectBuildSystem(rel); system != "" {
			buildSystems[system] = true
		}
		if kind := detectManifestKind(rel); kind != "" {
			manifests = append(manifests, artifacts.ProfileSignal{
				ID:       "manifest:" + rel,
				Kind:     "manifest",
				Name:     kind,
				Status:   "observed",
				Detector: "fingerprint-v2:path",
				Scope:    rel,
				Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: rel}},
			})
		}
		if info.Size() > maxFingerprintFileBytes {
			skippedLarge++
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			skippedUnreadable++
			return nil
		}
		if strings.IndexByte(string(data), 0) >= 0 {
			return nil
		}
		scanFileSignals(rel, string(data), accumulators)
		return nil
	})
	if err != nil {
		return artifacts.ProjectProfileV2{}, fmt.Errorf("walk repo: %w", err)
	}

	sort.Slice(manifests, func(i, j int) bool { return manifests[i].ID < manifests[j].ID })
	warnings := []string{
		"signals are deterministic candidates; architecture agents must ground roles and trust boundaries before using them as facts",
	}
	if skippedLarge > 0 {
		warnings = append(warnings, fmt.Sprintf("content scan skipped %d files larger than %d bytes", skippedLarge, maxFingerprintFileBytes))
	}
	if skippedUnreadable > 0 {
		warnings = append(warnings, fmt.Sprintf("content scan could not read %d paths", skippedUnreadable))
	}
	return artifacts.ProjectProfileV2{
		SchemaVersion:    "teecheck.project_profile.v2",
		RunID:            manifest.RunID,
		Repo:             artifacts.RepoRef{URL: manifest.RepoURL, Commit: manifest.Commit, Focus: manifest.Focus},
		Languages:        append([]string(nil), legacy.Languages...),
		BuildSystems:     sortedSet(buildSystems),
		TEEPlatforms:     accumulatedSignals(accumulators[0]),
		CandidateRoles:   accumulatedSignals(accumulators[1]),
		TrustArtifacts:   accumulatedSignals(accumulators[2]),
		Manifests:        manifests,
		BoundarySignals:  accumulatedSignals(accumulators[3]),
		StateSignals:     accumulatedSignals(accumulators[4]),
		SensitivePaths:   append([]string(nil), legacy.SensitivePaths...),
		TopLevelDirs:     append([]string(nil), legacy.TopLevelDirs...),
		FrameworkHints:   append([]string(nil), legacy.FrameworkHints...),
		CoverageWarnings: warnings,
	}, nil
}

func scanFileSignals(rel, content string, groups []map[string]*signalAccumulator) {
	lines := strings.Split(content, "\n")
	for lineIndex, line := range lines {
		for _, group := range groups {
			for _, accumulator := range group {
				if len(accumulator.evidence) >= maxEvidencePerSignal || !accumulator.detector.pattern.MatchString(line) {
					continue
				}
				accumulator.evidence = append(accumulator.evidence, artifacts.EvidenceReference{
					Kind:      "code_or_config",
					File:      rel,
					StartLine: lineIndex + 1,
					EndLine:   lineIndex + 1,
					Tool:      "fingerprint-v2",
				})
			}
		}
	}
}

func accumulatedSignals(accumulators map[string]*signalAccumulator) []artifacts.ProfileSignal {
	var signals []artifacts.ProfileSignal
	for _, accumulator := range accumulators {
		if len(accumulator.evidence) == 0 {
			continue
		}
		signals = append(signals, artifacts.ProfileSignal{
			ID:         accumulator.detector.id,
			Kind:       accumulator.detector.kind,
			Name:       accumulator.detector.name,
			Status:     "observed",
			Detector:   "fingerprint-v2:content",
			Scope:      "repository",
			Confidence: "candidate",
			Evidence:   accumulator.evidence,
		})
	}
	sort.Slice(signals, func(i, j int) bool { return signals[i].ID < signals[j].ID })
	return signals
}

func detectBuildSystem(rel string) string {
	base := strings.ToLower(filepath.Base(rel))
	switch base {
	case "cargo.toml":
		return "cargo"
	case "go.mod":
		return "go-modules"
	case "package.json":
		return "npm"
	case "pyproject.toml", "setup.py":
		return "python"
	case "cmakelists.txt":
		return "cmake"
	case "makefile", "gnumakefile":
		return "make"
	case "build.gradle", "build.gradle.kts":
		return "gradle"
	}
	return ""
}

func detectManifestKind(rel string) string {
	lower := strings.ToLower(rel)
	base := filepath.Base(lower)
	switch {
	case strings.HasSuffix(lower, ".edl"):
		return "SGX EDL"
	case strings.HasSuffix(lower, ".manifest"), strings.HasSuffix(lower, ".manifest.template"):
		return "TEE manifest"
	case base == "enclave.config.xml":
		return "SGX enclave configuration"
	case strings.Contains(base, "nitro") && (strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")):
		return "Nitro enclave configuration"
	case strings.Contains(base, "enclave") && (base == "dockerfile.enclave" || strings.HasSuffix(base, ".toml")):
		return "Enclave build manifest"
	}
	return ""
}
