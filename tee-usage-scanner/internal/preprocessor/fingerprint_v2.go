package preprocessor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
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
		// trustzone is the generic Arm TrustZone signal (secure/normal world,
		// SMC calls). It deliberately no longer matches "op-tee"/"optee" —
		// OP-TEE is one specific TrustZone OS among several (Trustonic
		// Kinibi, Huawei iTrustee, ...), and collapsing the two into one
		// signal would hide which TEE OS is actually present. See
		// platform:optee below for the OP-TEE-specific signal; both fire
		// together on an OP-TEE repo, which is correct — it IS TrustZone.
		newDetector("platform:trustzone", "Arm TrustZone", "tee_platform", `trustzone|secure.?world|normal.?world|smc.?call`),
		newDetector("platform:open-enclave", "Open Enclave", "tee_platform", `open.?enclave|oe_enclave|oe_result_t`),
		newDetector("platform:gramine", "Gramine", "tee_platform", `gramine|sgx\.manifest|protected_files`),
		// platform:optee — OP-TEE OS is the largest single platform in the
		// benchmark corpus (27 of 44 datasets) and had no dedicated detector
		// before this PR; only the generic "trustzone" signal caught it, and
		// only when secure/normal-world wording happened to appear.
		// tee_api_types.h, tee_ta_manager, utee_defines, tee_svc_cryp and
		// libutee are OP-TEE's own internal header/module names (not shared
		// with any other TrustZone OS); optee_msg is the normal-world <->
		// OP-TEE message ABI; libmpa is OP-TEE's own bignum library (as
		// opposed to the vendored, platform-neutral libtomcrypt/libmbedtls
		// it also ships). TEE_Result is the GlobalPlatform TEE Client API
		// result type — also used by other GP-compliant TEE OSes, so on its
		// own it is the weakest term here, but across all 44 benchmark
		// datasets (including the non-OP-TEE TrustZone/TF-M/SGX/SEV-SNP/
		// control cases) it never produced a false positive, so it stays.
		newDetector("platform:optee", "OP-TEE OS", "tee_platform", `\boptee\b|op-tee|tee_ta_manager|tee_svc_cryp|utee_defines|tee_api_types|tee_internal_api|libutee|optee_msg|cfg_tee_core|libmpa|\btee_result\b`),
		// platform:tfm — Trusted Firmware-M is the second-largest platform in
		// the corpus (9 of 44) and also had no detector. secure_fw/partitions
		// and secure_fw/spm are TF-M's own top-level source layout; the
		// tfm_* alternatives are restricted to TF-M's actual module prefixes
		// (core, spm, hal, svc, arch, psa, plat, crypto_api, secure_api,
		// multi_core, mbedcrypto, fwu, rpc) rather than a bare "tfm_" —
		// libtomcrypt (vendored into OP-TEE, present in this same corpus)
		// defines an unrelated "TFM_LTC_DESC" build macro (Toom-Cook fast
		// multiplication, nothing to do with Trusted Firmware-M) that a bare
		// tfm_ prefix would have wrongly matched.
		newDetector("platform:tfm", "Trusted Firmware-M", "tee_platform", `\btf-m\b|trusted[- ]firmware-m\b|secure_fw/partitions|secure_fw/spm|tfm_hal|tfm_spm|tfm_core|tfm_svc|tfm_secure_api|tfm_crypto_api|tfm_arch|tfm_psa|tfm_plat|tfm_multi_core|tfm_mbedcrypto|tfm_fwu|tfm_rpc`),
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
		// artifact:crypto-operation — ported from tee-audit's
		// TRUST_ARTIFACT_PATTERNS["crypto_operations"] (patterns/tee_signals.py).
		// tee-audit had no equivalent to artifact:cryptographic-key (public/
		// private key material, certs), and TEECheck had no equivalent to
		// tee-audit's crypto_operations (algorithm/operation names). Kept
		// both rather than merging into one overbroad pattern: key material
		// and "code performs a crypto operation" are different candidate
		// facts for an Architecture Agent to ground separately. This is the
		// single highest-recall addition for the C corpus — nearly every
		// OP-TEE/TF-M CVE here is in a crypto implementation (tee_svc_cryp.c,
		// libtomcrypt, mbedtls, hpre_rsa.c, aes-gcm.c, ...).
		newDetector("artifact:crypto-operation", "Cryptographic operation", "trust_artifact", `encrypt|decrypt|\bcipher\b|\baes\b|\brsa\b|\becdsa\b|ed25519|secp256k1|\bhmac\b|\bkdf\b|\bsign\b|\bverify\b|key.?gen|\btls\b|\bssl\b`),
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

// buildProfileV2 walks the repository once, evaluating every detector group
// against each file's content (and, for the platforms group, its path) and
// the manifest/build-system classifiers against each path. knowledgeRoot
// locates the PR-02-migrated exclusion.yml (knowledge/twe/definitions/) so
// vendor/generated/test evidence can be marked per §21 — see loadFingerprintExclusionRules.
func buildProfileV2(manifest artifacts.Manifest, legacy artifacts.ProjectProfile, knowledgeRoot string) (artifacts.ProjectProfileV2, error) {
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

	exclusionRules, exclusionWarning, err := loadFingerprintExclusionRules(knowledgeRoot)
	if err != nil {
		return artifacts.ProjectProfileV2{}, err
	}

	var manifests []artifacts.ProfileSignal
	buildSystems := map[string]bool{}
	var skippedLarge, skippedUnreadable, excludedScopeFiles int
	err = filepath.Walk(manifest.LocalPath, func(path string, info os.FileInfo, walkErr error) error {
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
		excludedScope := exclusionRules.Match(rel)
		if excludedScope {
			excludedScopeFiles++
		}
		if system := detectBuildSystem(rel); system != "" {
			buildSystems[system] = true
		}
		kind := detectManifestKind(rel)
		if kind != "" {
			manifests = append(manifests, artifacts.ProfileSignal{
				ID:       "manifest:" + rel,
				Kind:     "manifest",
				Name:     kind,
				Status:   "observed",
				Detector: "fingerprint-v2:path",
				Scope:    rel,
				Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: rel, Tool: "fingerprint-v2:path", Note: scopeNote(excludedScope)}},
			})
		}
		scanPathSignals(rel, accumulators[0], excludedScope)
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
		// Dockerfile TEE base images can only be told apart by content (the
		// filename alone is generic), so this classifier runs here instead
		// of in detectManifestKind. Skipped when the path already produced a
		// manifest hit (e.g. Dockerfile.enclave) to avoid a duplicate entry.
		if kind == "" && isDockerfileName(rel) {
			if line, ok := detectDockerfileTEEBaseImage(string(data)); ok {
				manifests = append(manifests, artifacts.ProfileSignal{
					ID:       "manifest:" + rel,
					Kind:     "manifest",
					Name:     "Container build manifest (TEE base image)",
					Status:   "observed",
					Detector: "fingerprint-v2:content",
					Scope:    rel,
					Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: rel, StartLine: line, EndLine: line, Tool: "fingerprint-v2:content", Note: scopeNote(excludedScope)}},
				})
			}
		}
		scanFileSignals(rel, string(data), accumulators, excludedScope)
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
	if exclusionWarning != "" {
		warnings = append(warnings, exclusionWarning)
	} else if excludedScopeFiles > 0 {
		warnings = append(warnings, fmt.Sprintf("%d files matched knowledge/twe/definitions/exclusion.yml (vendor/generated/test); their evidence is marked, not dropped", excludedScopeFiles))
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

func scanFileSignals(rel, content string, groups []map[string]*signalAccumulator, excludedScope bool) {
	note := scopeNote(excludedScope)
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
					Note:      note,
				})
			}
		}
	}
}

// scanPathSignals matches the platforms group against the repo-relative path
// itself, not just file content. This catches tree-layout evidence that
// never appears as a literal token inside a file's body — e.g. OP-TEE's own
// bignum library at lib/libmpa/*.c has no "optee" token in its source, only
// in its vendoring path. tee-audit's fingerprint.py played a similar role
// with a separate CRITICAL_PATH_DIRS list fed into its own directory scan;
// this reuses the existing per-detector regex library against path text
// instead of introducing a second pattern list, so the two names cannot
// drift out of sync. Deliberately restricted to platforms: it is the
// highest-value, lowest-ambiguity signal family, and applying path matching
// to the broader (and largely Web3-flavored) role/boundary/state regexes
// has no benchmark evidence behind it and risks directory-name noise.
func scanPathSignals(rel string, accumulators map[string]*signalAccumulator, excludedScope bool) {
	note := scopeNote(excludedScope)
	for _, accumulator := range accumulators {
		if len(accumulator.evidence) >= maxEvidencePerSignal || !accumulator.detector.pattern.MatchString(rel) {
			continue
		}
		accumulator.evidence = append(accumulator.evidence, artifacts.EvidenceReference{
			Kind: "path",
			File: rel,
			Tool: "fingerprint-v2:path",
			Note: note,
		})
	}
}

// excludedScopeNote is the marker recorded on evidence whose file matched
// knowledge/twe/definitions/exclusion.yml. Per §21, absence of first-party
// origin is marked, never dropped — an OP-TEE SDK vendored under
// third_party/ still tells an Architecture Agent the platform is OP-TEE; it
// just should not be weighted as first-party code.
const excludedScopeNote = "vendor/generated/test scope (knowledge/twe/definitions/exclusion.yml)"

func scopeNote(excludedScope bool) string {
	if excludedScope {
		return excludedScopeNote
	}
	return ""
}

// loadFingerprintExclusionRules loads knowledge/twe/definitions/exclusion.yml
// under knowledgeRoot. Missing is tolerated (older/custom knowledge roots
// keep working, same as compileTWEKnowledge's playbook lookup) and reported
// as a coverage warning rather than failing the whole profile build; a
// present-but-malformed file is fatal, matching LoadExclusionRules' own
// fail-loud validation.
func loadFingerprintExclusionRules(knowledgeRoot string) (twe.ExclusionRules, string, error) {
	path := filepath.Join(knowledgeRoot, "twe", "definitions", "exclusion.yml")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return twe.ExclusionRules{}, fmt.Sprintf("exclusion rules not found at %s; vendor/generated/test scope was not marked", path), nil
		}
		return twe.ExclusionRules{}, "", fmt.Errorf("stat exclusion rules: %w", err)
	}
	rules, err := twe.LoadExclusionRules(path)
	if err != nil {
		return twe.ExclusionRules{}, "", err
	}
	return rules, "", nil
}

// isDockerfileName reports whether base is a Dockerfile, including tagged
// variants like Dockerfile.sgx — but not dockerfile.enclave, which
// detectManifestKind already classifies from the path alone.
func isDockerfileName(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	return (base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")) && base != "dockerfile.enclave"
}

// dockerfileTEEBaseImagePattern is ported from tee-audit's
// DockerfileParser._TEE_BASE_IMAGE_PATTERNS (utils/manifest_parsers.py).
// teaclave's own image name is "apache/incubator-teaclave"; matching just
// "incubator-teaclave" is enough and avoids anchoring to the "apache/"
// registry prefix, which is incidental.
var dockerfileTEEBaseImagePattern = regexp.MustCompile(`(?i)^\s*FROM\s+\S*(openenclave|aws-nitro|nitro-enclaves|gramine|occlum|incubator-teaclave)\S*`)

func detectDockerfileTEEBaseImage(content string) (line int, ok bool) {
	for i, l := range strings.Split(content, "\n") {
		if dockerfileTEEBaseImagePattern.MatchString(l) {
			return i + 1, true
		}
	}
	return 0, false
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
	case "sub.mk", "conf.mk":
		// OP-TEE build fragments. Deliberately a build system rather than a
		// manifest: sub.mk lists which sources compile into a TA or into
		// core, which is build wiring, not a declaration of the trust
		// boundary the way user_ta_header_defines.h is.
		return "optee-make"
	}
	return ""
}

// detectManifestKind classifies a manifest purely from its path — no content
// read is needed for these formats, unlike detectDockerfileTEEBaseImage.
// Ported from tee-audit's utils/manifest_parsers.py parser set (Gramine, EDL,
// Dockerfile) plus TEECheck's pre-existing enclave-config/Nitro cases; kept
// as filename classification rather than porting manifest_parsers.py's
// deeper per-format entry-point extraction (trusted{}/untrusted{} function
// names, Gramine trusted_files lists, ...) — that is Architecture Model
// territory (§3.4/§22), not a Fingerprint-layer candidate signal.
func detectManifestKind(rel string) string {
	lower := strings.ToLower(rel)
	base := filepath.Base(lower)
	switch {
	case strings.HasSuffix(lower, ".edl"):
		// EDL is Intel SGX's IDL format, also reused by Open Enclave (see
		// CVE-2020-15224's include/openenclave/edl/socket.edl in the
		// benchmark) — not SGX-exclusive, so the label says trust boundary
		// rather than naming one platform.
		return "EDL trust boundary definition"
	case strings.HasSuffix(lower, ".manifest"), strings.HasSuffix(lower, ".manifest.template"):
		return "Gramine manifest"
	case base == "enclave.config.xml":
		return "SGX enclave configuration"
	case strings.Contains(base, "nitro") && (strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")):
		return "Nitro enclave configuration"
	case strings.Contains(base, "enclave") && (base == "dockerfile.enclave" || strings.HasSuffix(base, ".toml")):
		return "Enclave build manifest"

	// The cases above are the SGX/Gramine/Nitro formats, which is everything
	// tee-audit's manifest_parsers.py knew about — it has no notion of OP-TEE
	// or TF-M. Those two platforms are 36 of the benchmark's 44 datasets, so
	// their declaration formats belong here too. This corpus ships partial
	// checkouts containing none of them, so these arms are unexercised by it;
	// they matter when fingerprinting a whole OP-TEE or TF-M tree, which is
	// what PR-04's Architecture Agent reads.
	case base == "user_ta_header_defines.h":
		// OP-TEE's TA manifest in all but name: declares the TA UUID, flags,
		// stack and heap sizes and properties. The closest analogue OP-TEE
		// has to an SGX enclave configuration.
		return "OP-TEE TA manifest"
	case base == "manifest.yaml", base == "tfm_manifest_list.yaml",
		strings.HasSuffix(base, "_manifest.yaml"):
		// TF-M secure-partition manifests, declaring the partition's
		// services, IRQs and priorities across the trust boundary.
		return "TF-M secure partition manifest"
	}
	return ""
}
