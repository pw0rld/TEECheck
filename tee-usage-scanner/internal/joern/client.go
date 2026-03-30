package joern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/evidence"
)

const (
	defaultEndpoint = "http://127.0.0.1:8080/query-sync"
	defaultTimeout  = 2 * time.Minute
)

var (
	ansiPattern        = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	finalStringPattern = regexp.MustCompile(`(?m):\s*String\s*=\s*("(?:\\.|[^"\\])*")`)
)

type Client struct {
	Binary     string
	Endpoint   string
	SSHTarget  string
	RemoteRoot string
}

type queryRequest struct {
	Query string `json:"query"`
}

type queryResponse struct {
	Success bool   `json:"success"`
	Stdout  string `json:"stdout"`
	UUID    string `json:"uuid"`
}

type evidenceQuery struct {
	Name     string
	Template string
}

func (c Client) ExportEvidence(sourcePath string) ([]evidence.Package, error) {
	if strings.TrimSpace(sourcePath) == "" {
		return nil, fmt.Errorf("source path is empty")
	}

	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("resolve source path: %w", err)
	}

	querySource := absSource
	if strings.TrimSpace(c.SSHTarget) != "" {
		querySource = c.remoteSourcePath(absSource)
	}

	var packages []evidence.Package
	for _, query := range evidenceQueries {
		packs, err := c.exportEvidenceWithQuery(querySource, query)
		if err != nil {
			return nil, fmt.Errorf("%s extractor: %w", query.Name, err)
		}
		packages = append(packages, packs...)
	}

	if err := normalizePackages(absSource, packages); err != nil {
		return nil, err
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Candidate.ID < packages[j].Candidate.ID
	})
	return packages, nil
}

func (c Client) exportEvidenceWithQuery(querySource string, queryDef evidenceQuery) ([]evidence.Package, error) {
	query := fmt.Sprintf(queryDef.Template, strconv.Quote(querySource))
	resp, err := c.runQuery(query)
	if err != nil {
		return nil, err
	}

	jsonString, err := extractJSONString(resp.Stdout)
	if err != nil {
		return nil, err
	}

	var packages []evidence.Package
	if err := json.Unmarshal([]byte(jsonString), &packages); err != nil {
		return nil, fmt.Errorf("parse Joern evidence payload: %w", err)
	}
	return packages, nil
}

func (c Client) runQuery(query string) (queryResponse, error) {
	if strings.TrimSpace(query) == "" {
		return queryResponse{}, fmt.Errorf("query is empty")
	}

	endpoint := c.Endpoint
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultEndpoint
	}

	payload, err := json.Marshal(queryRequest{Query: query})
	if err != nil {
		return queryResponse{}, fmt.Errorf("marshal Joern query: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if strings.TrimSpace(c.SSHTarget) != "" {
		return c.runQueryOverSSH(ctx, endpoint, payload)
	}

	return c.runQueryOverHTTP(ctx, endpoint, payload)
}

func (c Client) runQueryOverHTTP(ctx context.Context, endpoint string, payload []byte) (queryResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return queryResponse{}, fmt.Errorf("build Joern request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return queryResponse{}, fmt.Errorf("execute Joern request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return queryResponse{}, fmt.Errorf("read Joern response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return queryResponse{}, fmt.Errorf("Joern request failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return decodeQueryResponse(body)
}

func (c Client) runQueryOverSSH(ctx context.Context, endpoint string, payload []byte) (queryResponse, error) {
	remoteCommand := fmt.Sprintf(
		"curl -sS --max-time %d -X POST %s -H 'Content-Type: application/json' --data-binary @-",
		int(defaultTimeout.Seconds()),
		shellQuote(endpoint),
	)

	cmd := exec.CommandContext(ctx, "ssh", "-T", c.SSHTarget, remoteCommand)
	cmd.Stdin = bytes.NewReader(payload)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return queryResponse{}, fmt.Errorf("execute remote Joern query via ssh %q: %w\n%s", c.SSHTarget, err, strings.TrimSpace(string(output)))
	}

	return decodeQueryResponse(output)
}

func decodeQueryResponse(body []byte) (queryResponse, error) {
	var resp queryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return queryResponse{}, fmt.Errorf("parse Joern response JSON: %w", err)
	}
	if !resp.Success {
		return queryResponse{}, fmt.Errorf("Joern query failed: %s", strings.TrimSpace(resp.Stdout))
	}
	return resp, nil
}

func extractJSONString(stdout string) (string, error) {
	cleaned := ansiPattern.ReplaceAllString(stdout, "")
	matches := finalStringPattern.FindAllStringSubmatch(cleaned, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("did not find final JSON string in Joern stdout: %s", strings.TrimSpace(cleaned))
	}

	value, err := strconv.Unquote(matches[len(matches)-1][1])
	if err != nil {
		return "", fmt.Errorf("unquote Joern JSON string: %w", err)
	}
	return value, nil
}

func normalizePackages(sourceRoot string, packages []evidence.Package) error {
	index, err := indexSourceFiles(sourceRoot)
	if err != nil {
		return fmt.Errorf("index source files: %w", err)
	}

	for i := range packages {
		packages[i].Candidate.File = resolveSourceFile(index, sourceRoot, packages[i].Candidate.File, packages[i].Candidate.Line, packages[i].Candidate.Expression)
		packages[i].Candidate.ID = buildCandidateID(packages[i].Candidate)

		for j := range packages[i].Checks {
			packages[i].Checks[j].File = resolveSourceFile(index, sourceRoot, packages[i].Checks[j].File, packages[i].Checks[j].Line, packages[i].Checks[j].Expression)
		}

		for j := range packages[i].CodeSnippets {
			packages[i].CodeSnippets[j].File = resolveSourceFile(index, sourceRoot, packages[i].CodeSnippets[j].File, packages[i].CodeSnippets[j].Line, packages[i].CodeSnippets[j].Code)
		}

		for j := range packages[i].KeySites {
			packages[i].KeySites[j].File = resolveSourceFile(index, sourceRoot, packages[i].KeySites[j].File, packages[i].KeySites[j].Line, packages[i].KeySites[j].Expression)
		}
	}

	return nil
}

func indexSourceFiles(root string) (map[string][]string, error) {
	index := make(map[string][]string)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		index[base] = append(index[base], path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	for name := range index {
		sort.Strings(index[name])
	}
	return index, nil
}

func resolveSourceFile(index map[string][]string, sourceRoot, reported string, line int, hint string) string {
	reported = strings.TrimSpace(reported)
	if reported == "" {
		return reported
	}

	if filepath.IsAbs(reported) {
		return makeDisplayPath(reported)
	}

	matches := index[filepath.Base(reported)]
	if len(matches) == 0 {
		return filepath.ToSlash(reported)
	}
	if len(matches) == 1 {
		return makeDisplayPath(matches[0])
	}

	if line > 0 {
		for _, match := range matches {
			if lineMatches(match, line, hint) {
				return makeDisplayPath(match)
			}
		}
	}

	relReported := filepath.Join(sourceRoot, reported)
	if _, err := os.Stat(relReported); err == nil {
		return makeDisplayPath(relReported)
	}

	return makeDisplayPath(matches[0])
}

func lineMatches(path string, line int, hint string) bool {
	if line <= 0 {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		return false
	}
	if strings.TrimSpace(hint) == "" {
		return true
	}

	return compact(lines[line-1]) == compact(hint)
}

func compact(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), "")
}

func makeDisplayPath(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(path)
	}

	rel, err := filepath.Rel(wd, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func buildCandidateID(candidate evidence.Candidate) string {
	base := strings.TrimSuffix(filepath.Base(candidate.File), filepath.Ext(candidate.File))
	if base == "" {
		base = "candidate"
	}

	parts := []string{
		base,
		sanitizeIDPart(candidate.Function),
		fmt.Sprintf("line%d", candidate.Line),
		fmt.Sprintf("param%d", candidate.ParamIndex),
	}
	return strings.Join(parts, "-")
}

func sanitizeIDPart(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}

	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}

	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "unknown"
	}
	return result
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func (c Client) remoteSourcePath(localPath string) string {
	remoteRoot := strings.TrimSpace(c.RemoteRoot)
	if remoteRoot == "" {
		remoteRoot = "/workspace/tee-usage-scanner"
	}

	wd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(localPath)
	}

	localRoot := findLocalRootForRemoteRoot(wd, remoteRoot)
	rel, err := filepath.Rel(localRoot, localPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel, err = filepath.Rel(wd, localPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(localPath)
		}
	}

	return filepath.ToSlash(filepath.Join(remoteRoot, rel))
}

func findLocalRootForRemoteRoot(start, remoteRoot string) string {
	needle := filepath.Base(filepath.Clean(remoteRoot))
	current := filepath.Clean(start)

	for {
		if filepath.Base(current) == needle {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			return start
		}
		current = parent
	}
}

const evidenceQueryTemplate = `
case class ExtractedCheck(
  kind: String,
  file: String,
  method: String,
  line: Int,
  expression: String,
  notes: List[String]
)

def paramIndexOf(expr: String): Int = {
  val pattern = "params\\[(\\d+)\\]".r
  pattern.findFirstMatchIn(expr).map(_.group(1).toInt).getOrElse(-1)
}

def normalizeCode(value: String): String = {
  value.split("\\s+").filter(_.nonEmpty).mkString(" ").trim
}

importCode(%s)

val controls = cpg.controlStructure.l

val paramTypeChecks = controls.flatMap { cs =>
  val condition = normalizeCode(cs.condition.code.l.headOption.getOrElse(""))
  if (condition.contains("param_types")) {
    Some(ExtractedCheck(
      "param_types_check",
      cs.file.name.l.headOption.getOrElse(""),
      cs.method.name,
      cs.lineNumber.getOrElse(-1),
      condition,
      List("param_types appears in a guarding condition")
    ))
  } else {
    None
  }
}

val sizeChecks = controls.flatMap { cs =>
  val condition = normalizeCode(cs.condition.code.l.headOption.getOrElse(""))
  if (condition.contains(".memref.size")) {
    Some(ExtractedCheck(
      "size_check",
      cs.file.name.l.headOption.getOrElse(""),
      cs.method.name,
      cs.lineNumber.getOrElse(-1),
      condition,
      List("memref size is checked before use")
    ))
  } else {
    None
  }
}

val checks = paramTypeChecks ++ sizeChecks

val packages = cpg.call.l.flatMap { call =>
  val expressions = call.argument.code.l.map(normalizeCode).filter(_.contains(".memref.buffer"))
  expressions.headOption.map { expr =>
    val file = call.file.name.l.headOption.getOrElse("")
    val method = call.method.name
    val line = call.lineNumber.getOrElse(-1)
    val paramIndex = paramIndexOf(expr)
    val localChecks = checks
      .filter(check => check.file == file && check.method == method && check.line >= 0 && check.line < line)
      .sortBy(_.line)

    val candidateNotes =
      if (method == "TA_InvokeCommandEntryPoint")
        List("candidate occurs in the TA entrypoint")
      else
        List("candidate occurs in a helper that should inherit entrypoint validation")

    val controlFlowSummary =
      if (localChecks.isEmpty)
        List(s"$method: no same-method checks observed before memref use")
      else
        List(s"$method: observed same-method checks before memref use: ${localChecks.map(_.kind).distinct.mkString(", ")}")

    ujson.Obj(
      "schema_version" -> "teecheck.evidence.v1",
      "metadata" -> ujson.Obj(
        "source" -> "joern",
        "review_recommended" -> (method != "TA_InvokeCommandEntryPoint").toString
      ),
      "candidate" -> ujson.Obj(
        "id" -> s"${file}:${method}:${line}:${paramIndex}",
        "sdk" -> "optee",
        "file" -> file,
        "function" -> method,
        "line" -> line,
        "expression" -> expr,
        "operation_kind" -> "memref_use",
        "param_index" -> paramIndex,
        "notes" -> ujson.Arr.from(candidateNotes.map(ujson.Str(_)))
      ),
      "checks" -> ujson.Arr.from(localChecks.map { check =>
        ujson.Obj(
          "kind" -> check.kind,
          "file" -> check.file,
          "line" -> check.line,
          "expression" -> check.expression,
          "dominates_target" -> (check.line < line),
          "notes" -> ujson.Arr.from(check.notes.map(ujson.Str(_)))
        )
      }),
      "bindings" -> ujson.Arr(),
      "code_snippets" -> ujson.Arr(
        ujson.Obj(
          "label" -> "sensitive-operation",
          "file" -> file,
          "line" -> line,
          "code" -> normalizeCode(call.code)
        )
      ),
      "control_flow_summary" -> ujson.Arr.from(controlFlowSummary.map(ujson.Str(_))),
      "data_flow_summary" -> ujson.Arr(
        ujson.Str(s"$expr originates from TA entry parameter")
      )
    )
  }
}

ujson.write(ujson.Arr.from(packages))
`

const attestationEvidenceQueryTemplate = `
case class ExtractedCheck(
  kind: String,
  file: String,
  method: String,
  line: Int,
  expression: String,
  fields: List[String],
  notes: List[String]
)

case class ExtractedSite(
  kind: String,
  file: String,
  method: String,
  line: Int,
  expression: String,
  notes: List[String]
)

def normalizeCode(value: String): String = {
  value.split("\\s+").filter(_.nonEmpty).mkString(" ").trim
}

def lower(value: String): String = normalizeCode(value).toLowerCase

def fileOfMethod(method: io.shiftleft.codepropertygraph.generated.nodes.Method): String =
  method.file.name.l.headOption.getOrElse("")

def fileOfCall(call: io.shiftleft.codepropertygraph.generated.nodes.Call): String =
  call.file.name.l.headOption.getOrElse("")

def isVerifierFile(file: String): Boolean = {
  val lowered = file.toLowerCase
  lowered.endsWith("verify.js") || lowered.endsWith("verify.rs")
}

def backendOf(file: String): String = {
  val lowered = file.toLowerCase
  if (lowered.endsWith(".js")) "javascript"
  else if (lowered.endsWith(".rs")) "rust"
  else "unknown"
}

def methodCodes(method: io.shiftleft.codepropertygraph.generated.nodes.Method): List[String] =
  method.ast.code.l.map(normalizeCode)

def containsAny(value: String, needles: List[String]): Boolean = {
  val lowered = value.toLowerCase
  needles.exists(needle => lowered.contains(needle.toLowerCase))
}

def collectPolicyFields(method: io.shiftleft.codepropertygraph.generated.nodes.Method): List[String] = {
  val codes = methodCodes(method).map(_.toLowerCase)
  var fields = List[String]()

  if (codes.exists(code => code.contains("mrsigner") || code.contains("mr_signer")))
    fields = fields :+ "mrsigner"
  if (codes.exists(code => code.contains("isvprodid") || code.contains("isv_prod_id")))
    fields = fields :+ "isvprodid"
  if (codes.exists(code => code.contains("isvsvn") || code.contains("isv_svn")))
    fields = fields :+ "isvsvn"
  if (codes.exists(code => code.contains("miscselectmask") || code.contains("miscselect_mask") || (code.contains("miscselect") && code.contains("mask"))))
    fields = fields :+ "miscselect_masked"
  if (codes.exists(code => code.contains("attributesmask") || code.contains("attributes_mask") || (code.contains("attributes") && code.contains("mask"))))
    fields = fields :+ "attributes_masked"

  fields.distinct
}

def firstSite(kind: String, method: io.shiftleft.codepropertygraph.generated.nodes.Method, calls: List[io.shiftleft.codepropertygraph.generated.nodes.Call], needles: List[String], notes: List[String]): Option[ExtractedSite] = {
  calls.find(call => containsAny(call.name, needles) || containsAny(call.code, needles)).map { call =>
    ExtractedSite(
      kind,
      fileOfCall(call),
      method.name,
      call.lineNumber.getOrElse(-1),
      normalizeCode(call.code),
      notes
    )
  }
}

importCode(%s)

val policyHelpers = cpg.method.l.filter { method =>
  val file = fileOfMethod(method)
  isVerifierFile(file) && containsAny(method.name, List("verifyqeidentitypolicy", "verify_qe_identity_policy"))
}

val attestationEntries = cpg.method.l.filter { method =>
  val file = fileOfMethod(method)
  val callNames = method.ast.isCall.name.l.map(_.toLowerCase)
  val returnCodes = method.ast.isReturn.code.l.map(lower)
  isVerifierFile(file) &&
  method.name != ":program" &&
  !containsAny(method.name, List("verifyqeidentitypolicy", "verify_qe_identity_policy")) &&
  (
    containsAny(method.name, List("verifyimpl", "verify_impl")) ||
    (
      callNames.exists(name => containsAny(name, List("verifyqeidentitypolicy", "verify_qe_identity_policy"))) &&
      returnCodes.exists(code => containsAny(code, List("verifiedreport", "verificationresult::ok")))
    )
  )
}

val packages = attestationEntries.flatMap { entry =>
  val file = fileOfMethod(entry)
  val method = entry.name
  val line = entry.lineNumber.getOrElse(-1)
  val backend = backendOf(file)
  val entryCalls = entry.ast.isCall.l
  val entryReturns = entry.ast.isReturn.l

  val identityParsingSite = entry.ast.l
    .find(node => containsAny(node.code, List("collateral.qe_identity", "collateral.qe_identity_issuer_chain", "qeidentity.fromjson", "from_str::<qeidentity>", "qe_identity")))
    .map { node =>
      ExtractedSite(
        "identity_parsing_site",
        file,
        method,
        node.lineNumber.getOrElse(-1),
        normalizeCode(node.code),
        List("Identity material is parsed or consumed here")
      )
    }

  val issuerCheck = firstSite(
    "certificate_chain_validation_site",
    entry,
    entryCalls,
    List("verifycertificatechain", "verify_certificate_chain"),
    List("Certificate chain validation observed")
  )

  val signatureCheck = entryCalls
    .find(call =>
      containsAny(call.name, List("verifyecdsasignature", "verify_qe_identity_signature", "verifysignature", "verify_signature")) &&
      containsAny(call.code, List("qe_identity", "collateral.qe_identity"))
    )
    .map { call =>
      ExtractedSite(
        "identity_signature_validation_site",
        fileOfCall(call),
        method,
        call.lineNumber.getOrElse(-1),
        normalizeCode(call.code),
        List("Identity signature validation observed")
      )
    }

  val policyCall = entryCalls
    .find(call => containsAny(call.name, List("verifyqeidentitypolicy", "verify_qe_identity_policy")))

  val trustDecision = entryReturns
    .find(ret => containsAny(ret.code, List("verifiedreport", "verificationresult::ok")))
    .orElse(entryReturns.headOption)
    .map { ret =>
      ExtractedSite(
        "trust_decision_site",
        ret.file.name.l.headOption.getOrElse(file),
        method,
        ret.lineNumber.getOrElse(-1),
        normalizeCode(ret.code),
        List("Trust-bearing result returned here")
      )
    }

  val policyHelper = policyHelpers.headOption
  val policyFields = policyHelper.map(collectPolicyFields).getOrElse(Nil)

  val checks = List(
    issuerCheck.map(site => ExtractedCheck("issuer_chain_validation", site.file, site.method, site.line, site.expression, Nil, site.notes)),
    signatureCheck.map(site => ExtractedCheck("identity_signature_validation", site.file, site.method, site.line, site.expression, Nil, site.notes)),
    policyCall.map { call =>
      ExtractedCheck(
        "identity_policy_binding",
        fileOfCall(call),
        method,
        call.lineNumber.getOrElse(-1),
        normalizeCode(call.code),
        policyFields,
        List(
          "Policy helper reached from attestation verification entry"
        ) ++ policyHelper.map(helper => s"helper_definition=${fileOfMethod(helper)}:${helper.lineNumber.getOrElse(-1)}").toList
      )
    }
  ).flatten

  val keySites = List(
    Some(ExtractedSite(
      "verification_entry",
      file,
      method,
      line,
      s"${entry.name}(...)",
      List("Attestation verification entrypoint")
    )),
    identityParsingSite,
    issuerCheck,
    signatureCheck,
    policyCall.map { call =>
      ExtractedSite(
        "policy_binding_site",
        fileOfCall(call),
        method,
        call.lineNumber.getOrElse(-1),
        normalizeCode(call.code),
        List("Policy binding call site") ++ policyHelper.map(helper => s"helper_definition=${fileOfMethod(helper)}:${helper.lineNumber.getOrElse(-1)}").toList
      )
    },
    trustDecision
  ).flatten

  val summaries = List(
    if (checks.isEmpty)
      s"$method: no attestation obligations observed before trust decision"
    else
      s"$method: observed attestation checks before trust decision: ${checks.map(_.kind).distinct.mkString(", ")}"
  )

  val snippets = List(
    Some(ujson.Obj(
      "label" -> "verification-entry",
      "file" -> file,
      "line" -> line,
      "code" -> s"${entry.name}(...)"
    )),
    trustDecision.map(site => ujson.Obj(
      "label" -> "trust-decision",
      "file" -> site.file,
      "line" -> site.line,
      "code" -> site.expression
    )),
    policyHelper.map(helper => ujson.Obj(
      "label" -> "policy-helper",
      "file" -> fileOfMethod(helper),
      "line" -> helper.lineNumber.getOrElse(-1),
      "code" -> s"${helper.name}(...)"
    ))
  ).flatten

  if (policyCall.isDefined || identityParsingSite.isDefined || trustDecision.isDefined) {
    Some(
      ujson.Obj(
        "schema_version" -> "teecheck.evidence.v1",
        "metadata" -> ujson.Obj(
          "source" -> "joern",
          "backend_name" -> backend,
          "review_recommended" -> "true"
        ),
        "candidate" -> ujson.Obj(
          "id" -> s"${file}:${method}:${line}:attestation",
          "sdk" -> "dcap",
          "file" -> file,
          "function" -> method,
          "line" -> line,
          "expression" -> s"${entry.name}(...)",
          "operation_kind" -> "attestation_verification_entry",
          "param_index" -> -1,
          "notes" -> ujson.Arr(
            "Attestation verification candidate emitted from verifier source file",
            s"backend=$backend"
          )
        ),
        "checks" -> ujson.Arr.from(checks.map { check =>
          ujson.Obj(
            "kind" -> check.kind,
            "file" -> check.file,
            "line" -> check.line,
            "expression" -> check.expression,
            "dominates_target" -> (check.line >= 0 && trustDecision.forall(site => check.line <= site.line)),
            "fields" -> ujson.Arr.from(check.fields.map(ujson.Str(_))),
            "notes" -> ujson.Arr.from(check.notes.map(ujson.Str(_)))
          )
        }),
        "bindings" -> ujson.Arr(),
        "key_sites" -> ujson.Arr.from(keySites.map { site =>
          ujson.Obj(
            "kind" -> site.kind,
            "file" -> site.file,
            "line" -> site.line,
            "function" -> site.method,
            "expression" -> site.expression,
            "notes" -> ujson.Arr.from(site.notes.map(ujson.Str(_)))
          )
        }),
        "code_snippets" -> ujson.Arr.from(snippets),
        "control_flow_summary" -> ujson.Arr.from(summaries.map(ujson.Str(_))),
        "data_flow_summary" -> ujson.Arr(
          ujson.Str("qe_identity or related collateral influences the final trust decision")
        )
      )
    )
  } else {
    None
  }
}

ujson.write(ujson.Arr.from(packages))
`

var evidenceQueries = []evidenceQuery{
	{
		Name:     "optee-memref",
		Template: evidenceQueryTemplate,
	},
	{
		Name:     "attestation",
		Template: attestationEvidenceQueryTemplate,
	},
}
