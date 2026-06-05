# tee-audit

A 7-stage static audit pipeline for analyzing TEE usage in Web3 and blockchain projects. Combines deterministic scanning (CodeQL, structural search) with LLM-assisted reasoning and adversarial review to produce reproducible, evidence-grounded security findings.

## What it does

tee-audit takes a repository URL or local path and produces a structured security report covering:

- **TEE platform signals** — SGX, SEV, TrustZone, Confidential Computing, and custom enclave patterns
- **Web3 role signals** — validator, key manager, oracle, bridge, and off-chain worker patterns
- **Trust boundary invariants** — security properties derived from the repo's architecture
- **Verified findings** — severity-graded, cross-boundary evidence, with code locations and remediation
- **Positive guards** — confirmed security mechanisms that are in place
- **Adversarial review** — iterative severity challenges and finding dismissal to reduce false positives

## Quick start

```bash
# Install
pip install tee-audit

# Or from source
git clone https://github.com/pinshenxu/tee-audit.git
cd tee-audit
pip install -e .

# Set up LLM API key (required for stages 1, 2, 5b, 6, 7)
export ANTHROPIC_API_KEY=sk-...

# Set up CodeQL (required for stage 4)
tee-audit setup codeql

# Run full audit
tee-audit scan --repo https://github.com/example/project

# Run specific stages only
tee-audit scan --repo ./local-project --stage 0-3

# Use other LLM providers
tee-audit scan --repo ./project --llm-api openai
tee-audit scan --repo ./project --llm-api glm
```

## Pipeline stages

| Stage | Name | Method | Description |
|-------|------|--------|-------------|
| 0 | Fingerprint | Deterministic | Scan repo for TEE platforms, Web3 roles, trust artifacts, manifests |
| 1 | Dossier | LLM | Generate architecture dossier with parties, roles, and trust boundaries |
| 2 | Invariants | LLM | Extract security invariants guided by TEE taxonomy |
| 3 | Analysis Matrix | Deterministic | Map invariants to analysis families and tools |
| 4 | CodeQL Scan | External tool + LLM | Generate project-specific CodeQL queries, build DB, run scan |
| 5 | Triage + Deep Verify | Deterministic + LLM | Grade SARIF results, verify findings with zone maps and caller graphs |
| 6 | Report Assembly | Deterministic + LLM | Build report with dashboard, Mermaid diagrams, and code evidence |
| 7 | Report Review | LLM | Adversarial review loop: severity challenges, finding dismissal, unknown resolution |

Stages 0 and 3 are pure Python. Stage 4 requires the CodeQL CLI. Stages 1, 2, 5b, 6, and 7 require an LLM API key.

## Analysis families

Each invariant is mapped to one of five analysis families:

1. **Flow** — Value crosses a trust boundary to a dangerous sink
2. **Guard** — Required check exists before a critical action
3. **Binding** — Cryptographic or identity binding between artifacts
4. **State/Lifecycle** — Continuity, replay resistance, rollback protection
5. **Config/Build/Deploy** — Flags, features, deployment assumptions

See [docs/reference/analysis-families.md](docs/reference/analysis-families.md) for the full methodology.

## Output

Results are saved to the `output/` directory:

```
output/
├── <project>-audit/              # Working directory (gitignored)
│   ├── <project>/                # Cloned repository
│   ├── artifact/                 # SARIF, zone maps, caller graphs
│   └── results/                  # Stage outputs and final report
│       ├── stage0_output.json    # Fingerprint
│       ├── stage1_output.json    # Dossier
│       ├── ...
│       ├── stage7_output.json    # Review results
│       └── report.md             # Human-readable report
└── reports/                      # Organized reports (tracked in git)
    └── YYYY-MM-DD/
        └── <project>.md
```

Intermediate results are persisted per-stage, enabling resume if a later stage fails.

## Configuration

Priority order: CLI arguments > environment variables > config file > defaults.

```bash
# Environment variables
ANTHROPIC_API_KEY          # LLM API key (Anthropic)
OPENAI_API_KEY             # LLM API key (OpenAI)
GLM_API_KEY                # LLM API key (GLM / z.ai)
GLM_BASE_URL               # Custom base URL for GLM provider
TEE_AUDIT_CODEQL_PATH      # Path to CodeQL binary
TEE_AUDIT_ARTIFACT_ROOT    # Output directory (default: output/)

# Config file (~/.tee-audit/config.yaml)
llm_provider: anthropic    # anthropic | openai | glm | codex
llm_model: ""              # Leave empty for provider default
max_concurrent_llm_calls: 3
verbose: false
```

## Development

```bash
# Set up environment
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/

# Validate cross-boundary evidence in findings
python scripts/validate_boundary.py <repo-name>
```

## Architecture

```
src/tee_audit/
├── cli.py                 # Click CLI entry point
├── pipeline.py            # Stage orchestration
├── config.py              # Configuration management
├── contracts.py           # Per-stage typed input/output contracts
├── audit_context.py       # Stage persistence and resume support
├── models/                # Pydantic data models
│   ├── fingerprint.py     #   Fingerprint
│   ├── invariant.py       #   Invariant, InvariantFamily
│   ├── finding.py         #   Finding, Severity, Confidence, CodeLocation
│   ├── triage.py          #   GradedFinding, PositiveGuard
│   ├── unknown.py         #   Unknown
│   └── report.py          #   Report, DashboardEntry
├── stages/                # Pipeline stage implementations
│   ├── fingerprint.py     #   Stage 0: TEE signal + manifest detection
│   ├── dossier.py         #   Stage 1: LLM architecture dossier
│   ├── invariants.py      #   Stage 2: LLM invariant extraction
│   ├── matrix.py          #   Stage 3: Analysis matrix generation
│   ├── codeql.py          #   Stage 4: LLM-generated CodeQL queries + scan
│   ├── triage.py          #   Stage 5a: Deterministic grading
│   ├── deep_verify.py     #   Stage 5b: LLM verification with zone maps
│   ├── report.py          #   Stage 6: Report with dashboard + evidence
│   └── report_review.py   #   Stage 7: Ralph adversarial review loop
├── llm/                   # LLM integration
│   ├── client.py          #   Multi-provider client (Anthropic, OpenAI, GLM)
│   ├── prompt_loader.py   #   Template loading with variable substitution
│   └── response_parser.py #   Structured output parsing with retry
├── patterns/              # Regex pattern libraries
│   └── tee_signals.py     #   TEE platform, Web3 role, trust artifact patterns
├── prompts/               # LLM prompt templates (Markdown)
├── utils/                 # Shared utilities
│   ├── call_graph.py      #   Trust zone classification, caller graphs
│   ├── codeql_check.py    #   CodeQL discovery, validation, download
│   ├── codeql_templates.py#   Language-aware CodeQL query generation
│   ├── manifest_parsers.py#   TEE manifest parsers (Gramine, OE EDL, Dockerfile)
│   ├── repo.py            #   Repo resolution, cloning, commit hash
│   └── sarif.py           #   SARIF 2.1.0 parser
└── logging.py             # Structured JSON logging
```

## Audited Projects

Reports for 14 open-source Web3 TEE projects are available in `output/reports/`:

automata-dcap-attestation, dcap-qvl, fabric-private-chaincode, full-service, mobilecoin, Node, oasis-core, oasis-sdk, phala-blockchain, qos, raiko, sapphire-paratime, SecretNetwork, suave-geth

## Reference Documentation

| Document | Description |
|----------|-------------|
| [methodology.md](docs/reference/methodology.md) | 7-stage audit methodology and principles |
| [analysis-families.md](docs/reference/analysis-families.md) | 5 analysis families for classifying invariants |
| [rule-seeds.md](docs/reference/rule-seeds.md) | CodeQL rule seeds mapped to analysis families |
| [evidence-grading.md](docs/reference/evidence-grading.md) | Finding confidence labels and evidence standards |
| [codeql-bootstrap.md](docs/guides/codeql-bootstrap.md) | CodeQL setup and database creation guide |
| [fingerprint-template.md](docs/templates/fingerprint-template.md) | Stage 0 project fingerprint template |
| [dossier-template.md](docs/templates/dossier-template.md) | Stage 1 architecture dossier template |
| [invariant-template.md](docs/templates/invariant-template.md) | Stage 2 security invariant template |

## License

MIT
