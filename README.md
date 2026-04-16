# tee-audit

A 7-stage static audit pipeline for analyzing TEE usage in Web3 and blockchain projects. Combines deterministic scanning (CodeQL, structural search) with LLM-assisted reasoning to produce reproducible, evidence-grounded security findings.

## What it does

tee-audit takes a repository URL or local path and produces a structured security report covering:

- **TEE platform signals** — SGX, SEV, TrustZone, Confidential Computing, and custom enclave patterns
- **Web3 role signals** — validator, key manager, oracle, bridge, and off-chain worker patterns
- **Trust boundary invariants** — security properties derived from the repo's architecture
- **Verified findings** — severity-graded, POC-backed, with code locations and remediation
- **Positive guards** — confirmed security mechanisms that are in place

## Quick start

```bash
# Install
pip install tee-audit

# Or from source
git clone https://github.com/pinshenxu/tee-audit.git
cd tee-audit
pip install -e .

# Set up LLM API key (required for stages 1, 2, 5, 6)
export ANTHROPIC_API_KEY=sk-...

# Set up CodeQL (required for stage 4)
tee-audit setup codeql

# Run full audit
tee-audit scan --repo https://github.com/example/project

# Run specific stages only
tee-audit scan --repo ./local-project --stage 0-3

# Use OpenAI instead of Anthropic
tee-audit scan --repo ./project --llm-api openai
```

## Pipeline stages

| Stage | Name | Method | Description |
|-------|------|--------|-------------|
| 0 | Fingerprint | Deterministic | Scan repo for TEE platforms, Web3 roles, trust artifacts, build flags |
| 1 | Dossier | LLM | Generate architecture dossier from fingerprint + repo structure |
| 2 | Invariants | LLM | Extract security invariants from dossier and trust paths |
| 3 | Analysis Matrix | Deterministic | Map invariants to analysis families and tools |
| 4 | CodeQL Scan | External tool | Build CodeQL database and run baseline queries |
| 5 | Triage + Deep Verify | Deterministic + LLM | Grade SARIF results, verify findings with POCs |
| 6 | Report Assembly | Deterministic + LLM | Build severity dashboard and executive summary |

Stages 0 and 3 are pure Python. Stage 4 requires the CodeQL CLI. Stages 1, 2, 5b, and 6 require an LLM API key.

## Analysis families

Each invariant is mapped to one of five analysis families:

1. **Flow** — Value crosses a trust boundary to a dangerous sink
2. **Guard** — Required check exists before a critical action
3. **Binding** — Cryptographic or identity binding between artifacts
4. **State/Lifecycle** — Continuity, replay resistance, rollback protection
5. **Config/Build/Deploy** — Flags, features, deployment assumptions

See [docs/analysis-families.md](docs/analysis-families.md) for the full methodology.

## Output

Results are saved to the `results/` directory:

```
results/
├── stage0_output.json    # Fingerprint
├── stage1_output.json    # Dossier
├── stage2_output.json    # Invariants
├── stage3_output.json    # Analysis matrix
├── stage4_output.json    # CodeQL results
├── stage5_output.json    # Triage
├── stage6_output.json    # Deep verify
├── stage7_output.json    # Final report
└── report.md             # Human-readable report
```

Intermediate results are persisted per-stage, enabling resume if a later stage fails.

## Configuration

Priority order: CLI arguments > environment variables > config file > defaults.

```bash
# Environment variables
ANTHROPIC_API_KEY          # LLM API key (Anthropic)
OPENAI_API_KEY             # LLM API key (OpenAI)
TEE_AUDIT_CODEQL_PATH      # Path to CodeQL binary
TEE_AUDIT_ARTIFACT_ROOT    # Output directory (default: /tmp/tee-audit)

# Config file (~/.tee-audit/config.yaml)
llm_provider: anthropic
llm_model: claude-sonnet-4-20250514
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
│   ├── finding.py         #   Finding, Severity, Confidence
│   ├── triage.py          #   GradedFinding, PositiveGuard
│   ├── unknown.py         #   Unknown
│   └── report.py          #   Report, DashboardEntry
├── stages/                # Pipeline stage implementations
│   ├── fingerprint.py     #   Stage 0: TEE signal detection
│   ├── dossier.py         #   Stage 1: LLM architecture dossier
│   ├── invariants.py      #   Stage 2: LLM invariant extraction
│   ├── matrix.py          #   Stage 3: Analysis matrix generation
│   ├── codeql.py          #   Stage 4: CodeQL database + scan
│   ├── triage.py          #   Stage 5a: Deterministic grading
│   ├── deep_verify.py     #   Stage 5b: LLM verification with POCs
│   └── report.py          #   Stage 6: Dashboard + executive summary
├── llm/                   # LLM integration
│   ├── client.py          #   Abstract client, Anthropic, OpenAI
│   ├── prompt_loader.py   #   Template loading with variable substitution
│   └── response_parser.py #   Structured output parsing with retry
├── patterns/              # Regex pattern libraries
│   ├── tee_signals.py     #   TEE platform, Web3 role, trust artifact patterns
│   └── search_patterns.py #   Additional structural search patterns
├── prompts/               # LLM prompt templates (Markdown)
├── utils/                 # Shared utilities
│   ├── codeql_check.py    #   CodeQL discovery, validation, download
│   ├── repo.py            #   Repo resolution, cloning, commit hash
│   └── sarif.py           #   SARIF 2.1.0 parser
└── logging.py             # Structured JSON logging
```

## License

MIT
