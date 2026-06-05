"""LLM-driven CodeQL query generation from taint specifications.

Uses embedded language-specific CodeQL templates and project-specific taint
specifications to generate queries via LLM, with a compile-and-refine loop.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

from pydantic import BaseModel

from tee_audit.llm.client import LLMClient
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.invariant import Invariant

logger = logging.getLogger(__name__)

# Language → CodeQL pack dependency
_LANGUAGE_PACKS: dict[str, str] = {
    "rust": "codeql/rust-all",
    "go": "codeql/go-all",
    "cpp": "codeql/cpp-all",
    "python": "codeql/python-all",
    "javascript": "codeql/javascript-all",
}

# Language → import statement
_LANGUAGE_IMPORTS: dict[str, str] = {
    "rust": "rust",
    "go": "go",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
}

# Language → taint tracking code template (modern DataFlow::ConfigSig API)
_TAINT_TRACKING_TEMPLATES: dict[str, str] = {
    "rust": """\
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking

/**
 * @name [descriptive name]
 * @description [what taint flow is detected and why it matters for TEE security]
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Call call |
      // Prefer canonical path matching for precision
      call.getStaticTarget().(Function).getCanonicalPath().matches("%source_pattern%") and
      source.asExpr() = call
    )
    or
    exists(Call call |
      // Fallback to name matching
      call.getTargetName().toLowerCase().matches("%source_pattern%") and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getStaticTarget().(Function).getCanonicalPath().matches("%sink_pattern%") and
      sink.asExpr() = call
    )
    or
    exists(Call call |
      call.getTargetName().toLowerCase().matches("%sink_pattern%") and
      sink.asExpr() = call
    )
    or
    exists(Call call |
      // Match sink at argument position (e.g., report_data argument)
      call.getTargetName().toLowerCase().matches("%sink_function%") and
      sink.asExpr() = call.getAnArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(Call call |
      call.getTargetName().toLowerCase().matches("%barrier_pattern%") and
      node.asExpr() = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Track through security-relevant crypto operations only
    exists(Call call |
      call.getTargetName().toLowerCase().matches([
        "%hash%", "%digest%", "%sha%", "%hmac%",
        "%encrypt%", "%sign%"
      ]) and
      node1.asExpr() = call.getAnArgument() and
      node2.asExpr() = call
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TEE security: data from $@ reaches $@ without proper guard.",
  source.getNode(), "this source",
  sink.getNode(), "this sink\"""",
    "go": """\
import go
import codeql.go.dataflow.DataFlow
import codeql.go.dataflow.TaintTracking

/**
 * @name [descriptive name]
 * @description [what taint flow is detected and why it matters for TEE security]
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%sink_pattern%") and
      sink = call
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%barrier_pattern%") and
      node = call
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TEE security: data from %s reaches %s without proper guard.",
  source.getNode(), sink.getNode()""",
    "cpp": """\
import cpp
import codeql.cpp.dataflow.DataFlow
import codeql.cpp.dataflow.TaintTracking

/**
 * @name [descriptive name]
 * @description [what taint flow is detected and why it matters for TEE security]
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall call |
      call.getTarget().getName().toLowerCase().matches("%source_pattern%") and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName().toLowerCase().matches("%sink_pattern%") and
      sink.asExpr() = call
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(FunctionCall call |
      call.getTarget().getName().toLowerCase().matches("%barrier_pattern%") and
      node.asExpr() = call
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TEE security: data from $@ reaches $@ without proper guard.",
  source.getNode(), "this source",
  sink.getNode(), "this sink\"""",
    "python": """\
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * @name [descriptive name]
 * @description [what taint flow is detected and why it matters for TEE security]
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName().toLowerCase().matches("%sink_pattern%") and
      sink = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%sink_pattern%") and
      sink = call
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName().toLowerCase().matches("%barrier_pattern%") and
      node = call
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TEE security: data from $@ reaches $@ without proper guard.",
  source.getNode(), "this source",
  sink.getNode(), "this sink\"""",
    "javascript": """\
import javascript
import semmle.javascript.dataflow.new.DataFlow
import semmle.javascript.dataflow.new.TaintTracking

/**
 * @name [descriptive name]
 * @description [what taint flow is detected and why it matters for TEE security]
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::PropertyRead).getPropertyName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::GlobalNameNode).getName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::PropertyRead).getPropertyName().toLowerCase().matches("%sink_pattern%") and
      sink = call
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::GlobalNameNode).getName().toLowerCase().matches("%sink_pattern%") and
      sink = call
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::PropertyRead).getPropertyName().toLowerCase().matches("%barrier_pattern%") and
      node = call
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "TEE security: data from $@ reaches $@ without proper guard.",
  source.getNode(), "this source",
  sink.getNode(), "this sink\"""",
}

# Language → absence/negative-flow query template
# For invariants where the vulnerability is the ABSENCE of a required flow or check.
# Example: "identity key is NOT bound to report_data" — the missing flow IS the bug.
_ABSENCE_QUERY_TEMPLATES: dict[str, str] = {
    "rust": """\
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking

/**
 * @name [descriptive name — e.g., Missing identity key binding in report]
 * @description [what required flow/check is absent and the security impact]
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module ExpectedFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getTargetName().toLowerCase().matches("%source_pattern%") and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getTargetName().toLowerCase().matches("%sink_pattern%") and
      sink.asExpr() = call.getAnArgument()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Call call |
      call.getTargetName().toLowerCase().matches([
        "%hash%", "%digest%", "%sha%", "%hmac%",
        "%encrypt%", "%sign%"
      ]) and
      node1.asExpr() = call.getAnArgument() and
      node2.asExpr() = call
    )
  }
}

module ExpectedFlow = TaintTracking::Global<ExpectedFlowConfig>;

from Call target
where
  target.getTargetName().toLowerCase().matches("%target_pattern%")
  and not exists(DataFlow::Node source, DataFlow::Node sink |
    ExpectedFlowConfig::isSource(source) and
    ExpectedFlowConfig::isSink(sink) and
    ExpectedFlow::flow(source, sink)
  )
select target,
  "Security concern: %specific description of what is missing and why it matters%\"""",
    "go": """\
import go
import codeql.go.dataflow.DataFlow
import codeql.go.dataflow.TaintTracking

/**
 * @name [descriptive name — e.g., Missing identity key binding in report]
 * @description [what required flow/check is absent and the security impact]
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module ExpectedFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%source_pattern%") and
      source = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%sink_pattern%") and
      sink = call.getAnArgument()
    )
  }
}

module ExpectedFlow = TaintTracking::Global<ExpectedFlowConfig>;

from DataFlow::CallNode target
where
  target.getFunction().(DataFlow::NameNode).getName().toLowerCase().matches("%target_pattern%")
  and not exists(DataFlow::Node source, DataFlow::Node sink |
    ExpectedFlowConfig::isSource(source) and
    ExpectedFlowConfig::isSink(sink) and
    ExpectedFlow::flow(source, sink)
  )
select target,
  "Security concern: %specific description of what is missing and why it matters%\"""",
    "cpp": """\
import cpp
import codeql.cpp.dataflow.DataFlow
import codeql.cpp.dataflow.TaintTracking

/**
 * @name [descriptive name — e.g., Missing identity key binding in report]
 * @description [what required flow/check is absent and the security impact]
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/generated/[slug]
 * @tags security tee [family]
 */

module ExpectedFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall call |
      call.getTarget().getName().toLowerCase().matches("%source_pattern%") and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName().toLowerCase().matches("%sink_pattern%") and
      sink.asExpr() = call.getAnArgument()
    )
  }
}

module ExpectedFlow = TaintTracking::Global<ExpectedFlowConfig>;

from FunctionCall target
where
  target.getTarget().getName().toLowerCase().matches("%target_pattern%")
  and not exists(DataFlow::Node source, DataFlow::Node sink |
    ExpectedFlowConfig::isSource(source) and
    ExpectedFlowConfig::isSink(sink) and
    ExpectedFlow::flow(source, sink)
  )
select target,
  "Security concern: %specific description of what is missing and why it matters%\"""",
}

# File extension → CodeQL language name
_EXT_TO_LANGUAGE: dict[str, str] = {
    ".rs": "rust",
    ".go": "go",
    ".c": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
}


class CodeQLQueryFile(BaseModel):
    """A single generated CodeQL query file."""

    filename: str
    content: str


class CodeQLQueryBatch(BaseModel):
    """Batch of generated CodeQL queries from the LLM."""

    queries: list[CodeQLQueryFile]


# Language-specific CodeQL API reference for LLM prompts
_LANGUAGE_API_REFERENCES: dict[str, str] = {
    "rust": (
        "RUST CODEQL API REFERENCE (ONLY use these — all others WILL NOT compile):\n"
        "VALID Call methods: `call.getTargetName()` (string), `call.getStaticTarget()` (Function), "
        "`call.getAnArgument()` (Expr).\n"
        "VALID Function methods: `fun.getCanonicalPath()` (string).\n"
        "VALID DataFlow::Node methods: `node.asExpr()` (Expr), `node.asParameter()` (Parameter).\n"
        "VALID DataFlow constructors: `DataFlow::exprNode(expr)`, `DataFlow::parameterNode(param)`.\n"
        "DO NOT USE (these do NOT exist in Rust CodeQL): "
        "`getTarget()`, `getReceiver()`, `getEnclosingStmt()`, `getEnclosingFunction()`, "
        "`getEnclosingCallable()`, `getEnclosingExpr()`, `getStringValue()`, `getType()` on Expr, "
        "`getAChild()`, `exprNode()` as standalone (use `DataFlow::exprNode()`), "
        "`Parameter` as a type (use `param` in function context), "
        "`LocalVariable` type, `Variable` type, `BinOp`/`BinOpKind` types.\n"
        "For matching calls: ALWAYS use `call.getTargetName().toLowerCase().matches(...)` "
        "or `call.getStaticTarget().(Function).getCanonicalPath().matches(...)`. "
        "NEVER use `call.getTarget().getName()`.\n\n"
        "EXAMPLE — this complete Rust CodeQL query COMPILES. Follow this EXACT structure:\n"
        "```codeql\n"
        "import rust\n"
        "import codeql.rust.dataflow.DataFlow\n"
        "import codeql.rust.dataflow.TaintTracking\n"
        "/** @name Example @description desc @kind path-problem @problem.severity error "
        "@id tee-audit/generated/example @tags security tee */\n"
        "module TaintConfig implements DataFlow::ConfigSig {\n"
        "  predicate isSource(DataFlow::Node source) {\n"
        "    exists(Call call |\n"
        "      call.getTargetName().toLowerCase().matches(\"%pattern%\") and\n"
        "      source.asExpr() = call\n"
        "    )\n"
        "  }\n"
        "  predicate isSink(DataFlow::Node sink) {\n"
        "    exists(Call call |\n"
        "      call.getTargetName().toLowerCase().matches(\"%pattern%\") and\n"
        "      sink.asExpr() = call.getAnArgument()\n"
        "    )\n"
        "  }\n"
        "  predicate isBarrier(DataFlow::Node node) {\n"
        "    exists(Call call |\n"
        "      call.getTargetName().toLowerCase().matches(\"%pattern%\") and\n"
        "      node.asExpr() = call\n"
        "    )\n"
        "  }\n"
        "}\n"
        "module TaintFlow = TaintTracking::Global<TaintConfig>;\n"
        "import TaintFlow::PathGraph\n"
        "from TaintFlow::PathNode source, TaintFlow::PathNode sink\n"
        "where TaintFlow::flowPath(source, sink)\n"
        "select sink.getNode(), source, sink, \"msg\", source.getNode(), \"src\", sink.getNode(), \"snk\"\n"
        "```\n"
    ),
    "go": (
        "GO CODEQL API REFERENCE (ONLY use these — all others WILL NOT compile):\n"
        "VALID Call methods: `call.getTarget().getName()` (string), `call.getAnArgument()` (Expr).\n"
        "VALID Function methods: `fun.getName()` (string), `fun.getQualifiedName()` (string).\n"
        "VALID DataFlow::Node methods: `node.asExpr()` (Expr), `node.asParameter()` (Parameter).\n"
        "VALID DataFlow constructors: `DataFlow::exprNode(expr)`, `DataFlow::parameterNode(param)`.\n"
        "VALID Expr methods: `expr.getType()` (Type).\n"
        "DO NOT USE (these do NOT exist in Go CodeQL): "
        "`getTargetName()`, `getStaticTarget()`, `getCanonicalPath()`, `getReceiver()`, "
        "`getEnclosingStmt()`, `getEnclosingCallable()`, `getStringValue()`, "
        "`LocalVariable` type, `BinOp`/`BinOpKind` types.\n"
        "For matching calls: use `call.getTarget().getName().regexpMatch(\".*pattern.*\")` "
        "or `call.getTarget().getName().toLowerCase().matches(\"%pattern%\")`.\n\n"
        "EXAMPLE — this complete Go CodeQL query COMPILES. Follow this EXACT structure:\n"
        "```codeql\n"
        "import go\n"
        "import codeql.go.dataflow.DataFlow\n"
        "import codeql.go.dataflow.TaintTracking\n"
        "/** @name Example @description desc @kind path-problem @problem.severity error "
        "@id tee-audit/generated/example @tags security tee */\n"
        "module TaintConfig implements DataFlow::ConfigSig {\n"
        "  predicate isSource(DataFlow::Node source) {\n"
        "    exists(DataFlow::CallCfgNode call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      source = call.getAnArgument()\n"
        "    )\n"
        "  }\n"
        "  predicate isSink(DataFlow::Node sink) {\n"
        "    exists(DataFlow::CallCfgNode call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      sink = call.getAnArgument()\n"
        "    )\n"
        "  }\n"
        "  predicate isBarrier(DataFlow::Node node) {\n"
        "    exists(DataFlow::CallCfgNode call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      node = call.getAnArgument()\n"
        "    )\n"
        "  }\n"
        "}\n"
        "module TaintFlow = TaintTracking::Global<TaintConfig>;\n"
        "import TaintFlow::PathGraph\n"
        "from TaintFlow::PathNode source, TaintFlow::PathNode sink\n"
        "where TaintFlow::flowPath(source, sink)\n"
        "select sink.getNode(), source, sink, \"msg\", source.getNode(), \"src\", sink.getNode(), \"snk\"\n"
        "```\n"
    ),
    "cpp": (
        "C++ CODEQL API REFERENCE (ONLY use these — all others WILL NOT compile):\n"
        "VALID Call methods: `call.getTarget().getName()` (string), `call.getAnArgument()` (Expr), "
        "`call.getArgument(n)` (Expr).\n"
        "VALID Function methods: `fun.getName()` (string), `fun.getQualifiedName()` (string), "
        "`fun.hasQualifiedName(...)` (boolean).\n"
        "VALID DataFlow::Node methods: `node.asExpr()` (Expr), `node.asParameter()` (Parameter).\n"
        "VALID DataFlow constructors: `DataFlow::exprNode(expr)`, `DataFlow::parameterNode(param)`.\n"
        "VALID Expr methods: `expr.getType()` (Type), `expr.getValue()` (string for literals).\n"
        "DO NOT USE (these do NOT exist in C++ CodeQL): "
        "`getTargetName()`, `getStaticTarget()`, `getCanonicalPath()`, "
        "`getReceiver()`, `getEnclosingStmt()`, `getEnclosingCallable()`, "
        "`getStringValue()`, `LocalVariable` type.\n"
        "For matching calls: use `call.getTarget().getName().matches(\"%pattern%\")` "
        "or `call.getTarget().(Function).hasQualifiedName(\"namespace\", \"function\")`.\n\n"
        "EXAMPLE — this complete C++ CodeQL query COMPILES. Follow this EXACT structure:\n"
        "```codeql\n"
        "import cpp\n"
        "import codeql.cpp.dataflow.DataFlow\n"
        "import codeql.cpp.dataflow.TaintTracking\n"
        "/** @name Example @description desc @kind path-problem @problem.severity error "
        "@id tee-audit/generated/example @tags security tee */\n"
        "module TaintConfig implements DataFlow::ConfigSig {\n"
        "  predicate isSource(DataFlow::Node source) {\n"
        "    exists(FunctionCall call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      source.asExpr() = call.getArgument(0)\n"
        "    )\n"
        "  }\n"
        "  predicate isSink(DataFlow::Node sink) {\n"
        "    exists(FunctionCall call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      sink.asExpr() = call.getArgument(0)\n"
        "    )\n"
        "  }\n"
        "  predicate isBarrier(DataFlow::Node node) {\n"
        "    exists(FunctionCall call |\n"
        "      call.getTarget().getName().toLowerCase().matches(\"%pattern%\") and\n"
        "      node.asExpr() = call\n"
        "    )\n"
        "  }\n"
        "}\n"
        "module TaintFlow = TaintTracking::Global<TaintConfig>;\n"
        "import TaintFlow::PathGraph\n"
        "from TaintFlow::PathNode source, TaintFlow::PathNode sink\n"
        "where TaintFlow::flowPath(source, sink)\n"
        "select sink.getNode(), source, sink, \"msg\", source.getNode(), \"src\", sink.getNode(), \"snk\"\n"
        "```\n"
    ),
}


def detect_codeql_language(repo_path: Path) -> str:
    """Detect the primary CodeQL language from repository file extensions.

    Counts source files by extension and returns the most common language.
    Defaults to "rust" (most TEE projects are Rust).
    """
    counts: dict[str, int] = {}
    skip = {"target", "build", "dist", "node_modules", ".git", "vendor", "__pycache__", ".venv", "cargo-home"}

    for ext, lang in _EXT_TO_LANGUAGE.items():
        count = 0
        for f in repo_path.rglob(f"*{ext}"):
            if any(p in skip for p in f.parts):
                continue
            count += 1
        if count > 0:
            counts[lang] = counts.get(lang, 0) + count

    if not counts:
        return "rust"

    return max(counts, key=counts.get)


def _extract_project_apis(invariants: list[Invariant]) -> list[str]:
    """Extract key API patterns from invariants for the LLM prompt."""
    apis: set[str] = set()
    for inv in invariants:
        for spec in inv.taint_specs:
            if spec.source:
                apis.add(spec.source)
            if spec.sink:
                apis.add(spec.sink)
            if spec.sanitizer:
                apis.add(spec.sanitizer)
        for src in inv.sources:
            apis.add(src)
        for sink in inv.sinks:
            apis.add(sink)
        for guard in inv.guards:
            apis.add(guard)

    return sorted(apis)[:30]


_FORBIDDEN_FLOW_PATTERNS = [
    '"%clone%"', '"%copy%"', '"%as_ref%"', '"%to_owned%"',
    '"%into%"', '"%from%"', '"%update%"', '"%extend%"',
    '"%finalize%"', '"%serialize%"', '"%encode%"', '"%decode%"',
    '"%parse%"', '"%to_vec%"', '"%as_slice%"', '"%to_string%"',
    '"%unwrap%"', '"%expect%"', '"%to_bytes%"', '"%as_bytes%"',
    '"%as_str%"', '"%map%"', '"%and_then%"', '"%flatten%"',
    '"%collect%"', '"%into_iter%"', '"%index%"', '"%get%"',
    '"%try_from%"', '"%format%"',
]

_ALLOWED_CRYPTO_FLOW_PATTERNS = {
    '"%hash%"', '"%digest%"', '"%sha%"', '"%hmac%"',
    '"%encrypt%"', '"%sign%"', '"%blake%"', '"%keccak%"',
    '"%mac%"', '"%kdf%"',
}

# Anti-patterns: broad source/sink patterns that match thousands of calls
# Matches both single matches("%X%") and list matches(["%X%", ...])
_SOURCE_SINK_ANTI_PATTERNS = [
    (r'isSource.*?"%read%"', "isSource matching %read% — too broad, matches every I/O call"),
    (r'isSource.*?"%open%"', "isSource matching %open% — too broad, matches every I/O call"),
    (r'isSink.*?"%accept%"', "isSink matching %accept% — too broad"),
    (r'isSink.*?"%apply%"', "isSink matching %apply% — too broad"),
    (r'isSink.*?"%commit%"', "isSink matching %commit% — too broad"),
    (r'isSink.*?"%register%"', "isSink matching %register% — too broad"),
    (r'isSink.*?"%save%"', "isSink matching %save% — too broad"),
    (r'isSink.*?"%write%"', "isSink matching %write% — too broad"),
]

# Broad patterns that should be stripped from match lists when specific alternatives exist
_BROAD_SOURCE_PATTERNS = {'"%read%"', '"%open%"'}
_BROAD_SINK_PATTERNS = {'"%accept%"', '"%apply%"', '"%commit%"', '"%register%"', '"%save%"', '"%write%"'}


def _sanitize_query(content: str, language: str = "rust") -> str:
    """Strip forbidden patterns from isAdditionalFlowStep as a safety net.

    For Binding/Guard queries (identified by ExpectedFlowConfig), removes
    isAdditionalFlowStep entirely since it's not needed for absence detection.
    For Flow queries, uses an ALLOWLIST — only keeps crypto-related patterns.
    """
    is_absence_query = "ExpectedFlowConfig" in content

    # For absence (Binding/Guard) queries: remove isAdditionalFlowStep entirely
    if is_absence_query:
        content = re.sub(
            r"\n\s*predicate isAdditionalFlowStep\([^)]*\)\s*\{[^}]*\}",
            "", content, flags=re.DOTALL,
        )
        if "isAdditionalFlowStep" not in content:
            logger.info("Sanitized: removed isAdditionalFlowStep from absence query")
            return content

    # For taint queries: use allowlist — only keep crypto ops
    flow_step_match = re.search(
        r"(predicate isAdditionalFlowStep\([^)]*\)\s*\{)(.+?)(\})",
        content, re.DOTALL,
    )
    if not flow_step_match:
        return content

    # Extract all string patterns from the body
    all_patterns = re.findall(r'"%[^"]+%"', flow_step_match.group(2))
    kept = [p for p in all_patterns if p.lower() in _ALLOWED_CRYPTO_FLOW_PATTERNS]

    if not kept:
        # No allowed patterns remain — remove entire predicate
        content = content[:flow_step_match.start()] + content[flow_step_match.end():]
        logger.info("Sanitized: removed isAdditionalFlowStep (no crypto ops)")
    elif len(kept) < len(all_patterns):
        # Rebuild with only allowed crypto patterns
        kept_formatted = ", ".join(kept)
        new_pred = (
            f"  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {{\n"
            f"    exists(Call call |\n"
            f"      call.getTargetName().toLowerCase().matches([\n"
            f"        {kept_formatted}\n"
            f"      ]) and\n"
            f"      node1.asExpr() = call.getAnArgument() and\n"
            f"      node2.asExpr() = call\n"
            f"    )\n"
            f"  }}"
        )
        content = content[:flow_step_match.start()] + new_pred + content[flow_step_match.end():]
        logger.info("Sanitized: kept %d/%d isAdditionalFlowStep patterns (crypto only)", len(kept), len(all_patterns))

    # Sanitize source/sink: strip broad patterns from match lists when specific alternatives exist
    content = _sanitize_predicate_patterns(content, "isSource", _BROAD_SOURCE_PATTERNS)
    content = _sanitize_predicate_patterns(content, "isSink", _BROAD_SINK_PATTERNS)

    return content


def _sanitize_predicate_patterns(content: str, pred_name: str, broad_patterns: set[str]) -> str:
    """Strip broad anti-patterns from a predicate's match lists when specific alternatives exist.

    Only removes broad patterns if there are other more-specific patterns remaining.
    If all patterns are broad, keeps them all (better than a broken predicate).
    """
    # Find all match list occurrences within the predicate
    pred_match = re.search(
        rf"predicate {pred_name}\(.*?\).*?(?=\n\s*(?:predicate|module|from|select))",
        content, re.DOTALL,
    )
    if not pred_match:
        return content

    pred_text = pred_match.group(0)
    original_pred = pred_text

    # Find all match lists in this predicate
    for list_match in re.finditer(r'matches\(\[(.*?)\]\)', pred_text, re.DOTALL):
        list_content = list_match.group(1)
        all_patterns = [p.strip() for p in re.findall(r'"%[^"]+%"', list_content)]

        if len(all_patterns) <= 1:
            continue  # Don't strip if only one pattern

        specific = [p for p in all_patterns if p.lower() not in broad_patterns]
        broad = [p for p in all_patterns if p.lower() in broad_patterns]

        if not specific:
            continue  # All broad — keep them, better than nothing

        if not broad:
            continue  # No broad patterns to strip

        # Replace the match list: remove broad patterns
        new_list = ", ".join(specific)
        old_list_str = f"matches([{list_content}])"
        new_list_str = f"matches([{new_list}])"
        pred_text = pred_text.replace(old_list_str, new_list_str)

    if pred_text != original_pred:
        content = content[:pred_match.start()] + pred_text + content[pred_match.end():]
        logger.info("Sanitized: stripped broad patterns from %s", pred_name)

    return content


def _validate_query(content: str, language: str = "rust") -> tuple[bool, list[str]]:
    """Validate a generated query has required CodeQL structure.

    Returns (is_valid, list_of_warnings).
    """
    warnings: list[str] = []

    has_name = "@name" in content
    has_kind = "@kind" in content
    has_select = "select" in content.lower()

    # Reject deprecated API patterns
    has_deprecated_config = "TaintTracking::Configuration" in content
    has_deprecated_sanitizer = "isSanitizer" in content

    # Reject cross-language imports
    _LANG_MODULES = {
        "rust": {"semmle.code.cpp.", "semmle.python.", "semmle.javascript.", "import go", "import cpp"},
        "go": {"semmle.code.cpp.", "semmle.python.", "semmle.javascript.", "import rust", "import cpp"},
        "cpp": {"semmle.python.", "semmle.javascript.", "import rust", "import go"},
        "python": {"semmle.code.cpp.", "semmle.javascript.", "import rust", "import go", "import cpp"},
        "javascript": {"semmle.code.cpp.", "semmle.python.", "import rust", "import go", "import cpp"},
    }
    wrong_lang_imports = _LANG_MODULES.get(language, set())
    has_cross_lang = any(imp in content for imp in wrong_lang_imports)

    # Check for forbidden isAdditionalFlowStep patterns
    flow_step_match = re.search(
        r"isAdditionalFlowStep.*?(?=\n\s*(?:predicate|module|from|select))",
        content, re.DOTALL,
    )
    has_forbidden_flow = False
    if flow_step_match:
        flow_step_body = flow_step_match.group(0)
        for forbidden in _FORBIDDEN_FLOW_PATTERNS:
            if forbidden.lower() in flow_step_body.lower():
                warnings.append(f"Forbidden isAdditionalFlowStep pattern: {forbidden}")
                has_forbidden_flow = True
                break

    # Check for source/sink anti-patterns
    for pattern, desc in _SOURCE_SINK_ANTI_PATTERNS:
        if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
            warnings.append(f"Source/sink anti-pattern: {desc}")

    if has_deprecated_config or has_deprecated_sanitizer:
        warnings.append("Uses deprecated API patterns")
    if has_cross_lang:
        warnings.append("Imports modules from different language")

    is_valid = (
        has_name and has_kind and has_select
        and not has_deprecated_config
        and not has_deprecated_sanitizer
        and not has_cross_lang
        and not has_forbidden_flow
    )
    return is_valid, warnings


def _compile_queries(codeql_path: Path, query_dir: Path) -> tuple[bool, str]:
    """Compile generated queries with CodeQL to check for syntax errors.

    Returns (success, error_output).
    """
    # Build search paths: CodeQL distribution qlpacks + user packages
    codeql_root = codeql_path.parent.parent
    search_paths = [str(codeql_root / "qlpacks")]
    user_packs = Path.home() / ".codeql" / "packages"
    if user_packs.exists():
        search_paths.append(str(user_packs))

    cmd = [str(codeql_path), "query", "compile", str(query_dir)]
    for sp in search_paths:
        cmd += ["--search-path", sp]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return True, ""
        return False, (result.stderr or result.stdout or "")[-2000:]
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, f"Compile check failed: {e}"


def _refine_queries(
    client: LLMClient,
    queries: list[CodeQLQueryFile],
    compile_errors: str,
    system_prompt: str,
    temperature: float,
    language: str = "rust",
) -> list[CodeQLQueryFile] | None:
    """Ask LLM to fix queries that failed CodeQL compilation.

    Uses plain text completion (not structured JSON) to avoid proxy
    compatibility issues with tool/function calling.
    """
    failed_queries = "\n\n---QUERY SEPARATOR---\n\n".join(
        f"// File: {q.filename}\n{q.content}" for q in queries
    )
    refinement_prompt = (
        f"The following CodeQL queries failed to compile:\n\n"
        f"{failed_queries}\n\n"
        f"CodeQL compilation errors:\n```\n{compile_errors}\n```\n\n"
        f"Fix ALL queries so they compile against the CodeQL {language} standard library. "
        f"Keep the same @name, @kind, @id annotations. "
        f"Use the modern `module Config implements DataFlow::ConfigSig` + "
        f"`TaintTracking::Global<Config>` pattern. "
        f"Do NOT use the deprecated `TaintTracking::Configuration` class. "
        f"Use `isBarrier` (not `isSanitizer`) for guard predicates. "
        f"Do NOT use `from` as a variable/parameter name (it is a reserved keyword). "
        f"Output each fixed query as a complete .ql file, separated by `---QUERY SEPARATOR---`."
    )
    try:
        response_text = client.complete(system_prompt, refinement_prompt, temperature)
    except Exception as e:
        logger.warning("Query refinement call failed: %s", str(e)[:200])
        return None

    # Parse the response: split by separator and extract queries
    parts = response_text.split("---QUERY SEPARATOR---")
    fixed_queries: list[CodeQLQueryFile] = []
    for i, part in enumerate(parts):
        content = part.strip()
        # Strip markdown fences
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
        content = content.strip()

        if _validate_query(content, language)[0]:
            # Extract filename from @id or use index
            id_match = re.search(r"@id\s+(\S+)", content)
            name_match = re.search(r"@name\s+(.+?)(?:\n|\*)", content)
            if id_match:
                safe_name = re.sub(r"[^\w-]", "_", id_match.group(1)) + ".ql"
            else:
                safe_name = f"refined_{i}.ql"
            fixed_queries.append(CodeQLQueryFile(filename=safe_name, content=content))

    if not fixed_queries:
        logger.warning("Query refinement produced no valid queries")
        return None
    return fixed_queries




def generate_codeql_queries(
    invariants: list[Invariant],
    repo_path: Path,
    language: str,
    client: LLMClient,
    temperature: float = 0.0,
    codeql_path: Path | None = None,
    manifest_entry_points: list[str] | None = None,
) -> Path | None:
    """Generate project-specific CodeQL queries via LLM with refinement loop.

    Uses embedded language-specific templates and project-specific taint
    specifications to generate queries. If codeql_path is provided, compiles
    queries and feeds errors back to the LLM for refinement (up to 2 rounds).

    Returns the path to the generated query pack directory, or None on failure.
    """
    # Filter to expressible invariants with taint specs
    expressible = [
        inv for inv in invariants
        if inv.codeql_expressible and inv.taint_specs
    ]
    if not expressible:
        logger.info("No codeql-expressible invariants with taint specs, skipping query generation")
        return None

    # Get language-specific template
    taint_template = _TAINT_TRACKING_TEMPLATES.get(
        language, _TAINT_TRACKING_TEMPLATES["rust"],
    )
    lang_import = _LANGUAGE_IMPORTS.get(language, _LANGUAGE_IMPORTS["rust"])

    # Extract project API patterns
    project_apis = _extract_project_apis(expressible)

    # Merge manifest entry points (ECALL/OCALL names) into project APIs
    if manifest_entry_points:
        existing = set(project_apis)
        for ep_name in manifest_entry_points:
            if ep_name not in existing:
                project_apis.append(ep_name)
        logger.info(
            "Merged %d manifest entry points into project APIs (total: %d)",
            len(manifest_entry_points), len(project_apis),
        )

    # Build taint specs JSON for prompt
    taint_specs_json = []
    for inv in expressible:
        for spec in inv.taint_specs:
            taint_specs_json.append({
                "invariant_id": inv.id,
                "source": spec.source,
                "sink": spec.sink,
                "sanitizer": spec.sanitizer,
                "taint_type": spec.taint_type,
                "description": spec.description,
                "family": inv.family.value,
            })

    # Get absence template for negative-flow queries
    absence_template = _ABSENCE_QUERY_TEMPLATES.get(
        language, _ABSENCE_QUERY_TEMPLATES.get("rust", ""),
    )

    # Build system prompt
    system_prompt = (
        "You are a CodeQL query generation expert. Generate ONE precise, compilable CodeQL query "
        f"for the {language} language that detects the TEE security pattern described below.\n\n"
        "CRITICAL API RULES for CodeQL 2.24+:\n"
        "- Use `module Config implements DataFlow::ConfigSig` with predicates "
        "`isSource`, `isSink`, `isBarrier` (NOT `isSanitizer`), "
        "then `module Flow = TaintTracking::Global<Config>` and `import Flow::PathGraph`.\n"
        "- Do NOT use the deprecated `TaintTracking::Configuration` class.\n"
        "- Do NOT use `TaintTracking::ConfigSig`. Use `DataFlow::ConfigSig`.\n"
        f"- ONLY import {language} language modules (e.g., `import {lang_import}`). "
        f"NEVER import modules from other languages.\n"
        "- Use `isBarrier` (not `isSanitizer`) for guards/sanitizers.\n"
        "- Include `isAdditionalFlowStep` for hash/crypto/update operations when tracking "
        "binding flows (key → hash → digest → report_data).\n\n"
        + _LANGUAGE_API_REFERENCES.get(language, _LANGUAGE_API_REFERENCES["rust"])
        + "\nSTRICTLY follow this structure. "
        "No other Call/Expr methods are needed beyond those listed in the API reference above.\n\n"
        "STRUCTURAL RULES:\n"
        "- Query metadata (@name, @description, @kind, @problem.severity, @id, @tags) MUST appear "
        "at the TOP of the file, BEFORE any import statements.\n"
        "- Use `@kind problem` for structural/absence queries (Binding, Guard). "
        "Use `@kind path-problem` for taint tracking queries (Flow, State, Leakage).\n"
        "- Do NOT wrap boolean expressions in `exists()`. `exists()` is for introducing "
        "variables (`exists(Type var | predicate)`), not for negating booleans. "
        "Use `not expr.matches(...)` instead of `not exists(expr.matches(...))`.\n"
        "- Do NOT use `from` as a variable/parameter name — it is a reserved keyword "
        "in CodeQL (used in `from ... where ... select`). Use `src`, `node1`, or "
        "`source_node` instead. Similarly avoid `where`, `select`, `import` as names.\n\n"
        "VULNERABILITY MODELING — the most critical part:\n"
        "- For Binding invariants (e.g., 'key must be bound to report_data'): the vulnerability "
        "is the ABSENCE of flow. Use a negative query: find report creation sites where NO identity "
        "key material reaches the report_data argument. Do NOT flag when key DOES flow to report_data.\n"
        "- For Guard invariants (e.g., 'verification missing'): find acceptance/registration sinks "
        "and check whether specific field comparisons (MRENCLAVE, MRSIGNER, ISVSVN, report_data, "
        "attributes, debug flag) are present. Report MISSING checks, not presence of verify functions. "
        "Consider using DataFlow::BarrierGuard for dominance checks.\n"
        "- For Flow invariants (e.g., 'untrusted data reaches trusted decision'): this IS positive "
        "taint tracking — data flows where it should not. Narrow sources to specific attacker-controlled "
        "types (request body extractors, OCALL returns, external file reads), not every function parameter. "
        "Narrow sinks to specific privileged operations, not broad name substrings.\n"
        "- Do NOT model 'verify_quote() flows to register_worker()' as a vulnerability. "
        "That is normal operation. Instead model 'register_worker accepts without checking specific fields'.\n\n"
        "SOURCE/SINK/BARRIER PRECISION:\n"
        "- Sources: must be specific to the vulnerability. Do NOT use broad patterns like matching every "
        "parameter or every call with 'key' in the name. Use concrete API names from project_apis.\n"
        "- Sinks: target specific security-sensitive operations, not broad substrings. E.g., for "
        "Binding queries, target `create_report` report_data argument specifically.\n"
        "- Barriers: must be value-aware. A barrier should only block flow when it processes the SAME "
        "value that would reach the sink. Do not treat names like 'validate', 'check', 'parse' as "
        "automatic barriers — they must validate the tainted value specifically.\n\n"
        "CANONICAL PATH MATCHING:\n"
        "- PREFER `call.getStaticTarget().(Function).getCanonicalPath().matches(\"%module%function%\")` "
        "over broad `call.getTargetName().toLowerCase().matches(\"%pattern%\")` when the module path is known.\n"
        "- Canonical path matching is more precise: it avoids matching unrelated functions with similar names.\n"
        "- Use broad name matching only as a fallback when canonical paths are unknown.\n\n"
        "isAdditionalFlowStep DISCIPLINE — STRICTLY ENFORCED:\n"
        "- ONLY include security-relevant crypto operations: hash, digest, sha, hmac, encrypt, sign, blake, keccak.\n"
        "- FORBIDDEN patterns (using ANY of these will cause query rejection): "
        "%clone%, %copy%, %as_ref%, %to_owned%, %into%, %from%, %update%, %extend%, %finalize%, "
        "%serialize%, %encode%, %decode%, %parse%, %to_vec%, %as_slice%, %to_string%, %unwrap%, %expect%.\n"
        "- These forbidden patterns are standard library operations that appear thousands of times. "
        "Including them destroys query precision.\n"
        "- If no security-relevant crypto operation is needed, OMIT isAdditionalFlowStep entirely.\n\n"
        "SOURCE/SINK ANTI-PATTERNS — DO NOT USE:\n"
        "- isSource matching %read% or %open% alone — too broad, matches every I/O call.\n"
        "- isSink matching %accept%, %apply%, %commit%, %register%, %save%, %write% alone — "
        "matches thousands of unrelated calls.\n"
        "- ALWAYS pair broad patterns with project-specific API names.\n\n"
        "PRECISION GUIDANCE:\n"
        "- Taint-tracking queries (@kind path-problem) are MORE PRECISE than structural queries (@kind problem) "
        "because they verify actual data flow paths rather than just checking for the presence/absence of function calls.\n"
        "- Prefer taint-tracking for Flow, State, and Leakage invariants — the DataFlow engine traces real paths.\n"
        "- Use structural (@kind problem) ONLY for Binding/Guard invariants where the vulnerability IS the absence "
        "of a required check. Even then, consider whether a taint-tracking query with isBarrier could model the guard "
        "more precisely.\n\n"
        "Each query must have @name, @kind, @id, and @problem.severity annotations. "
        "Use project-specific API names from the project_apis list. "
        "Output ONLY the CodeQL query — no explanation, no markdown fences."
    )

    # Generate one query per taint spec using simple text completion
    # (Structured JSON output with embedded CodeQL queries is too slow/error-prone for GLM)
    all_queries: list[CodeQLQueryFile] = []
    query_log: list[dict] = []  # Step 3.3: query type logging

    for idx, spec in enumerate(taint_specs_json):
        logger.info(
            "Generating CodeQL query %d/%d for %s (%s)",
            idx + 1, len(taint_specs_json),
            spec["invariant_id"], spec["family"],
        )

        # Select template based on invariant family
        is_binding_or_guard = spec["family"] in ("Binding", "Guard")
        ref_template = absence_template if is_binding_or_guard else taint_template
        template_label = "absence (negative flow)" if is_binding_or_guard else "taint tracking (positive flow)"

        query_prompt = (
            f"## Reference Template ({template_label})\n\n```codeql\n{ref_template}\n```\n\n"
            f"## Project APIs (MUST use at least one in each source/sink predicate)\n\n"
            + ("\n".join(f"- {a}" for a in project_apis) if project_apis else "No specific API patterns extracted.")
            + "\n\n"
            f"## Taint Specification\n\n"
            f"Generate a CodeQL {language} query for this taint spec:\n"
            f"```json\n{json.dumps(spec, indent=2)}\n```\n\n"
            f"MANDATORY: Each isSource and isSink predicate MUST reference at least one concrete "
            f"project API name from the list above. Do NOT rely solely on broad wildcard patterns "
            f"like `%key%` or `%verify%`. Use at least one specific function name from Project APIs "
            f"in each predicate. You MAY include one broad wildcard as a secondary fallback pattern, "
            f"but the primary pattern must be specific.\n\n"
        )
        if is_binding_or_guard:
            query_prompt += (
                "IMPORTANT: This is a Binding or Guard invariant. The vulnerability is the ABSENCE of "
                "a required flow or check, NOT the presence of flow.\n\n"
                "STRUCTURE (follow EXACTLY — do NOT deviate):\n"
                "1. Define `module ExpectedFlowConfig implements DataFlow::ConfigSig` with isSource, "
                "isSink, isBarrier predicates using ONLY `call.getTargetName()` for matching.\n"
                "2. Define `module ExpectedFlow = TaintTracking::Global<ExpectedFlowConfig>`.\n"
                "3. Main query: find target calls using `call.getTargetName()`, then use "
                "`not exists(DataFlow::Node source, DataFlow::Node sink | "
                "ExpectedFlowConfig::isSource(source) and ExpectedFlowConfig::isSink(sink) and "
                "ExpectedFlow::flow(source, sink))` to check that NO expected flow exists.\n"
                "4. Use `@kind problem` (NOT `@kind path-problem`).\n\n"
                "DO NOT attempt control-flow dominance analysis. DO NOT use getEnclosingExpr, "
                "getEnclosingStmt, exprNode, or any method not listed in the API reference above. "
                "The `not exists(... ExpectedFlow::flow(...))` pattern is sufficient for absence detection.\n"
            )
        else:
            query_prompt += (
                "- Use `@kind path-problem` for taint tracking specs.\n"
                "- Narrow sources to specific attacker-controlled entry points (e.g., HTTP request body "
                "extractors, OCALL return values, external file reads). Do NOT use every function parameter.\n"
                "- Narrow sinks to specific privileged operations with concrete API names. "
                "Do NOT match broad substrings like 'key', 'execute', 'dispatch'.\n"
                "- Barriers must validate the SAME tainted value, not just have 'validate' in their name.\n"
            )
        query_prompt += (
            f"- Use the project API names listed above in your source/sink/barrier predicates.\n"
            f"- Prefer canonical path matching over wildcard name matching where possible.\n"
            f"- Set @id to `tee-audit/generated/{spec['invariant_id'].lower()}-{spec['family'].lower()}`.\n"
            f"- Output ONLY the .ql file content. No markdown, no explanation."
        )

        try:
            response_text = client.complete(system_prompt, query_prompt, temperature)
        except Exception as e:
            logger.warning(
                "Query %d/%d for %s failed: %s",
                idx + 1, len(taint_specs_json), spec["invariant_id"], str(e)[:200],
            )
            continue

        # Strip markdown code fences if present
        content = response_text.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
        content = content.strip()

        # Sanitize: strip forbidden isAdditionalFlowStep patterns
        content = _sanitize_query(content, language)

        is_valid, val_warnings = _validate_query(content, language)
        if is_valid:
            safe_name = f"{spec['invariant_id'].lower()}_{spec['family'].lower()}.ql"
            all_queries.append(CodeQLQueryFile(filename=safe_name, content=content))
            logger.info("Query %d/%d generated successfully: %s", idx + 1, len(taint_specs_json), safe_name)
            query_log.append({
                "invariant_id": spec["invariant_id"],
                "query_type": "structural" if is_binding_or_guard else "taint",
                "reasoning": f"{'Absence/negative flow for Binding/Guard family' if is_binding_or_guard else 'Positive taint tracking for data flow verification'}",
                "template": template_label,
                "filename": safe_name,
                "status": "generated",
            })
        else:
            logger.warning("Query %d/%d for %s failed validation, skipping", idx + 1, len(taint_specs_json), spec["invariant_id"])
            query_log.append({
                "invariant_id": spec["invariant_id"],
                "query_type": "structural" if is_binding_or_guard else "taint",
                "reasoning": f"Query failed validation: {'; '.join(val_warnings) if val_warnings else 'unknown'}",
                "template": template_label,
                "filename": f"{spec['invariant_id'].lower()}_{spec['family'].lower()}.ql",
                "status": "validation_failed",
            })

    if not all_queries:
        raise RuntimeError("LLM generated no valid CodeQL queries")

    # Validate and write queries — clear old generated files first
    output_dir = repo_path.parent / "artifact" / "codeql-queries" / "generated" / language
    output_dir.mkdir(parents=True, exist_ok=True)
    for old_file in output_dir.glob("*.ql"):
        old_file.unlink()
        logger.debug("Removed stale query: %s", old_file.name)
    for old_file in output_dir.glob("*.qls"):
        old_file.unlink()
        logger.debug("Removed stale suite: %s", old_file.name)

    valid_count = 0
    for qf in all_queries:
        # Sanitize before final write
        qf = CodeQLQueryFile(filename=qf.filename, content=_sanitize_query(qf.content, language))
        is_valid, val_warnings = _validate_query(qf.content, language)
        if not is_valid:
            logger.warning("Skipping invalid query %s: %s", qf.filename, "; ".join(val_warnings))
            continue

        safe_name = re.sub(r"[^\w-]", "_", qf.filename)
        if not safe_name.endswith(".ql"):
            safe_name += ".ql"
        (output_dir / safe_name).write_text(qf.content)
        valid_count += 1

    if valid_count == 0:
        raise RuntimeError("No valid CodeQL queries generated after validation — all queries failed structure check")

    # Generate qlpack.yml
    pack_dep = _LANGUAGE_PACKS.get(language, _LANGUAGE_PACKS["rust"])
    qlpack = f"""name: tee-generated-queries
version: 0.1.0
dependencies:
  {pack_dep}: "*"
"""
    (output_dir / "qlpack.yml").write_text(qlpack)

    # Refinement loop: compile queries and fix errors via LLM
    if codeql_path is not None:
        for round_num in range(1, 3):  # max 2 refinement rounds
            success, errors = _compile_queries(codeql_path, output_dir)
            if success:
                logger.info("All queries compiled successfully (round %d)", round_num)
                break

            logger.warning(
                "Query compilation failed (round %d), asking LLM to refine",
                round_num,
            )
            current_queries = [
                CodeQLQueryFile(
                    filename=f.name,
                    content=f.read_text(errors="ignore"),
                )
                for f in sorted(output_dir.glob("*.ql"))
            ]
            refined = _refine_queries(
                client, current_queries, errors, system_prompt, temperature,
                language,
            )
            if refined is None:
                logger.warning("LLM refinement returned no queries, keeping originals")
                break

            if len(refined) < len(current_queries):
                logger.warning(
                    "Refinement returned %d queries (submitted %d), some may be lost",
                    len(refined), len(current_queries),
                )

            # Overwrite with refined queries
            new_count = 0
            for qf in refined:
                # Sanitize refined queries too
                sanitized = CodeQLQueryFile(filename=qf.filename, content=_sanitize_query(qf.content, language))
                if not _validate_query(sanitized.content, language)[0]:
                    continue
                safe_name = re.sub(r"[^\w-]", "_", sanitized.filename)
                if not safe_name.endswith(".ql"):
                    safe_name += ".ql"
                (output_dir / safe_name).write_text(sanitized.content)
                new_count += 1

            if new_count > 0:
                logger.info("Refined %d queries (round %d)", new_count, round_num)
                # Update qlpack dependencies in case they changed
                (output_dir / "qlpack.yml").write_text(qlpack)
            else:
                logger.warning("No valid queries after refinement, keeping originals")
                break
        else:
            logger.warning("Query refinement exhausted after 2 rounds")

    # Generate query suite (CodeQL .qls format: one `- query:` per file)
    ql_files = sorted(output_dir.glob("*.ql"))
    suite_lines = ["# Auto-generated query suite"]
    for ql in ql_files:
        suite_lines.append(f"- query: ./{ql.name}")
    suite_path = output_dir / "tee-generated.qls"
    suite_path.write_text("\n".join(suite_lines))

    logger.info(
        "Generated %d valid CodeQL queries for %s at %s",
        valid_count, language, output_dir,
    )

    # Write query generation log
    if query_log:
        log_path = output_dir / "query_generation_log.json"
        log_path.write_text(json.dumps(query_log, indent=2))
        logger.info("Query generation log written to %s (%d entries)", log_path, len(query_log))

    return output_dir
