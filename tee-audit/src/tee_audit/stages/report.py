"""Stage 6: Report Assembly — build final audit report."""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage6Input, Stage6Output
from tee_audit.llm.client import LLMClient
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.utils.call_graph import classify_code_location
from tee_audit.models.finding import Finding, Severity, TaxonomyCategory, TrustPathTier
from tee_audit.models.report import DashboardEntry, DiagramType, MermaidDiagram, Report, TaxonomySummaryEntry, TrustBoundaryRow

logger = logging.getLogger(__name__)


class ReportResponse(BaseModel):
    """Wrapper for LLM report narrative response."""

    executive_summary: str
    methodology_notes: str


class ArchitectureDiagramResponse(BaseModel):
    """LLM-generated architecture diagram with text context."""

    architecture_summary: str
    trust_boundary_table: list[dict[str, str]]
    mermaid_code: str


def _build_dashboard(findings: list, tee_relevant_only: bool = False) -> list[DashboardEntry]:
    """Build severity × trust-path-tier dashboard matrix deterministically."""
    if tee_relevant_only:
        findings = [f for f in findings if getattr(f, 'is_tee_relevant', True)]
    counts: Counter[tuple[str, str]] = Counter()
    for f in findings:
        counts[(f.severity.value, f.trust_path_tier.value)] += 1

    entries = []
    for severity in Severity:
        for tier in TrustPathTier:
            count = counts.get((severity.value, tier.value), 0)
            if count > 0:
                entries.append(DashboardEntry(severity=severity, trust_path_tier=tier, count=count))
    return entries


def _sanitize_id(text: str) -> str:
    """Sanitize text for use as a Mermaid node ID."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', text).strip('_') or 'node'


def _sanitize_label(text: str, max_len: int = 0) -> str:
    """Escape characters that break Mermaid label syntax.

    If max_len > 0, truncate at word boundary to fit.
    """
    s = text.replace('"', "'").replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    if max_len > 0 and len(s) > max_len:
        cut = s[:max_len - 3].rfind(" ")
        if cut > max_len // 2:
            s = s[:cut] + "..."
        else:
            s = s[:max_len - 3] + "..."
    return s


def _build_architecture_diagram(
    key_components: list[str], fingerprint,
) -> MermaidDiagram:
    """Build a flowchart TD showing system architecture with trust boundaries."""
    lines = ["flowchart TD"]

    tee_styles = {
        "SGX": "fill:#ff6b6b,stroke:#333,color:#fff",
        "TDX": "fill:#4ecdc4,stroke:#333,color:#fff",
        "Nitro": "fill:#45b7d1,stroke:#333,color:#fff",
        "SEV_SNP": "fill:#96ceb4,stroke:#333,color:#fff",
        "ARM_TZ": "fill:#feca57,stroke:#333,color:#fff",
        "CVM": "fill:#ff9ff3,stroke:#333,color:#fff",
    }

    # Classify components into functional layers
    _LAYER_KEYWORDS = {
        "Core Logic": ["library", "verification", "verify", "core", "engine", "runtime", "enclave"],
        "Crypto": ["cryptograph", "crypto", "hash", "signature", "ring", "openssl", "webpki", "tls"],
        "Network/IO": ["collateral", "fetch", "http", "network", "rpc", "api client", "pccs"],
        "FFI/Bindings": ["ffi", "binding", "wrapper", "c header", "wasm", "cgo"],
        "Interface": ["cli", "tool", "command", "sdk", "interface"],
    }

    layers: dict[str, list[tuple[str, str]]] = {}  # layer_name -> [(id, label)]
    node_count = 0

    for comp in key_components:
        comp_lower = comp.lower()
        assigned = False
        for layer_name, keywords in _LAYER_KEYWORDS.items():
            if any(kw in comp_lower for kw in keywords):
                layers.setdefault(layer_name, [])
                nid = f"comp_{node_count}"
                # Extract short name from component description
                short_name = comp.split(" — ")[0].split(" - ")[0] if " — " in comp or " - " in comp else comp
                if len(short_name) > 70:
                    short_name = short_name[:67] + "..."
                layers[layer_name].append((nid, short_name))
                node_count += 1
                assigned = True
                break
        if not assigned:
            layers.setdefault("Other", [])
            nid = f"comp_{node_count}"
            short_name = comp.split(" — ")[0].split(" - ")[0] if " — " in comp or " - " in comp else comp
            if len(short_name) > 70:
                short_name = short_name[:67] + "..."
            layers["Other"].append((nid, short_name))
            node_count += 1

    # External TEE actors at the top
    platforms = fingerprint.tee_platforms if fingerprint else {}
    tee_ids: list[str] = []
    if platforms:
        lines.append('    subgraph teeActors["TEE Platforms (External)"]')
        for platform in platforms:
            pid = f"tee_{node_count}"
            lines.append(f'        {pid}["{_sanitize_label(platform)}"]')
            style = tee_styles.get(platform)
            if style:
                lines.append(f"        style {pid} {style}")
            tee_ids.append(pid)
            node_count += 1
        lines.append("    end")
        lines.append("")

    # Render layers as subgraphs
    layer_order = ["Core Logic", "Crypto", "Network/IO", "FFI/Bindings", "Interface", "Other"]
    layer_ids: list[str] = []
    for layer_name in layer_order:
        if layer_name not in layers:
            continue
        sg_id = f"sg_{layer_name.replace('/', '_').replace(' ', '_').lower()}"
        lines.append(f'    subgraph {sg_id}["{layer_name}"]')
        for nid, label in layers[layer_name]:
            lines.append(f'        {nid}["{_sanitize_label(label)}"]')
        lines.append("    end")
        lines.append("")
        layer_ids.append(sg_id)

    # Draw connections: TEE actors → Core Logic
    if tee_ids and "Core Logic" in layers:
        for tid in tee_ids:
            for nid, _ in layers["Core Logic"][:1]:
                lines.append(f"    {tid} -.->|attestation quote| {nid}")

    # Draw connections between adjacent layers
    layer_list = [layers[l] for l in layer_order if l in layers]
    for i in range(len(layer_list) - 1):
        last_in_prev = layer_list[i][-1][0]
        first_in_next = layer_list[i + 1][0][0]
        lines.append(f"    {last_in_prev} --> {first_in_next}")

    # Chain components within each layer
    for layer_name in layer_order:
        if layer_name not in layers:
            continue
        nodes = layers[layer_name]
        for i in range(len(nodes) - 1):
            lines.append(f"    {nodes[i][0]} --> {nodes[i + 1][0]}")

    # Critical paths subgraph
    critical_paths = getattr(fingerprint, "critical_paths", []) if fingerprint else []
    if critical_paths:
        lines.append("")
        lines.append('    subgraph critPaths["Critical Paths"]')
        for cp in critical_paths:
            cp_id = _sanitize_id(cp)
            lines.append(f'        {cp_id}["{_sanitize_label(cp)}"]')
        lines.append("    end")

    # Trust boundary annotation
    if layers:
        lines.append("")
        lines.append('    subgraph trustBoundary["Trust Boundary"]')
        lines.append('        tb_note["All components run in UNTRUSTED context unless noted"]')
        lines.append("    end")

    if node_count == 0:
        lines.append('    nodata["No architecture data available"]')

    return MermaidDiagram(
        diagram_type=DiagramType.ARCHITECTURE,
        title="System Architecture with Trust Boundaries",
        mermaid_code="\n".join(lines),
    )


def _build_trust_path_diagram(invariants: list, fingerprint) -> MermaidDiagram:
    """Build a graph showing trust paths with trusted/untrusted boundary."""
    lines = ["graph LR"]

    tier_styles = {
        "core": "fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold",
        "adjacent": "fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold",
        "peripheral": "fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e",
    }

    if not invariants:
        lines.append('    nodata["No invariant data available"]')
        return MermaidDiagram(
            diagram_type=DiagramType.TRUST_PATH,
            title="Trust Path Diagram",
            mermaid_code="\n".join(lines),
        )

    # Deduplicate trust path endpoints into distinct roles
    role_nodes: dict[str, tuple[str, str]] = {}  # normalized_name -> (node_id, tier)
    node_count = 0
    edge_count = 0

    def _classify_node(label: str) -> str:
        """Classify a single node by its label content."""
        t = label.lower()
        # Core: enclave/TEE boundary nodes
        core_kw = ["enclave", "tee ", "sgx", "tdx", "mrenclave", "mrsigner",
                    "pcr", "measurement", "report_data", "attestation",
                    "quote", "qe identity", "qe certification", "cpusvn",
                    "isvsvn", "isv_prod", "isv_svn"]
        # Adjacent: host/network/crypto boundary nodes
        adj_kw = ["collateral", "certificate", "cert", "crl", "pccs", "tcb",
                  "fetch", "chain", "webpki", "crypto",
                  "qvl", "verifier", "verify", "parser", "comparison",
                  "validity", "decision", "result"]
        # Peripheral: application/FFI boundary nodes
        peri_kw = ["binding", "wasm", "ffi", "cli", "application", "config",
                   "dapp", "smart contract", "oracle", "endpoint"]

        # Check most specific first
        if any(kw in t for kw in peri_kw):
            return "peripheral"
        if any(kw in t for kw in core_kw):
            return "core"
        if any(kw in t for kw in adj_kw):
            return "adjacent"
        return "adjacent"

    for inv in invariants:
        parts = re.split(r'\s*→\s*|\s*->\s*', inv.trust_path)
        parts = [p.strip() for p in parts if p.strip()]

        chain_ids: list[str] = []
        for part in parts:
            norm = part.lower().strip()
            if norm in role_nodes:
                chain_ids.append(role_nodes[norm][0])
            else:
                nid = f"role_{node_count}"
                label = _sanitize_label(part, max_len=60)
                tier = _classify_node(part)
                lines.append(f'    {nid}["{label}"]')
                style = tier_styles.get(tier)
                if style:
                    lines.append(f"    style {nid} {style}")
                role_nodes[norm] = (nid, tier)
                chain_ids.append(nid)
                node_count += 1

        # Draw edge with invariant ID label
        for i in range(len(chain_ids) - 1):
            lines.append(f"    {chain_ids[i]} -->|{inv.id}| {chain_ids[i + 1]}")
            edge_count += 1

    if node_count == 0:
        lines.append('    nodata["No trust path data available"]')

    # Legend
    lines.append("")
    lines.append('    subgraph legend["Trust Tier Legend"]')
    lines.append('        l1["🔒 Core — enclave/TEE boundary"]')
    lines.append('        style l1 fill:#d4edda,stroke:#28a745,color:#1a1a2e')
    lines.append('        l2["⚠️ Adjacent — host/OS boundary"]')
    lines.append('        style l2 fill:#f8d7da,stroke:#dc3545,color:#1a1a2e')
    lines.append('        l3["🌐 Peripheral — network/config boundary"]')
    lines.append('        style l3 fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e')
    lines.append("    end")

    return MermaidDiagram(
        diagram_type=DiagramType.TRUST_PATH,
        title="Trust Path & Boundary Diagram",
        mermaid_code="\n".join(lines),
    )


def _build_data_flow_diagram(
    dossier_sections: dict[str, str], fingerprint,
    invariants: list | None = None,
) -> MermaidDiagram:
    """Build a flowchart LR showing data flow between trust artifact categories."""
    lines = ["flowchart LR"]

    tier_styles = {
        "core": "fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold",
        "adjacent": "fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold",
        "peripheral": "fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e",
    }

    # Classify node tier based on label content
    def _classify(label: str) -> str:
        t = label.lower()
        if any(kw in t for kw in ["binding", "wasm", "ffi", "cli", "application",
                                    "config", "dapp", "smart contract", "oracle", "endpoint"]):
            return "peripheral"
        if any(kw in t for kw in ["enclave", "tee", "sgx", "tdx", "quote", "attestation",
                                    "mrenclave", "mrsigner", "pcr", "report_data",
                                    "qe identity", "qe certification", "cpusvn", "isvsvn"]):
            return "core"
        return "adjacent"

    # Build nodes from invariant sources and sinks
    node_map: dict[str, str] = {}  # normalized label -> node_id
    edges: list[tuple[str, str, str]] = []  # (from_id, to_id, label)
    node_count = 0

    if invariants:
        for inv in invariants:
            # Extract short source/sink descriptions
            src_labels = [s.split("(")[0].strip()[:70] for s in inv.sources[:2]]
            sink_labels = [s.split("(")[0].strip()[:70] for s in inv.sinks[:2]]

            chain_labels = src_labels + sink_labels
            chain_ids: list[str] = []

            for label in chain_labels:
                norm = label.lower().strip()
                if norm in node_map:
                    chain_ids.append(node_map[norm])
                else:
                    nid = f"df_{node_count}"
                    node_map[norm] = nid
                    tier = _classify(label)
                    lines.append(f'    {nid}["{_sanitize_label(label, max_len=60)}"]')
                    style = tier_styles.get(tier)
                    if style:
                        lines.append(f"    style {nid} {style}")
                    chain_ids.append(nid)
                    node_count += 1

            # Connect source -> sink through the chain
            for i in range(len(chain_ids) - 1):
                edges.append((chain_ids[i], chain_ids[i + 1], inv.id))

    if node_count == 0:
        # Fallback: use fingerprint.trust_artifacts as nodes
        artifacts = getattr(fingerprint, "trust_artifacts", {}) or {} if fingerprint else {}
        for category, files in artifacts.items():
            norm = category.lower().strip()
            if norm in node_map:
                continue
            nid = f"df_{node_count}"
            node_map[norm] = nid
            tier = _classify(category)
            lines.append(f'    {nid}["{_sanitize_label(category)}"]')
            style = tier_styles.get(tier)
            if style:
                lines.append(f"    style {nid} {style}")
            node_count += 1

        # Connect adjacent artifact categories
        artifact_ids = [node_map[k.lower().strip()] for k in artifacts if k.lower().strip() in node_map]
        for i in range(len(artifact_ids) - 1):
            edges.append((artifact_ids[i], artifact_ids[i + 1], "data flow"))

    if node_count == 0:
        # Fallback: use tee_platforms as nodes
        platforms = getattr(fingerprint, "tee_platforms", {}) or {} if fingerprint else {}
        for platform in platforms:
            norm = platform.lower().strip()
            if norm in node_map:
                continue
            nid = f"df_{node_count}"
            node_map[norm] = nid
            tier = _classify(platform)
            lines.append(f'    {nid}["{_sanitize_label(platform)}"]')
            style = tier_styles.get(tier)
            if style:
                lines.append(f"    style {nid} {style}")
            node_count += 1

    # Add dossier keywords as edge annotations
    if dossier_sections:
        keywords_found: set[str] = set()
        tee_keywords = ["enclave", "attestation", "seal", "unseal", "quote", "measurement",
                         "ecall", "ocall", "trusted", "untrusted"]
        for section_text in dossier_sections.values():
            text_lower = section_text.lower()
            for kw in tee_keywords:
                if kw in text_lower and kw not in keywords_found:
                    keywords_found.add(kw)

        if keywords_found and node_count > 0:
            # Add a keyword annotation node
            kw_text = ", ".join(sorted(keywords_found)[:5])
            kw_id = f"df_{node_count}"
            lines.append(f'    {kw_id}["Keywords: {_sanitize_label(kw_text)}"]')
            node_count += 1

    if node_count == 0:
        lines.append('    nodata["No data flow data available"]')

    # Add edges (deduplicate)
    seen_edges: set[tuple[str, str]] = set()
    for from_id, to_id, label in edges:
        key = (from_id, to_id)
        if key not in seen_edges:
            seen_edges.add(key)
            lines.append(f"    {from_id} -->|{label}| {to_id}")

    # Legend
    lines.append("")
    lines.append('    subgraph legend["Data Flow Legend"]')
    lines.append('        dl1["🔒 TEE/Core data"]')
    lines.append('        style dl1 fill:#d4edda,stroke:#28a745,color:#1a1a2e')
    lines.append('        dl2["⚠️ Verification/Host data"]')
    lines.append('        style dl2 fill:#f8d7da,stroke:#dc3545,color:#1a1a2e')
    lines.append('        dl3["🌐 Application/Network data"]')
    lines.append('        style dl3 fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e')
    lines.append("    end")

    return MermaidDiagram(
        diagram_type=DiagramType.DATA_FLOW,
        title="Data Flow Diagram",
        mermaid_code="\n".join(lines),
    )


def _build_trust_boundary_narrative(
    invariants: list,
    fingerprint,
    zone_map: "ZoneMap | None" = None,
) -> str:
    """Build a structured prose section describing the trust boundary.

    Replaces the deterministic trust-path Mermaid diagram with evidence-cited prose.
    """
    if not invariants:
        return "_No trust boundary data available from invariant analysis._"

    # Collect trust path roles and their connections
    path_roles: dict[str, set[str]] = {}  # role -> set of connected roles
    for inv in invariants:
        parts = re.split(r'\s*→\s*|\s*->\s*', inv.trust_path)
        parts = [p.strip() for p in parts if p.strip()]
        for i, part in enumerate(parts):
            path_roles.setdefault(part, set())
            if i > 0:
                path_roles[parts[i - 1]].add(part)
                path_roles[part].add(parts[i - 1])

    # Classify roles into trust zones
    enclave_roles: list[str] = []
    host_roles: list[str] = []
    boundary_roles: list[str] = []

    core_kw = ["enclave", "tee ", "sgx", "tdx", "mrenclave", "mrsigner",
                "pcr", "measurement", "report_data", "attestation", "quote"]
    adj_kw = ["collateral", "certificate", "cert", "pccs", "tcb", "verify",
              "verifier", "qvl", "fetch", "host", "untrusted"]

    for role in path_roles:
        t = role.lower()
        if any(kw in t for kw in core_kw):
            enclave_roles.append(role)
        elif any(kw in t for kw in adj_kw):
            host_roles.append(role)
        else:
            boundary_roles.append(role)

    # Build narrative
    paragraphs: list[str] = []

    # Opening: describe the trust boundary
    if enclave_roles and host_roles:
        enclaves = ", ".join(f"**{r}**" for r in enclave_roles[:5])
        hosts = ", ".join(f"**{r}**" for r in host_roles[:5])
        paragraphs.append(
            f"The trust boundary separates enclave-side components ({enclaves}) "
            f"from host-side components ({hosts}). "
            f"Data and control flow across this boundary via the invariants listed below."
        )
    elif enclave_roles:
        enclaves = ", ".join(f"**{r}**" for r in enclave_roles[:5])
        paragraphs.append(
            f"The trusted boundary centers on {enclaves}. "
            f"The analysis identified {len(invariants)} invariants governing "
            f"trust path integrity."
        )
    else:
        paragraphs.append(
            f"The analysis identified {len(invariants)} invariants "
            f"governing trust boundary integrity."
        )

    # Trust path descriptions
    paragraphs.append("")
    paragraphs.append("**Trust Paths Identified:**")
    seen_paths: set[str] = set()
    for inv in invariants:
        path_key = inv.trust_path.strip()
        if path_key not in seen_paths:
            seen_paths.add(path_key)
            # Cite the invariant ID
            paragraphs.append(f"- `{inv.id}`: {inv.trust_path} — {inv.description}")

    # Cross-boundary connections
    cross_zone_connections: list[str] = []
    for role in enclave_roles[:5]:
        for connected in path_roles.get(role, set()):
            if connected in host_roles:
                cross_zone_connections.append(f"{role} ↔ {connected}")

    if cross_zone_connections:
        paragraphs.append("")
        paragraphs.append("**Cross-Boundary Connections:**")
        for conn in cross_zone_connections[:8]:
            paragraphs.append(f"- {conn}")

    # Zone map context
    if zone_map and zone_map.zones:
        from tee_audit.utils.call_graph import TrustZone
        trusted = sum(1 for z in zone_map.zones.values() if z == TrustZone.TRUSTED)
        untrusted = sum(1 for z in zone_map.zones.values() if z == TrustZone.UNTRUSTED)
        paragraphs.append("")
        paragraphs.append(
            f"The zone classification covers {len(zone_map.zones)} files "
            f"({trusted} trusted, {untrusted} untrusted). "
            f"See the Source Code Zone Partition above for the full directory-level breakdown."
        )

    return "\n".join(paragraphs)


def _classify_flow_direction(trust_path: str) -> str:
    """Classify a trust path's direction across the trust boundary.

    Returns: "host_to_enclave", "enclave_to_host", "internal_enclave",
    "internal_host", or "cross_boundary" (ambiguous).
    """
    t = trust_path.lower()
    enclave_kw = ["enclave", "tee ", "sgx", "tdx", "sealed", "quote body",
                  "mrenclave", "mrsigner", "pRuntime enclave"]
    host_kw = ["host", "untrusted", "on-chain", "rpc", "http", "network",
               "filesystem", "pcs", "pccs", "blockchain", "client", "user"]

    # Split the path into segments
    segments = re.split(r'\s*→\s*|\s*->\s*', trust_path)
    segments = [s.strip() for s in segments if s.strip()]

    if len(segments) < 2:
        return "cross_boundary"

    first_is_enclave = any(kw in segments[0].lower() for kw in enclave_kw)
    first_is_host = any(kw in segments[0].lower() for kw in host_kw)
    last_is_enclave = any(kw in segments[-1].lower() for kw in enclave_kw)
    last_is_host = any(kw in segments[-1].lower() for kw in host_kw)

    if first_is_host and last_is_enclave:
        return "host_to_enclave"
    if first_is_enclave and last_is_host:
        return "enclave_to_host"
    if first_is_enclave and last_is_enclave:
        return "internal_enclave"
    if first_is_host and last_is_host:
        return "internal_host"

    # Check if ANY segment crosses the boundary
    has_enclave = any(any(kw in s.lower() for kw in enclave_kw) for s in segments)
    has_host = any(any(kw in s.lower() for kw in host_kw) for s in segments)
    if has_enclave and has_host:
        return "cross_boundary"
    if has_enclave:
        return "internal_enclave"
    if has_host:
        return "internal_host"

    return "cross_boundary"


def _build_data_flow_summary(
    dossier_sections: dict[str, str],
    fingerprint,
    invariants: list | None = None,
    zone_map: "ZoneMap | None" = None,
) -> str:
    """Build a cross-boundary data flow analysis.

    Focuses on which data flows cross the trust boundary and in which direction,
    rather than listing all sources/sinks (which duplicates invariant content).
    """
    paragraphs: list[str] = []

    if not invariants:
        if dossier_sections:
            tee_keywords: set[str] = set()
            important_kw = ["enclave", "attestation", "seal", "quote", "measurement"]
            for section_text in dossier_sections.values():
                text_lower = section_text.lower()
                for kw in important_kw:
                    if kw in text_lower:
                        tee_keywords.add(kw)
            if tee_keywords:
                paragraphs.append(
                    f"Data flow analysis identified TEE-relevant data categories: "
                    f"{', '.join(f'**{k}**' for k in sorted(tee_keywords))}. "
                    f"See individual findings for specific data flow evidence."
                )
                return "\n".join(paragraphs)
        return "_No data flow data available from invariant analysis._"

    # Classify each invariant's flow direction
    flows_by_dir: dict[str, list[tuple[str, str, str]]] = {
        "host_to_enclave": [],
        "enclave_to_host": [],
        "cross_boundary": [],
        "internal_enclave": [],
        "internal_host": [],
    }
    for inv in invariants:
        direction = _classify_flow_direction(inv.trust_path)
        src_label = inv.sources[0].split("(")[0].strip()[:60] if inv.sources else ""
        sink_label = inv.sinks[0].split("(")[0].strip()[:60] if inv.sinks else ""
        flows_by_dir[direction].append((src_label, sink_label, inv.id))

    # Opening summary
    boundary_flows = (
        flows_by_dir["host_to_enclave"]
        + flows_by_dir["enclave_to_host"]
        + flows_by_dir["cross_boundary"]
    )
    paragraphs.append(
        f"Of {len(invariants)} invariants, **{len(boundary_flows)}** involve data "
        f"crossing the trust boundary between enclave and host."
    )

    # Cross-boundary flow table
    dir_labels = {
        "host_to_enclave": ("**Host → Enclave**", "External data entering the TEE — highest validation burden"),
        "enclave_to_host": ("**Enclave → Host**", "TEE outputs and secrets leaving the enclave — leakage risk"),
        "cross_boundary": ("**Bidirectional**", "Flows crossing the boundary in both directions"),
    }
    for dir_key, (label, desc) in dir_labels.items():
        flows = flows_by_dir[dir_key]
        if not flows:
            continue
        paragraphs.append("")
        paragraphs.append(f"{label} ({len(flows)} flow{'s' if len(flows) != 1 else ''})")
        paragraphs.append(f"_{desc}_")
        for src, sink, inv_id in flows[:8]:
            flow_desc = f"**{src}** → **{sink}**" if src and sink else ""
            if flow_desc:
                paragraphs.append(f"- `{inv_id}`: {flow_desc}")
            else:
                paragraphs.append(f"- `{inv_id}`")

    # Enclave entry/exit points summary
    entry_points = flows_by_dir["host_to_enclave"]
    exit_points = flows_by_dir["enclave_to_host"]
    if entry_points or exit_points:
        paragraphs.append("")
        paragraphs.append("**Boundary Interface Summary:**")
        if entry_points:
            inv_ids = ", ".join(f"`{inv_id}`" for _, _, inv_id in entry_points)
            paragraphs.append(
                f"- **Enclave entry points** ({len(entry_points)}): "
                f"data enters TEE via {inv_ids}"
            )
        if exit_points:
            inv_ids = ", ".join(f"`{inv_id}`" for _, _, inv_id in exit_points)
            paragraphs.append(
                f"- **Enclave exit points** ({len(exit_points)}): "
                f"data leaves TEE via {inv_ids}"
            )

    # Internal flows (brief mention only)
    internal = flows_by_dir["internal_enclave"] + flows_by_dir["internal_host"]
    if internal:
        paragraphs.append("")
        inv_ids = ", ".join(f"`{inv_id}`" for _, _, inv_id in internal[:6])
        suffix = f" +{len(internal) - 6} more" if len(internal) > 6 else ""
        paragraphs.append(
            f"_Internal flows ({len(internal)}): {inv_ids}{suffix} "
            f"— these stay within a single zone and are covered by individual findings._"
        )

    return "\n".join(paragraphs)


class MermaidFixResponse(BaseModel):
    """LLM response for Mermaid diagram fix."""
    mermaid_code: str


def _sanitize_mermaid(mermaid: str) -> str:
    """Fix known LLM-generated Mermaid syntax issues deterministically."""
    # Strip markdown fences
    if mermaid.startswith("```mermaid"):
        mermaid = mermaid[len("```mermaid"):]
    if mermaid.startswith("```"):
        mermaid = mermaid[3:]
    if mermaid.endswith("```"):
        mermaid = mermaid[:-3]
    mermaid = mermaid.strip()

    # Decode Python-style unicode escapes
    for raw, char in [
        (r"\U0001F512", "\U0001F512"),  # 🔒
        (r"\U0001F310", "\U0001F310"),  # 🌐
        (r"\U0001F510", "\U0001F510"),  # 🔐
        (r"⚠️", "⚠️"),
    ]:
        mermaid = mermaid.replace(raw, char)

    # Fix \n in node labels [text\nmore] → [text<br>more]
    def _fix_node_newlines(m):
        return m.group(0).replace(r"\n", "<br>")
    mermaid = re.sub(r'\[[^\]]*\\n[^\]]*\]', _fix_node_newlines, mermaid)

    # Fix invalid link syntax: <---> → <-->
    mermaid = mermaid.replace("<--->", "<-->")
    mermaid = re.sub(r'<-{3,}>', '<-->', mermaid)

    # Fix class assignments: "class A B C name" → "class A,B,C name"
    def _fix_class(m):
        indent, nodes, classname = m.group(1), m.group(2), m.group(3)
        parts = nodes.split()
        if len(parts) > 1:
            return f'{indent}class {",".join(parts)} {classname}'
        return m.group(0)
    mermaid = re.sub(
        r'^([ \t]*)class ([A-Za-z0-9_]+(?: [A-Za-z0-9_]+)+) ([a-z]\w*)\s*$',
        _fix_class, mermaid, flags=re.MULTILINE,
    )

    # Fix parentheses in link labels: |text (gRPC)| → |text - gRPC|
    def _fix_link_parens(m):
        label = m.group(1)
        fixed = label.replace("(", "-").replace(")", "")
        return f"|{fixed}|"
    mermaid = re.sub(r'\|([^|]*\([^|)]*\)[^|]*)\|', _fix_link_parens, mermaid)

    return mermaid


def _validate_mermaid(mermaid: str) -> tuple[bool, str]:
    """Validate Mermaid syntax using mmdc CLI. Returns (valid, error_message)."""
    import shutil
    import subprocess
    import tempfile

    mmdc = shutil.which("mmdc")
    if not mmdc:
        # Also try npx
        npx = shutil.which("npx")
        if npx:
            mmdc = npx
        else:
            logger.warning(
                "mmdc not available — Mermaid validation skipped. "
                "Install with: npm install -g @mermaid-js/mermaid-cli"
            )
            return True, ""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
        f.write(mermaid)
        tmpfile = f.name

    try:
        cmd = [mmdc]
        if mmdc.endswith("npx"):
            cmd = [mmdc, "@mermaid-js/mermaid-cli"]
        cmd.extend(["-i", tmpfile, "-o", os.devnull])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr[:500]
    except FileNotFoundError:
        logger.warning("mmdc not found — Mermaid validation skipped")
        return True, ""
    except subprocess.TimeoutExpired:
        logger.warning("mmdc validation timed out — skipping")
        return True, ""
    finally:
        os.unlink(tmpfile)


def _build_llm_architecture_diagram(
    key_components: list[str],
    fingerprint,
    dossier_sections: dict[str, str],
    client: LLMClient,
    results_dir: Path,
    temperature: float = 0.0,
    zone_map=None,
) -> tuple[MermaidDiagram, list[TrustBoundaryRow]]:
    """Use LLM to generate an architecture diagram with real data flows and a text summary.

    Returns (MermaidDiagram with text_summary, trust_boundary_table).
    Falls back to deterministic diagram on LLM failure.
    """
    # Assemble context for the LLM
    dossier_text = "\n\n".join(
        f"### {section}\n{content[:800]}"
        for section, content in dossier_sections.items()
    )
    platforms = fingerprint.tee_platforms if fingerprint else {}
    roles = fingerprint.web3_roles if fingerprint else {}
    artifacts = fingerprint.trust_artifacts if fingerprint else {}

    components_text = "\n".join(f"- {c}" for c in key_components[:15])

    # Build zone_map summary for LLM alignment — group by top-level component
    zone_summary = ""
    if zone_map and zone_map.zones:
        # Aggregate by top-level directory (first 2 path segments)
        component_zones: dict[str, dict[str, int]] = {}
        for rel_path, zone in zone_map.zones.items():
            parts = rel_path.replace("\\", "/").split("/")
            # Use first 2 segments as component key
            key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
            component_zones.setdefault(key, {})
            label = zone.value if hasattr(zone, "value") else str(zone)
            component_zones[key][label] = component_zones[key].get(label, 0) + 1
        lines = []
        for comp, counts in sorted(component_zones.items()):
            dominant = max(counts, key=counts.get)
            total = sum(counts.values())
            lines.append(f"  {comp}/ — {dominant} ({total} files)")
        zone_summary = (
            f"## Zone Classification (from code analysis — use this for trust_boundary_table context)\n"
            f"```\n" + "\n".join(lines[:30]) + "\n```\n\n"
        )

    user_prompt = (
        f"## Project Context\n\n"
        f"TEE Platforms: {', '.join(platforms.keys()) if platforms else 'unknown'}\n"
        f"Web3 Roles: {', '.join(roles.keys()) if roles else 'unknown'}\n"
        f"Trust Artifacts: {', '.join(artifacts.keys()) if artifacts else 'unknown'}\n\n"
        f"## Key Components\n{components_text}\n\n"
        f"{zone_summary}"
        f"## Architecture Dossier\n{dossier_text[:4000]}\n\n"
        f"## Task\n\n"
        f"Generate:\n"
        f"1. **architecture_summary**: 2-4 sentences explaining the system architecture, "
        f"trust boundaries, and how data flows between trusted/untrusted zones.\n"
        f"2. **trust_boundary_table**: A list of rows, each with keys: "
        f"\"actor\", \"component\", \"context\" (trusted/untrusted/mixed), \"boundary_type\" "
        f"(e.g., \"enclave/host\", \"network\", \"storage\", \"crypto boundary\"). "
        f"Include 5-12 rows covering all major components. "
        f"**IMPORTANT**: The \"context\" column MUST match the Zone Classification above — "
        f"if a component's directory is classified as trusted in the zone data, its context "
        f"must be \"trusted\"; if untrusted, it must be \"untrusted\". Do NOT contradict the zone data.\n"
        f"3. **mermaid_code**: A `flowchart TD` Mermaid diagram showing the real data flow "
        f"between components. Use subgraphs for trust zones (\"Trusted Zone\", \"Untrusted Zone\"). "
        f"Label edges with the data that flows between components. "
        f"Node labels must be short (max 30 chars). Keep it under 25 nodes.\n\n"
        f"**CRITICAL — Color scheme (use classDef + class):**\n"
        f"```\n"
        f"classDef trusted fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold\n"
        f"classDef untrusted fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold\n"
        f"classDef extnet fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e\n"
        f"classDef crypto fill:#e2d5f1,stroke:#6a4c93,color:#1a1a2e\n"
        f"```\n"
        f"- Trusted nodes (enclave, root CA): apply `class NODE trusted`\n"
        f"- Untrusted nodes (verifier, host, bindings): apply `class NODE untrusted`\n"
        f"- Network/external nodes (PCCS, APIs): apply `class NODE extnet`\n"
        f"- Crypto nodes (signature, hash): apply `class NODE crypto`\n"
        f"- Use icons in subgraph titles: 🔒 for Trusted, ⚠️ for Untrusted, 🌐 for Network\n"
        f"- Use dashed lines (---) for trust anchors, solid lines (--> ) for data flow"
    )

    system_prompt = (
        "You are a security architect producing an architecture diagram for a TEE audit report. "
        "Be precise and grounded in the provided context. The diagram must show real data flows "
        "and trust boundaries, not generic boxes. Use Mermaid flowchart syntax. "
        "ALWAYS include the classDef styles and class assignments — the colors are critical for readability."
    )

    try:
        response = parse_with_retry(
            client, system_prompt, user_prompt, ArchitectureDiagramResponse,
            error_save_dir=results_dir, temperature=temperature,
        )

        mermaid = _sanitize_mermaid(response.mermaid_code)

        # Ensure classDef styles are present (LLM sometimes omits them)
        required_classdefs = (
            "classDef trusted fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold\n"
            "classDef untrusted fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold\n"
            "classDef extnet fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e\n"
            "classDef crypto fill:#e2d5f1,stroke:#6a4c93,color:#1a1a2e"
        )
        if "classDef trusted" not in mermaid:
            insert_pos = mermaid.find("class ")
            if insert_pos > 0:
                mermaid = mermaid[:insert_pos] + required_classdefs + "\n\n    " + mermaid[insert_pos:]
            else:
                mermaid = mermaid + "\n\n" + required_classdefs

        # Validate and optionally retry with LLM
        valid, error = _validate_mermaid(mermaid)
        max_retries = 2
        for attempt in range(max_retries):
            if valid:
                break
            logger.info("Mermaid validation failed (attempt %d/%d): %s", attempt + 1, max_retries, error[:200])
            fix_prompt = (
                f"The following Mermaid diagram has a syntax error:\n\n```\n{mermaid}\n```\n\n"
                f"Error from mermaid-cli:\n{error}\n\n"
                "Fix the syntax. Return ONLY valid Mermaid code — no markdown fences, no explanation."
            )
            try:
                fix_response = parse_with_retry(
                    client, "You fix broken Mermaid diagrams. Return only valid Mermaid code.", fix_prompt,
                    MermaidFixResponse, temperature=temperature,
                )
                mermaid = _sanitize_mermaid(fix_response.mermaid_code)
                valid, error = _validate_mermaid(mermaid)
            except Exception as fix_err:
                logger.warning("Mermaid LLM fix failed on attempt %d: %s", attempt + 1, str(fix_err)[:200])

        if not valid:
            logger.warning("Mermaid still invalid after %d retries: %s", max_retries, error[:200])

        def _sanitize_table_cell(text: str) -> str:
            """Sanitize LLM output for markdown table cells."""
            return text.replace("|", "/").replace("\n", " ").replace("—", "--").replace("–", "-").replace("→", "->").replace("←", "<-")

        table = [
            TrustBoundaryRow(
                actor=_sanitize_table_cell(row.get("actor", "Unknown")),
                component=_sanitize_table_cell(row.get("component", "Unknown")),
                context=_sanitize_table_cell(row.get("context", "mixed")),
                boundary_type=_sanitize_table_cell(row.get("boundary_type", "unknown")),
            )
            for row in response.trust_boundary_table
        ]

        diagram = MermaidDiagram(
            diagram_type=DiagramType.ARCHITECTURE,
            title="System Architecture with Trust Boundaries",
            mermaid_code=mermaid,
            text_summary=response.architecture_summary,
        )
        return diagram, table

    except Exception as e:
        logger.warning("LLM architecture diagram failed, using deterministic fallback: %s", str(e)[:200])
        fallback = _build_architecture_diagram(key_components, fingerprint)
        return fallback, []


SEVERITY_COLORS = {
    Severity.CRITICAL: "fill:#ff0000,stroke:#333,color:#fff",
    Severity.HIGH: "fill:#ffa500,stroke:#333,color:#fff",
    Severity.MEDIUM: "fill:#ffd700,stroke:#333,color:#000",
    Severity.LOW: "fill:#90ee90,stroke:#333,color:#000",
    Severity.INFO: "fill:#d3d3d3,stroke:#333,color:#000",
}


def _build_attack_path_diagrams(findings: list[Finding]) -> list[MermaidDiagram]:
    """Build one flowchart LR per finding with >= 2 attack_path steps."""
    diagrams: list[MermaidDiagram] = []

    for finding in findings:
        if len(finding.attack_path) < 2:
            continue

        lines = [f"flowchart LR"]
        fid = _sanitize_id(finding.id)
        lines.append(f'    title_{fid}["{_sanitize_label(finding.title)}"]')

        step_ids: list[str] = []
        for i, step in enumerate(finding.attack_path):
            sid = f"{fid}_s{i}"
            label = _sanitize_label(step[:80] + "..." if len(step) > 80 else step)
            lines.append(f'    {sid}["{label}"]')
            step_ids.append(sid)

            # Annotate with code location if available
            if finding.code_locations and i < len(finding.code_locations):
                loc = finding.code_locations[i]
                loc_label = _sanitize_label(f"{loc.file}:{loc.line}" if loc.line else loc.file)
                lines.append(f'    {sid} -.- loc_{sid}["{loc_label}"]')

        for i in range(len(step_ids) - 1):
            lines.append(f"    {step_ids[i]} --> {step_ids[i + 1]}")

        # Apply severity color to all step nodes
        color = SEVERITY_COLORS.get(finding.severity)
        if color:
            for sid in step_ids:
                lines.append(f"    style {sid} {color}")

        diagrams.append(MermaidDiagram(
            diagram_type=DiagramType.ATTACK_PATH,
            title=f"Attack Path: {finding.id} - {finding.title}",
            mermaid_code="\n".join(lines),
        ))

    return diagrams


def _build_taxonomy_summary(findings: list[Finding]) -> list[TaxonomySummaryEntry]:
    """Build taxonomy summary from TEE-relevant findings grouped by category."""
    category_map: dict[TaxonomyCategory, list[str]] = {}
    for f in findings:
        if not f.is_tee_relevant or not f.tee_category:
            continue
        category_map.setdefault(f.tee_category, []).append(f.id)

    entries = []
    for category in TaxonomyCategory:
        ids = category_map.get(category, [])
        if ids:
            entries.append(TaxonomySummaryEntry(category=category, count=len(ids), finding_ids=ids))
    return entries


def _render_invocation_chain_text(
    hops: list,
    lines: list[str],
    zone_map: "ZoneMap | None" = None,
) -> None:
    """Render invocation chain as structured text with zone tags and boundary markers.

    Format per hop:
        [ZONE] file:line  caller → callee  **CROSS**
    """
    if not hops:
        return

    # Determine zone source annotation
    zone_sources: set[str] = set()
    for hop in hops:
        if hasattr(hop, "zone_source") and hop.zone_source and hop.zone_source != "unknown":
            zone_sources.add(hop.zone_source)
    source_label = f" (zone source: {', '.join(sorted(zone_sources))})" if zone_sources else ""

    lines.append(f"**Cross-File Call Chain**{source_label}:")
    lines.append("```")

    for i, hop in enumerate(hops):
        raw_zone = (hop.source_zone or "unknown").lower()
        if raw_zone in ("", "unknown"):
            zone_tag = "[???       ]"
        elif raw_zone == "trusted":
            zone_tag = "[ENCLAVE   ]"
        elif raw_zone == "untrusted":
            zone_tag = "[HOST      ]"
        else:
            zone_tag = f"[{raw_zone.upper():<10}]"

        file_loc = f"{hop.file}:{hop.line or '?'}"
        caller = hop.caller_function or hop.description.split("(")[0].strip()
        callee = (f"{hop.callee_module}::" if hop.callee_module else "") + hop.callee_name
        arrow = f"{caller} → {callee}"

        # Boundary crossing marker
        cross_marker = ""
        if hop.crosses_boundary:
            cross_marker = "  <-- BOUNDARY CROSSING"

        lines.append(f"{zone_tag} {file_loc}  {arrow}{cross_marker}")

    lines.append("```")
    lines.append("")


def _resolve_file_path(repo_path: Path, file_rel: str) -> Path | None:
    """Resolve a potentially inaccurate file path to an actual file on disk.

    Tries exact match first, then fuzzy matching by filename component.
    """
    if not file_rel or file_rel == "unknown":
        return None

    # Exact match
    target = repo_path / file_rel
    if target.exists():
        return target

    # Fuzzy: try matching just the filename (last path component)
    filename = file_rel.split("/")[-1]
    if filename and filename != file_rel:
        for i, match in enumerate(repo_path.rglob(filename)):
            if i >= 10:
                break
            if match.is_file():
                return match

    # Fuzzy: try stem match (without extension) — handles e.g. .c vs .h confusion
    stem = Path(filename).stem
    if stem and len(stem) > 3:
        for i, match in enumerate(repo_path.rglob(f"{stem}*")):
            if i >= 10:
                break
            if match.is_file() and not match.name.startswith("."):
                return match

    return None


def _read_source_context(repo_path: Path, file_rel: str, line_num: int | None, context_lines: int = 10) -> str | None:
    """Read source context around a line number from the repo.

    Uses fuzzy path resolution when exact path doesn't exist.
    """
    resolved = _resolve_file_path(repo_path, file_rel)
    if resolved is None:
        return None
    try:
        all_lines = resolved.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not all_lines:
        return None
    center = (line_num or len(all_lines)) - 1
    center = min(max(center, 0), len(all_lines) - 1)
    start = max(0, center - context_lines)
    end = min(len(all_lines), center + context_lines + 1)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == center else "   "
        snippet_lines.append(f"{marker} {i + 1:4d} | {all_lines[i]}")
    return "\n".join(snippet_lines)


def _find_key_line(repo_path: Path, rel_path: str, keywords: str) -> int | None:
    """Find the first line number matching a keyword pattern in a file."""
    target = repo_path / rel_path
    if not target.exists():
        return None
    try:
        content = target.read_text(errors="ignore")
    except OSError:
        return None
    pattern = re.compile(keywords, re.IGNORECASE)
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            return i
    return None


def _render_zone_partition(zone_map: "ZoneMap", key_components: list[str] | None = None) -> str:
    """Render a tree-style directory zone partition with emoji indicators.

    Zone indicators: 🟢 Trusted (enclave), 🔴 Untrusted (host), 🟡 Mixed (boundary)
    Directories with a single zone show a simplified label; mixed dirs expand to
    show individual files with per-file zone indicators.
    """
    from tee_audit.utils.call_graph import TrustZone

    # Group files by parent directory
    dir_files: dict[str, list[tuple[str, str]]] = {}  # dir -> [(filename, zone)]
    dir_reasoning: dict[str, list[str]] = {}  # dir -> [reasoning strings]

    for fpath, zone in zone_map.zones.items():
        zv = zone.value if isinstance(zone, TrustZone) else str(zone)
        parts = fpath.replace("\\", "/").split("/")
        parent = "/".join(parts[:-1]) if len(parts) > 1 else "(root)"
        filename = parts[-1]
        dir_files.setdefault(parent, []).append((filename, zv))
        # Collect LLM reasoning for descriptions
        reasoning = zone_map.llm_reasoning.get(fpath, "")
        if reasoning:
            dir_reasoning.setdefault(parent, []).append(reasoning)

    if not dir_files:
        return "_No zone classification data available._"

    # Build a tree structure from directory paths
    # Group by top-level component (first path segment)
    top_level: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for dir_path, files in sorted(dir_files.items()):
        parts = dir_path.split("/")
        top = parts[0] if parts else "(root)"
        top_level.setdefault(top, {})[dir_path] = files

    EMOJI = {"trusted": "🟢", "untrusted": "🔴", "mixed": "🟡"}
    LABEL = {"trusted": "Trusted", "untrusted": "Untrusted", "mixed": "Mixed"}

    def _dir_zone_key(files: list[tuple[str, str]]) -> str:
        zones = set(z for _, z in files)
        if len(zones) == 1:
            return zones.pop()
        return "mixed"

    def _dir_summary(files: list[tuple[str, str]]) -> str:
        zone_key = _dir_zone_key(files)
        counts: dict[str, int] = {}
        for _, z in files:
            counts[z] = counts.get(z, 0) + 1
        total = len(files)
        if zone_key != "mixed":
            return f"{EMOJI[zone_key]} {LABEL[zone_key]} ({total} file{'s' if total != 1 else ''})"
        t = counts.get("trusted", 0)
        u = counts.get("untrusted", 0)
        m = counts.get("mixed", 0)
        parts = []
        if t:
            parts.append(f"{t} trusted")
        if u:
            parts.append(f"{u} untrusted")
        if m:
            parts.append(f"{m} mixed")
        return f"{EMOJI['mixed']} Mixed ({', '.join(parts)})"

    # Detect if all reasoning is identical (project-level, not per-directory)
    all_reasoning_texts = set()
    for reasons in dir_reasoning.values():
        all_reasoning_texts.update(reasons)
    has_unique_descriptions = len(all_reasoning_texts) > 1

    # Heuristic directory name → description mapping
    _DIR_DESC = {
        "src": "", "lib": "library", "pkg": "package",
        "bin": "binaries", "cmd": "CLI commands", "cli": "CLI interface",
        "api": "API definitions", "server": "server logic", "client": "client code",
        "core": "core logic", "runtime": "runtime engine", "engine": "engine",
        "crypto": "cryptography", "signer": "signing", "signature": "signature ops",
        "attestation": "attestation logic", "seal": "sealing ops",
        "enclave": "enclave code", "host": "host-side code",
        "tests": "test suite", "test": "tests", "testing": "test utilities",
        "bench": "benchmarks", "benchmark": "benchmarks", "example": "examples",
        "examples": "examples", "docs": "documentation", "doc": "docs",
        "config": "configuration", "configs": "configurations",
        "scripts": "build/deploy scripts", "build": "build system",
        "contracts": "smart contracts", "contract": "smart contract",
        "types": "type definitions", "primitives": "primitive types",
        "utils": "utilities", "helpers": "helper functions",
        "storage": "storage layer", "db": "database", "database": "database layer",
        "network": "networking", "net": "networking", "rpc": "RPC interface",
        "grpc": "gRPC service", "http": "HTTP handlers", "rest": "REST API",
        "proto": "protocol buffers", "proto_generated": "generated protobuf",
        "messaging": "messaging", "mq": "message queue",
        "auth": "authentication", "permission": "permissions",
        "extension": "extensions", "chain-extension": "chain extensions",
        "loader": "loader/runtime", "runtimes": "runtime backends",
        "macro": "proc macros", "macros": "proc macros",
        "bindings": "language bindings", "ffi": "FFI bindings",
        "wasm": "WASM bindings", "js": "JS bindings", "go": "Go bindings",
        "py": "Python bindings", "python": "Python bindings",
        "sgx": "SGX interfaces", "tdx": "TDX interfaces",
        "pal": "platform abstraction", "ocall": "OCALL handlers",
        "ecall": "ECALL handlers", "sidevm": "side VM",
        "capi": "C API", "pink": "pRuntime (pink) node",
        "phactory": "pRuntime (phactory) worker",
    }

    # Build a mapping from directory path to component description from key_components.
    # Key components look like: "crates/sgx-attestation — Handles SGX quote generation..."
    comp_map: dict[str, str] = {}
    if key_components:
        for comp in key_components:
            # Split on em-dash, en-dash, or " - " to get path and description
            for sep in [" — ", " – ", " - "]:
                if sep in comp:
                    path_part, desc_part = comp.split(sep, 1)
                    path_part = path_part.strip()
                    desc_part = desc_part.strip()
                    if path_part and desc_part:
                        comp_map[path_part] = desc_part
                    break

    # Track which components have already had their description shown
    _shown_components: set[str] = set()

    def _extract_short_desc(desc: str) -> str:
        """Extract a concise first sentence from a component description."""
        # Take text up to first period, semicolon, or parenthesis
        for end_ch in ['. ', '; ', ' (', ' — ']:
            idx = desc.find(end_ch)
            if idx > 10:
                return desc[:idx + 1].strip()
        # Fallback: first 100 chars at word boundary
        if len(desc) <= 100:
            return desc
        cut = desc[:100].rfind(" ")
        return desc[:cut].strip() if cut > 50 else desc[:100].strip()

    def _infer_dir_description(dir_name: str, files: list[tuple[str, str]]) -> str:
        """Infer a directory's function from key_components, LLM reasoning, or heuristics."""
        clean = dir_name.rstrip("/")

        # Priority 1: Match against key_components (shown once per component)
        if comp_map:
            # Try exact match
            if clean in comp_map and clean not in _shown_components:
                _shown_components.add(clean)
                return _extract_short_desc(comp_map[clean])
            # Try prefix match: only show at the first encountered directory for each component
            best_match = ""
            best_desc = ""
            for comp_path, comp_desc in comp_map.items():
                comp_clean = comp_path.rstrip("/")
                if clean.startswith(comp_clean) and comp_clean not in _shown_components:
                    if len(comp_clean) > len(best_match):
                        best_match = comp_clean
                        best_desc = comp_desc
            if best_desc:
                _shown_components.add(best_match)
                return _extract_short_desc(best_desc)

        # Priority 2: LLM reasoning (if unique per-directory)
        if has_unique_descriptions:
            reasons = dir_reasoning.get(dir_name, [])
            if reasons:
                best = min(reasons, key=len)
                return _extract_short_desc(best)
        # Priority 3: Heuristic from the last path segment
        parts = dir_name.replace("\\", "/").rstrip("/").split("/")
        last = parts[-1].lower() if parts else ""
        # Check direct match, then strip common suffixes
        desc = _DIR_DESC.get(last)
        if not desc:
            for suffix in ["-src", "-lib", "-core", "-impl", "-rs"]:
                if last.endswith(suffix):
                    desc = _DIR_DESC.get(last[:-len(suffix)])
                    break
        if not desc:
            # Check if all files share a meaningful extension pattern
            exts = set(f.rsplit(".", 1)[-1] for f, _ in files if "." in f)
            if exts == {"sol"}:
                desc = "Solidity contracts"
        return desc or ""

    lines: list[str] = []
    lines.append("```")

    sorted_tops = sorted(top_level.keys())
    for i, top in enumerate(sorted_tops):
        subdirs = top_level[top]
        is_last_top = i == len(sorted_tops) - 1
        prefix = "└── " if is_last_top else "├── "
        child_prefix = "    " if is_last_top else "│   "

        # Collect all files under this top-level
        all_files: list[tuple[str, str]] = []
        for files in subdirs.values():
            all_files.extend(files)
        summary = _dir_summary(all_files)
        desc = _infer_dir_description(top, all_files)
        desc_part = f"  — {desc}" if desc else ""
        lines.append(f"{prefix}{top}/  {summary}{desc_part}")

        # Show subdirectories (limit depth to avoid overwhelming output)
        sorted_subdirs = sorted(subdirs.keys())
        for j, subdir in enumerate(sorted_subdirs):
            files = subdirs[subdir]
            is_last_sub = j == len(sorted_subdirs) - 1
            sub_prefix = child_prefix + ("└── " if is_last_sub else "├── ")
            sub_child = child_prefix + ("    " if is_last_sub else "│   ")

            zone_key = _dir_zone_key(files)
            sub_summary = _dir_summary(files)
            # Show relative path from top-level component to avoid duplicate names
            if subdir == top:
                dir_name = "."
            elif subdir.startswith(top + "/"):
                dir_name = subdir[len(top) + 1:]
            else:
                dir_name = subdir

            sub_desc = _infer_dir_description(subdir, files)
            sub_desc_part = f"  — {sub_desc}" if sub_desc else ""
            lines.append(f"{sub_prefix}{dir_name}/  {sub_summary}{sub_desc_part}")

            # For mixed directories, list individual files with zone indicators
            if zone_key == "mixed":
                mixed_files = sorted(files, key=lambda f: (f[1], f[0]))
                for k, (fname, fz) in enumerate(mixed_files[:15]):
                    is_last_file = k == min(len(mixed_files), 15) - 1
                    file_prefix = sub_child + ("└── " if is_last_file else "├── ")
                    fe = EMOJI.get(fz, "❓")
                    lines.append(f"{file_prefix}{fe} {fname}")
                if len(mixed_files) > 15:
                    lines.append(f"{sub_child}    ... {len(mixed_files) - 15} more files")

    lines.append("```")

    # Legend
    lines.append("")
    lines.append("_Legend: 🟢 Trusted (enclave) · 🔴 Untrusted (host) · 🟡 Mixed (boundary)_")

    return "\n".join(lines)


def _render_boundary_rationale(
    zone_map: "ZoneMap",
    repo_path: "Path | None",
) -> list[str]:
    """Render trust boundary rationale for manifest-less repos.

    Shows project role and reasoning. The zone partition tree above already shows
    per-directory classification, so this section provides the high-level rationale only.
    """
    lines: list[str] = []
    lines.append("### Trust Boundary Rationale")
    lines.append("")
    lines.append(
        "No TEE manifest, EDL, or PAL files were found. "
        "Classification is based on LLM-assisted analysis of directory structure, "
        "TEE API usage patterns, and project role inference."
    )
    lines.append("")

    # Show project role reasoning if available
    if hasattr(zone_map, "project_role") and zone_map.project_role:
        role_labels = {
            "enclave_only": "Enclave-only",
            "host_only": "Host-only",
            "mixed": "Mixed",
        }
        role_label = role_labels.get(zone_map.project_role, zone_map.project_role)
        lines.append(f"**Project Role:** {role_label}")
        if hasattr(zone_map, "project_role_reasoning") and zone_map.project_role_reasoning:
            lines.append(f"> {zone_map.project_role_reasoning}")
        lines.append("")

    # Show entry points if available
    if zone_map.entry_points:
        lines.append("**Boundary Entry Points:**")
        lines.append("")
        for edl_file, func_names in zone_map.entry_points.items():
            lines.append(f"- `{edl_file}`: {', '.join(f'`{f}`' for f in func_names[:10])}")
        lines.append("")

    return lines


def _render_partition_evidence(
    zone_map: "ZoneMap | None",
    repo_path: "Path | None",
    key_components: list[str] | None = None,
) -> list[str]:
    """Render the Trust Boundary Partition Evidence section.

    Deterministic section showing HOW and WHY files were classified into
    trusted/untrusted zones. No LLM calls.
    """
    lines: list[str] = []

    has_zones = zone_map and zone_map.zones
    if not has_zones:
        return lines

    from tee_audit.utils.call_graph import TrustZone, lookup_zone_source

    lines.append("## Trust Boundary Partition Evidence")
    lines.append("")

    # --- Methodology ---
    lines.append("### Partition Methodology")
    lines.append("")
    sources = set(zone_map.zone_source.values()) if zone_map.zone_source else set()
    method_parts = []
    if "gramine_enclave" in sources or "gramine_host" in sources:
        method_parts.append(
            "**Gramine enclave detection** identified the enclave root via `pal_gramine.rs` "
            "and Cargo.toml dependency graphs, classifying enclave-local crates as trusted "
            "and standalone host tools as untrusted"
        )
    if "manifest" in sources:
        method_parts.append(
            "**TEE manifest parsing** extracted trusted file lists from "
            "Gramine manifests or EDL files"
        )
    if "heuristic" in sources:
        method_parts.append(
            "**Path and content heuristics** classified files by directory patterns "
            "(enclave/, host/, trusted/) and TEE API usage (sgx_trts, sgx_urts, attestation)"
        )
    if "llm_inferred" in sources:
        method_parts.append("**LLM-assisted classification** for ambiguous files")
    if not method_parts:
        method_parts.append("Zone classification was applied using automated analysis")
    lines.append("; ".join(method_parts) + ".")
    lines.append("")

    # --- Project Role (if LLM-inferred) ---
    if hasattr(zone_map, "project_role") and zone_map.project_role:
        role_labels = {
            "enclave_only": "Enclave-only (all code runs inside TEE)",
            "host_only": "Host-only (all code runs outside TEE)",
            "mixed": "Mixed (contains both TEE and host code)",
        }
        role_label = role_labels.get(zone_map.project_role, zone_map.project_role)
        lines.append(f"**Project TEE Role:** {role_label}")
        if hasattr(zone_map, "project_role_reasoning") and zone_map.project_role_reasoning:
            lines.append(f"> {zone_map.project_role_reasoning}")
        lines.append("")

    # --- Directory-Level Zone Partition ---
    lines.append("### Source Code Zone Partition")
    lines.append("")
    lines.append(_render_zone_partition(zone_map, key_components))
    lines.append("")

    # --- Boundary Evidence ---
    if repo_path:
        boundary_files = _discover_boundary_files(zone_map, repo_path)
        has_manifest_evidence = any(
            "manifest" in r.lower() or "EDL" in r or "PAL" in r
            for _, r, _ in boundary_files
        )

        if has_manifest_evidence and boundary_files:
            # Repos with manifest/EDL/PAL: show boundary-defining files
            lines.append("### Boundary-Defining Files")
            lines.append("")
            for rel_path, reason, snippet in boundary_files:
                lines.append(f"**`{rel_path}`** -- {reason}")
                lines.append("```")
                lines.append(snippet or f"(file not available: {rel_path})")
                lines.append("```")
                lines.append("")
        else:
            # Manifest-less repos: show trust boundary rationale + cross-zone calls
            rationale_lines = _render_boundary_rationale(zone_map, repo_path)
            if rationale_lines:
                lines.extend(rationale_lines)

    # --- ECALL/OCALL Interface ---
    interface_rows: list[tuple[str, str, str, str]] = []
    if zone_map.entry_points:
        for edl_file, func_names in zone_map.entry_points.items():
            for func_name in func_names:
                itype = "ECALL" if "ecall" in func_name.lower() else "OCALL"
                zone = zone_map.zones.get(edl_file, TrustZone.UNKNOWN)
                zv = zone.value if isinstance(zone, TrustZone) else str(zone)
                interface_rows.append((func_name, itype, edl_file, zv))
    if interface_rows:
        lines.append("### Boundary-Crossing Interface")
        lines.append("")
        lines.append("| Function | Type | Defined In | Zone |")
        lines.append("| --- | --- | --- | --- |")
        for name, itype, file, zone in interface_rows[:30]:
            lines.append(f"| `{name}` | {itype} | `{file}` | {zone} |")
        if len(interface_rows) > 30:
            lines.append(f"| ... | ... | ... | _{len(interface_rows) - 30} more_ |")
        lines.append("")

    return lines


def _discover_boundary_files(
    zone_map: "ZoneMap",
    repo_path: Path,
    max_files: int = 5,
) -> list[tuple[str, str, str | None]]:
    """Discover up to max_files boundary-defining files with source snippets.

    Returns list of (rel_path, reason, snippet) tuples.
    """
    results: list[tuple[str, str, str | None]] = []
    seen: set[str] = set()

    # Strategy 1: Manifest files (Gramine, SGX SDK)
    for pattern in ["**/*.manifest.template", "**/*.manifest", "**/*.edl"]:
        for f in repo_path.glob(pattern):
            rel = str(f.relative_to(repo_path))
            if rel in seen or len(results) >= max_files:
                continue
            seen.add(rel)
            if rel.endswith(".edl"):
                reason = "EDL interface definition -- defines ECALL/OCALL boundary"
                key_line = _find_key_line(repo_path, rel, "trusted|untrusted|enclave")
            else:
                reason = "TEE manifest -- defines enclave configuration, trusted files, encrypted mounts"
                key_line = _find_key_line(repo_path, rel, "\\[sgx\\]|entrypoint|encrypted|trusted\\.files")
            snippet = _read_source_context(repo_path, rel, key_line, context_lines=8)
            results.append((rel, reason, snippet))

    # Strategy 2: PAL / Platform Abstraction Layer
    for marker in ["**/pal_gramine*", "**/pal_occlum*", "**/pal_*"]:
        for f in repo_path.glob(marker):
            rel = str(f.relative_to(repo_path))
            if rel in seen or len(results) >= max_files or not rel.endswith((".rs", ".c", ".h")):
                continue
            seen.add(rel)
            key_line = _find_key_line(repo_path, rel, "trait Platform|fn seal|fn attest|is_gramine|is_occlum")
            snippet = _read_source_context(repo_path, rel, key_line, context_lines=8)
            results.append((rel, "Platform Abstraction Layer -- enclave sealing/attestation interface", snippet))
            break  # One PAL file is enough

    # Strategy 3: ECALL/OCALL C ABI and interface files
    from tee_audit.utils.call_graph import TrustZone
    if len(results) < max_files:
        for pattern in ["**/types.h", "**/capi/**/*.rs", "**/capi/**/*.c"]:
            for f in repo_path.glob(pattern):
                rel = str(f.relative_to(repo_path))
                if rel in seen or len(results) >= max_files:
                    continue
                seen.add(rel)
                key_line = _find_key_line(repo_path, rel, "ecall|ocall|cross_call|extern.*\"C\"|typedef")
                snippet = _read_source_context(repo_path, rel, key_line, context_lines=8)
                results.append((rel, "ECALL/OCALL interface -- cross-boundary call definitions", snippet))
                break  # One interface file is enough

    # Strategy 4: Mixed-zone boundary files (boundary crossers, skip test files)
    if len(results) < max_files:
        mixed_files = [p for p, z in zone_map.zones.items() if z == TrustZone.MIXED]
        for mf in mixed_files:
            if mf in seen or len(results) >= max_files:
                continue
            if any(skip in mf for skip in ["test", "mock", "benchmark", "example"]):
                continue
            seen.add(mf)
            key_line = _find_key_line(repo_path, mf, "ecall|ocall|cross_call|extern.*\"C\"|entry_point|dispatch")
            snippet = _read_source_context(repo_path, mf, key_line, context_lines=8)
            results.append((mf, "Mixed-zone file -- spans the trust boundary", snippet))

    # Strategy 4: Representative trusted/untrusted files
    if len(results) < max_files:
        for zone_val, label in [("trusted", "Trusted (enclave)"), ("untrusted", "Untrusted (host)")]:
            if len(results) >= max_files:
                break
            zone_files = [p for p, z in zone_map.zones.items() if z.value == zone_val and p not in seen]
            if zone_files:
                # Pick the most representative (shortest path = likely core file)
                zone_files.sort(key=lambda p: p.count("/"))
                mf = zone_files[0]
                seen.add(mf)
                key_line = _find_key_line(repo_path, mf, "fn main|pub fn|mod |struct |impl ")
                snippet = _read_source_context(repo_path, mf, key_line, context_lines=8)
                results.append((mf, f"{label} representative file", snippet))

    return results[:max_files]


def _render_finding_detail(
    f: Finding,
    lines: list[str],
    show_taxonomy: bool = False,
    zone_map: "ZoneMap | None" = None,
    repo_path: "Path | None" = None,
) -> None:
    """Render a single finding in vulnerability disclosure format."""
    severity_tag = f.severity.value.upper()
    cwe_id_clean = f.cwe_id.removeprefix("CWE-").removeprefix("cwe-") if f.cwe_id else None
    cwe_tag = f" (CWE-{cwe_id_clean})" if cwe_id_clean else ""
    taxonomy_tag = f" [{f.tee_category.value}]" if show_taxonomy and f.tee_category else ""
    dim_tag = f" ({f.tee_dimension.value})" if show_taxonomy and f.tee_dimension else ""
    lines.append(f"### [{severity_tag}] {f.id}: {f.title}{taxonomy_tag}{dim_tag}{cwe_tag}")
    lines.append("")

    if f.root_cause:
        lines.append(f"**Root Cause**: {f.root_cause}")
    if f.impact:
        lines.append(f"**Impact**: {f.impact}")
    lines.append(f"**Confidence**: {f.confidence.value} | **Invariant**: {f.invariant_id} | **Tier**: {f.trust_path_tier.value}")
    lines.append("")

    if f.preconditions:
        lines.append("**Preconditions**:")
        for precond in f.preconditions:
            lines.append(f"- {precond}")
        lines.append("")

    if f.attack_path:
        lines.append("**Attack Scenario**:")
        loc_map: dict[int, str] = {}
        if f.code_locations:
            for idx, loc in enumerate(f.code_locations):
                loc_tag = f"`{loc.file}:{loc.line}`" if loc.line else f"`{loc.file}`"
                if zone_map:
                    zone = classify_code_location(loc.file, zone_map)
                    if zone.value != "unknown":
                        zl = "ENCLAVE" if zone.value == "trusted" else "HOST" if zone.value == "untrusted" else zone.value.upper()
                        loc_tag = f"`[{zl}] {loc.file}:{loc.line}`" if loc.line else f"`[{zl}] {loc.file}`"
                loc_map[idx] = loc_tag
        for i, raw_step in enumerate(f.attack_path):
            step = re.sub(r'^\s*\d+\.\s+', '', raw_step)
            loc_tag = loc_map.get(i)
            if loc_tag:
                lines.append(f"  {i + 1}. {step} ({loc_tag})")
            else:
                lines.append(f"  {i + 1}. {step}")
        remaining_locs = [loc_map[i] for i in loc_map if i >= len(f.attack_path)]
        if remaining_locs:
            lines.append(f"  **Evidence**: {', '.join(remaining_locs)}")
        lines.append("")

    # Code Evidence: single section with code blocks + prose analysis per block
    if f.code_locations:
        # Build evidence entries with zone, label, snippet, and prose from attack path
        host_entries: list[tuple[str, str, str | None, str]] = []  # (zone_tag, loc_label, snippet, prose)
        enclave_entries: list[tuple[str, str, str | None, str]] = []
        other_entries: list[tuple[str, str, str | None, str]] = []

        for idx, loc in enumerate(f.code_locations):
            loc_label = f"{loc.file}:{loc.line}" if loc.line else loc.file
            zone_tag = ""
            zone_group = other_entries

            if zone_map:
                zone = classify_code_location(loc.file, zone_map)
                if zone.value == "trusted":
                    zone_tag = "ENCLAVE"
                    zone_group = enclave_entries
                elif zone.value == "untrusted":
                    zone_tag = "HOST"
                    zone_group = host_entries
                elif zone.value != "unknown":
                    zone_tag = zone.value.upper()

            # Read multi-line source context (uses fuzzy path resolution)
            source_ctx = None
            if repo_path:
                source_ctx = _read_source_context(repo_path, loc.file, loc.line)
            snippet = source_ctx or loc.snippet

            if not snippet:
                continue  # Skip locations with no valid source

            # Derive prose from the corresponding attack path step
            prose = ""
            if f.attack_path and idx < len(f.attack_path):
                prose = re.sub(r'^\s*\d+\.\s+', '', f.attack_path[idx])
            elif idx == 0 and f.root_cause:
                prose = f.root_cause
            elif f.impact:
                prose = f"Related to: {f.impact[:200]}"

            full_label = f"{loc_label}"
            if zone_tag:
                full_label += f" [{zone_tag}]"
            zone_group.append((zone_tag, full_label, snippet, prose))

        # Collect all valid entries in zone order: HOST → ENCLAVE → Other
        all_entries = host_entries + enclave_entries + other_entries
        if all_entries:
            lines.append("### Code Evidence")
            lines.append("")
            for zone_tag, loc_label, snippet, prose in all_entries[:4]:
                lines.append(f"**`{loc_label}`**")
                lines.append("```")
                lines.append(snippet)
                lines.append("```")
                if prose:
                    lines.append(prose)
                lines.append("")

    if f.remediation:
        lines.append(f"**Remediation**: {f.remediation}")
        lines.append("")

    # Trust boundary trace (TEE-relevant findings only)
    if f.trust_boundary_trace:
        lines.append("**Trust Boundary Trace**:")
        lines.append("")
        lines.append("| Source Zone | Crossing Point | Sink Zone | Verification |")
        lines.append("| --- | --- | --- | --- |")
        for hop in f.trust_boundary_trace:
            crossing = hop.crossing_point.replace("|", "/")
            lines.append(f"| {hop.source_zone} | {crossing} | {hop.sink_zone} | {hop.verification_status} |")
        lines.append("")

    # Cross-file call chain as structured text (replaces table rendering)
    if f.trust_boundary_trace and any(h.file for h in f.trust_boundary_trace):
        chain_hops = [h for h in f.trust_boundary_trace if h.file]
        if len(chain_hops) >= 2:
            _render_invocation_chain_text(chain_hops, lines, zone_map)

            # Optional compact Mermaid diagram (>= 3 hops spanning >= 2 zones)
            zones_in_chain = set()
            for hop in chain_hops:
                z = (hop.source_zone or "").upper()
                if z and z != "UNKNOWN":
                    zones_in_chain.add(z)
            if len(chain_hops) >= 3 and len(zones_in_chain) >= 2:
                lines.append("```mermaid")
                lines.append("%% invocation-chain")
                lines.append("flowchart LR")
                for i, hop in enumerate(chain_hops):
                    node_id = f"hop{i}"
                    caller = hop.caller_function or "?"
                    callee = (f"{hop.callee_module}::" if hop.callee_module else "") + hop.callee_name
                    label = f"{hop.file.split('/')[-1]}:{caller} → {callee}"
                    lines.append(f"    {node_id}[\"{label}\"]")
                    if i > 0:
                        if hop.crosses_boundary:
                            lines.append(f"    hop{i - 1} -->|CROSS| {node_id}")
                        else:
                            lines.append(f"    hop{i - 1} --> {node_id}")
                lines.append("```")
                lines.append("")

    if f.trust_boundary_prose:
        lines.append(f"**Trust Boundary Analysis**: {f.trust_boundary_prose}")
        lines.append("")

def _validate_mermaid_block(lines: list[str]) -> list[str] | None:
    """Validate and fix common Mermaid syntax errors in a diagram block.

    Returns fixed lines, or None if no changes were needed.
    """
    import re as _re
    fixed = list(lines)
    changed = False

    for i, line in enumerate(fixed):
        stripped = line.strip()
        # Skip directives, comments, classDef, class, and subgraph lines
        if (stripped.startswith("%%") or stripped.startswith("classDef ")
                or stripped.startswith("class ") or stripped.startswith("subgraph ")
                or stripped.startswith("end") or stripped.startswith("flowchart ")
                or stripped.startswith("graph ") or not stripped):
            continue

        # Fix 1: Unmatched quotes in node label definitions like NodeID["label
        # Mermaid uses ["label"] or [label] for rectangular nodes
        new_line = line
        # Find all ["..."] patterns and validate
        open_brackets = []
        j = 0
        result = []
        while j < len(new_line):
            ch = new_line[j]
            if ch == '[' and j + 1 < len(new_line) and new_line[j + 1] == '"':
                # Start of [" label
                open_brackets.append(len(result))
                result.append(ch)
                j += 1
                result.append(new_line[j])  # the quote
            elif ch == '"' and open_brackets:
                # Closing quote inside a bracket label
                result.append(ch)
                # Check if next char is ]
                if j + 1 < len(new_line) and new_line[j + 1] == ']':
                    result.append(']')
                    j += 2
                    open_brackets.pop()
                    continue
                else:
                    # Missing closing bracket — add it
                    result.append(']')
                    open_brackets.pop()
                    changed = True
            else:
                result.append(ch)
            j += 1
        new_line = ''.join(result)

        # Fix 2: Parentheses in labels that aren't Mermaid syntax
        # In Mermaid, A(text) creates a rounded node. If a label contains parens,
        # it breaks. Replace inner parens with dashes inside quoted labels.
        def _fix_parens_in_labels(m):
            label = m.group(1)
            if '(' in label or ')' in label:
                return '["' + label.replace('(', '-').replace(')', '') + '"]'
            return m.group(0)

        new_line = _re.sub(r'\["([^"]*[\(\)][^"]*)"\]', _fix_parens_in_labels, new_line)

        # Fix 3: Pipe characters in labels (breaks Mermaid)
        def _fix_pipes_in_labels(m):
            label = m.group(1)
            if '|' in label:
                return '["' + label.replace('|', '/') + '"]'
            return m.group(0)

        new_line = _re.sub(r'\["([^"]*\|[^"]*)"\]', _fix_pipes_in_labels, new_line)

        # Fix 4: Angle brackets in labels (Mermaid interprets as HTML)
        def _fix_angles_in_labels(m):
            label = m.group(1)
            if '<' in label or '>' in label:
                return '["' + label.replace('<', '(').replace(')', ')') + '"]'
            return m.group(0)

        # Fix 5: Remove trailing semicolons (sometimes cause issues)
        new_line = _re.sub(r';\s*$', '', new_line)

        if new_line != line:
            fixed[i] = new_line
            changed = True

    return fixed if changed else None


def _validate_report_syntax(text: str) -> str:
    """Validate and fix report markdown syntax issues.

    Checks:
    1. Markdown tables have valid pipe alignment
    2. Mermaid diagram syntax is well-formed
    3. Mermaid node labels <= 50 chars
    4. Trust boundary trace tables have all 4 columns
    """
    lines = text.split("\n")
    fixed_lines: list[str] = []
    in_mermaid = False
    mermaid_start = -1

    in_invocation_chain = False  # Track invocation-chain Mermaid blocks
    mermaid_block_start = -1  # Track start of current block for post-validation

    for i, line in enumerate(lines):
        # Track Mermaid blocks
        if line.strip() == "```mermaid":
            in_mermaid = True
            mermaid_start = i
            mermaid_block_start = len(fixed_lines)  # Track position in fixed_lines
            in_invocation_chain = False  # Will be set by %% invocation-chain marker
            fixed_lines.append(line)
            continue
        if in_mermaid and line.strip() == "```":
            in_mermaid = False
            in_invocation_chain = False
            # Post-validate the completed Mermaid block
            block_lines = fixed_lines[mermaid_block_start + 1:]
            fixed_block = _validate_mermaid_block(block_lines)
            if fixed_block is not None:
                fixed_lines = fixed_lines[:mermaid_block_start + 1] + fixed_block
            fixed_lines.append(line)
            continue

        if in_mermaid:
            # Strip emojis from all Mermaid lines (breaks some renderers)
            import re as _emoji_re
            line = _emoji_re.sub(r'[\U0001F300-\U0001F9FF\U00002702-\U000027B0\U0001F000-\U0001FFFF]', '', line)
            # Replace em-dashes and special dashes with ASCII hyphens
            line = line.replace('—', '--').replace('–', '-').replace('―', '--')

            # Detect invocation-chain marker for wider label limit
            if "%% invocation-chain" in line:
                in_invocation_chain = True
                fixed_lines.append(line)
                continue

            # Truncate node labels: 100 chars for invocation-chain, 80 for others
            max_label = 100 if in_invocation_chain else 80
            truncate_to = max_label - 4  # Leave room for "..."

            def _truncate_label(m, t=truncate_to):
                text = m.group(2)
                if len(text) <= max_label:
                    return m.group(0)
                # Word-aware truncation: find last space before limit
                cut = text[:t].rfind(" ")
                if cut > t // 2:  # Only use word boundary if it's not too far back
                    text = text[:cut]
                else:
                    text = text[:t]
                return m.group(1) + text + "..." + m.group(3)

            import re as _re
            pattern = rf'((?:\w+\s*-->?\s*)?\w+\["?)([^"\]]{{{max_label + 1},}})((?:"?\]))'
            line = _re.sub(pattern, _truncate_label, line)
            fixed_lines.append(line)
            continue

        # Validate markdown table rows have consistent pipe count
        stripped = line.strip()
        if "|" in stripped and stripped.startswith("|"):
            pipes = stripped.count("|")
            # Check if this is a separator line (only pipes, dashes, colons, spaces)
            non_sep_chars = stripped.replace("|", "").replace("-", "").replace(" ", "").replace(":", "")
            is_separator = not non_sep_chars and pipes > 1
            if is_separator:
                # Separator line — pass through as-is, it's already valid
                fixed_lines.append(line)
                continue

            # Look back for header row to compare pipe count
            if fixed_lines:
                prev_idx = len(fixed_lines) - 1
                # Skip empty lines to find header
                while prev_idx >= 0 and not fixed_lines[prev_idx].strip():
                    prev_idx -= 1
                if prev_idx >= 0 and "|" in fixed_lines[prev_idx] and fixed_lines[prev_idx].strip().startswith("|"):
                    header_pipes = fixed_lines[prev_idx].count("|")
                    if pipes < header_pipes:
                        # Pad missing columns
                        diff = header_pipes - pipes
                        line = stripped + " |" * diff

        fixed_lines.append(line)

    return "\n".join(fixed_lines)


def _render_markdown_report(report: Report, zone_map: "ZoneMap | None" = None, repo_path: "Path | None" = None, key_components: list[str] | None = None) -> str:
    """Render the report as a Markdown document with TEE usage problem focus.

    Section order:
    1. Executive Summary
    2. Dashboard Summary (TEE-relevant only)
    3. Trust Boundary Analysis
    4. Architecture Diagrams
    5. Taxonomy Summary
    6. TEE Usage Problems (with taxonomy tags)
    7. Items Requiring Manual Review (TEE-related only)
    8. Positive Guards
    9. Dismissed Findings
    10. Appendix: Non-TEE Findings
    """
    lines: list[str] = []

    lines.append(f"# TEE Usage Audit Report: {report.project_name}")
    lines.append("")

    # --- Section 1: Executive Summary ---
    if report.executive_summary:
        summary = re.sub(r'^#{1,4}\s+.*$', '', report.executive_summary, flags=re.MULTILINE).strip()
        lines.append("## Executive Summary")
        lines.append(summary)
        lines.append("")

    # --- Section 2: Dashboard Summary (always rendered) ---
    lines.append("## Dashboard Summary")
    lines.append("")
    if report.dashboard:
        lines.append("| Severity | Trust-Path Tier | Count |")
        lines.append("| --- | --- | --- |")
        for entry in report.dashboard:
            lines.append(f"| {entry.severity.value} | {entry.trust_path_tier.value} | {entry.count} |")
    else:
        lines.append("| Severity | Trust-Path Tier | Count |")
        lines.append("| --- | --- | --- |")
        lines.append("| — | — | **0** |")
        lines.append("")
        lines.append("_No TEE usage issues identified._")
    lines.append("")

    # --- Section 3: Trust Boundary Analysis ---
    if report.trust_boundary_table:
        lines.append("## Trust Boundary Analysis")
        lines.append("")
        lines.append("| Actor | Component | Context | Boundary Type |")
        lines.append("| --- | --- | --- | --- |")
        for row in report.trust_boundary_table:
            actor = row.actor.replace("|", "/").replace("\n", " ")
            component = row.component.replace("|", "/").replace("\n", " ")
            context = row.context.replace("|", "/").replace("\n", " ")
            boundary = row.boundary_type.replace("|", "/").replace("\n", " ")
            lines.append(f"| {actor} | {component} | {context} | {boundary} |")
        lines.append("")

    # --- Section 3b: Trust Boundary Partition Evidence ---
    partition_lines = _render_partition_evidence(zone_map, repo_path, key_components)
    if partition_lines:
        lines.extend(partition_lines)

    # --- Section 4: Architecture Diagrams ---
    if report.diagrams:
        lines.append("## Architecture Diagrams")
        lines.append("")
        for diag in report.diagrams:
            lines.append(f"### {diag.title}")
            if diag.text_summary:
                lines.append(diag.text_summary)
                lines.append("")
            lines.append("```mermaid")
            lines.append(diag.mermaid_code)
            lines.append("```")
            lines.append("")

    # Trust Boundary Narrative (prose replacing trust-path Mermaid diagram)
    if hasattr(report, "trust_boundary_narrative") and report.trust_boundary_narrative:
        lines.append("### Trust Boundary Narrative")
        lines.append("")
        lines.append(report.trust_boundary_narrative)
        lines.append("")

    # Data Flow Summary (prose replacing data-flow Mermaid diagram)
    if hasattr(report, "data_flow_summary") and report.data_flow_summary:
        lines.append("### Data Flow Summary")
        lines.append("")
        lines.append(report.data_flow_summary)
        lines.append("")

    # Invariant reference table
    if report.invariants:
        lines.append("### Invariant Reference")
        lines.append("")
        lines.append("| ID | Description | Trust Path |")
        lines.append("| --- | --- | --- |")
        for inv in report.invariants:
            lines.append(f"| {inv.id} | {inv.description} | {inv.trust_path} |")
        lines.append("")

    # --- Section 5: Taxonomy Summary ---
    if report.taxonomy_summary:
        lines.append("## Taxonomy Summary")
        lines.append("")
        lines.append("| Category | Count | Findings |")
        lines.append("| --- | --- | --- |")
        for entry in report.taxonomy_summary:
            lines.append(f"| {entry.category.value} | {entry.count} | {', '.join(entry.finding_ids)} |")
        lines.append("")

    # --- Classify findings ---
    all_active = [f for f in report.findings if not f.dismissed] if report.findings else []
    dismissed_findings = [f for f in report.findings if f.dismissed] if report.findings else []
    tee_findings = [f for f in all_active if f.is_tee_relevant]
    generic_findings = [f for f in all_active if not f.is_tee_relevant]

    # Main body: Low+ severity TEE findings
    main_tee = [f for f in tee_findings if f.severity != Severity.INFO]
    # Appendix: Info TEE findings + all unknowns
    info_tee = [f for f in tee_findings if f.severity == Severity.INFO]
    tee_unknowns = [u for u in report.unknowns if getattr(u, 'is_tee_relevant', True)] if report.unknowns else []

    # --- Section 6: TEE Usage Problems (Low+ severity) ---
    if main_tee:
        lines.append("## TEE Usage Problems")
        lines.append("")
        for f in main_tee:
            _render_finding_detail(f, lines, show_taxonomy=True, zone_map=zone_map, repo_path=repo_path)

    # --- Section 7: Positive Guards ---
    if report.positive_guards:
        lines.append("## Positive Guards (Confirmed Security Controls)")
        lines.append("")
        for pg in report.positive_guards:
            if pg.title:
                short = pg.title
            else:
                desc = pg.description.strip()
                short = re.sub(r'\s*\([^)]*\)', '', desc.split(".")[0]).strip()
                if len(short) > 60:
                    short = short.split(",")[0].strip()
                if len(short) > 60:
                    short = short[:57] + "..."
            if not short:
                short = pg.id
            lines.append(f"### {pg.id}: {short}")
            lines.append(f"- **Invariants**: {', '.join(pg.invariant_refs)}")
            lines.append(f"- **Completeness**: {pg.completeness_status}")
            if pg.code_evidence:
                lines.append(f"- **Evidence**: {pg.code_evidence}")
            desc = pg.description.strip()
            if desc:
                lines.append(f"\n{desc}")
            lines.append("")

    # --- Section 9: Dismissed Findings ---
    if dismissed_findings:
        lines.append("## Dismissed Findings")
        lines.append("")
        lines.append("_The following findings were dismissed during adversarial review._")
        lines.append("")
        for f in dismissed_findings:
            lines.append(f"### ~~{f.id}: {f.title}~~")
            lines.append(f"- **Original Severity**: {f.severity.value}")
            lines.append(f"- **Dismissal Reason**: {f.dismissal_reason or 'Adversarial review: false positive'}")
            if f.code_locations:
                locs = ", ".join(
                    f"`{loc.file}:{loc.line}`" if loc.line else f"`{loc.file}`"
                    for loc in f.code_locations
                )
                lines.append(f"- **Location(s)**: {locs}")
            lines.append("")

    # --- Section 10: Appendix — Info Findings, Unknowns, Non-TEE ---
    appendix_has_content = info_tee or tee_unknowns or generic_findings
    if appendix_has_content:
        lines.append("## Appendix")
        lines.append("")
        lines.append(
            "_Info-severity TEE findings, items requiring manual review, and "
            "non-TEE findings are included here for completeness._"
        )
        lines.append("")

    if info_tee:
        lines.append("### Info-Severity TEE Findings")
        lines.append("")
        for f in info_tee:
            _render_finding_detail(f, lines, show_taxonomy=True, zone_map=zone_map, repo_path=repo_path)

    if tee_unknowns:
        lines.append("### Items Requiring Manual Review")
        lines.append("")
        for u in tee_unknowns:
            short_title = u.title if u.title else u.what_was_checked[:60]
            lines.append(f"#### {u.id}: {short_title}")
            if u.what_was_checked and u.what_was_checked != short_title:
                lines.append(f"\n{u.what_was_checked}")
            lines.append(f"- **Why Uncertain**: {u.why_uncertain}")
            lines.append(f"- **Recommended Steps**: {', '.join(u.recommended_steps)}")
            lines.append("")

    if generic_findings:
        lines.append("### Non-TEE Findings")
        lines.append("")
        lines.append(
            "_The following findings are generic code issues that do not directly "
            "involve TEE trust boundaries._"
        )
        lines.append("")
        for f in generic_findings:
            _render_finding_detail(f, lines, show_taxonomy=False, zone_map=zone_map, repo_path=repo_path)

    # --- Syntax validation ---
    report_text = "\n".join(lines)
    report_text = _validate_report_syntax(report_text)

    return report_text


def run_report(
    input_data: Stage6Input,
    client: LLMClient,
    results_dir: Path,
    temperature: float = 0.0,
) -> Stage6Output:
    """Run Stage 6: Assemble final audit report."""
    logger.info("Stage 6: Assembling report")

    # Load zone_map early — needed for architecture diagram and markdown rendering
    zone_map = None
    if input_data.zone_map_path and input_data.zone_map_path.exists():
        try:
            from tee_audit.utils.call_graph import ZoneMap as _ZoneMap
            zone_map = _ZoneMap.model_validate_json(input_data.zone_map_path.read_text())
            logger.info("Loaded zone map with %d classified files", len(zone_map.zones))
        except Exception as e:
            logger.warning("Failed to load zone map: %s", str(e)[:200])

    # Build dashboard from TEE-relevant findings only
    active_findings = [f for f in input_data.findings if not f.dismissed]
    dashboard = _build_dashboard(active_findings, tee_relevant_only=True)

    # Build taxonomy summary from TEE-relevant findings
    taxonomy_summary = _build_taxonomy_summary(active_findings)

    # Build diagrams from pipeline data
    architecture_diagram, trust_boundary_table = _build_llm_architecture_diagram(
        input_data.key_components, input_data.fingerprint,
        input_data.dossier_sections, client, results_dir, temperature,
        zone_map=zone_map,
    )
    trust_path_diagram = _build_trust_path_diagram(
        input_data.invariants, input_data.fingerprint,
    )
    data_flow_diagram = _build_data_flow_diagram(
        input_data.dossier_sections, input_data.fingerprint,
        invariants=input_data.invariants,
    )
    attack_path_diagrams = _build_attack_path_diagrams(input_data.findings)
    diagrams = [architecture_diagram]  # Only architecture as Mermaid; trust-path/data-flow are prose

    # Build prose replacements for trust-path and data-flow diagrams
    trust_boundary_narrative = _build_trust_boundary_narrative(
        input_data.invariants, input_data.fingerprint,
    )
    data_flow_summary = _build_data_flow_summary(
        input_data.dossier_sections, input_data.fingerprint,
        invariants=input_data.invariants,
    )

    # Generate executive summary via LLM — focused on TEE usage problems
    tee_findings = [f for f in active_findings if f.is_tee_relevant]
    generic_count = len(active_findings) - len(tee_findings)
    findings_summary = json.dumps(
        [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "tee_category": f.tee_category.value if f.tee_category else None,
                "tee_dimension": f.tee_dimension.value if f.tee_dimension else None,
            }
            for f in tee_findings
        ],
        indent=2,
    )

    try:
        response = parse_with_retry(
            client,
            "You are a TEE security auditor writing an executive summary for a TEE usage audit report. "
            "Focus on TEE usage problems — issues involving TEE primitives (attestation, sealing, "
            "measurement, ECALL/OCALL, quote generation/verification, freshness) or TEE trust boundaries "
            "(enclave/host, trusted/untrusted). "
            "2-3 short paragraphs max. No filler, no repetition. Use bullet lists for findings breakdown. "
            "Start with the most severe TEE usage problem. Mention taxonomy categories hit. "
            f"Note: {generic_count} generic code findings are in the appendix.",
            f"Write a concise executive summary focused on TEE usage problems for these findings:\n{findings_summary}",
            ReportResponse,
            error_save_dir=results_dir,
            temperature=temperature,
        )
        executive_summary = response.executive_summary
    except Exception as e:
        logger.warning("LLM report generation failed, using fallback summary: %s", str(e)[:200])
        tee_count = len(tee_findings)
        exec_count = len(active_findings)
        executive_summary = (
            f"TEE usage audit found {tee_count} TEE usage problems out of {exec_count} total findings "
            f"across {len(set(f.invariant_id for f in active_findings))} invariants. "
            f"See the TEE Usage Problems section for details."
        )

    # Assemble report
    report = Report(
        project_name=input_data.fingerprint.repo_root.rstrip("/").split("/")[-1] if input_data.fingerprint else "unknown",
        fingerprint=input_data.fingerprint,
        invariants=input_data.invariants,
        findings=input_data.findings,
        positive_guards=input_data.positive_guards,
        unknowns=input_data.unknowns,
        dashboard=dashboard,
        diagrams=diagrams,
        trust_boundary_table=trust_boundary_table,
        executive_summary=executive_summary,
        taxonomy_summary=taxonomy_summary,
        trust_boundary_narrative=trust_boundary_narrative,
        data_flow_summary=data_flow_summary,
    )

    # Write Markdown report
    results_dir.mkdir(parents=True, exist_ok=True)
    report_path = results_dir / "report.md"

    markdown = _render_markdown_report(report, zone_map=zone_map, repo_path=Path(input_data.fingerprint.repo_root), key_components=input_data.key_components)
    report_path.write_text(markdown)

    # Write JSON report for programmatic consumption
    json_path = results_dir / "report.json"
    json_path.write_text(report.model_dump_json(indent=2))

    logger.info("Stage 6 complete: report written to %s", report_path)
    return Stage6Output(report=report, report_path=report_path)
