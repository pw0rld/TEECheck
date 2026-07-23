"""Validate two-side boundary evidence in audit findings.

Usage: python scripts/validate_boundary.py <repo-name>
Example: python scripts/validate_boundary.py phala-blockchain
"""
import json
import sys
from pathlib import Path

from tee_audit.models.finding import Finding
from tee_audit.utils.call_graph import classify_code_location, ZoneMap


def validate_repo(repo_name: str) -> None:
    base = Path(f"output/{repo_name}-audit")
    stage55 = base / "results/stage55_output.json"
    zone_map_path = base / "artifact/zone_map.json"

    if not stage55.exists():
        print(f"ERROR: {stage55} not found")
        return

    findings_data = json.loads(stage55.read_text())
    findings = [Finding.model_validate(f) for f in findings_data.get("verified_findings", [])]

    zone_map = None
    if zone_map_path.exists():
        zone_map = ZoneMap.model_validate_json(zone_map_path.read_text())

    tee_findings = [f for f in findings if f.is_tee_relevant and not f.dismissed]
    print(f"\n{'='*60}")
    print(f"  Validation: {repo_name}")
    print(f"{'='*60}")
    print(f"  Total findings: {len(findings)}")
    print(f"  TEE-relevant (non-dismissed): {len(tee_findings)}")

    if not zone_map:
        print("  WARNING: No zone_map - cannot validate two-side evidence")
        return

    both_sides = 0
    host_only = 0
    enclave_only = 0
    no_locs = 0
    other = 0

    for f in tee_findings:
        if not f.code_locations:
            no_locs += 1
            print(f"  [NO LOCS] {f.id}: {f.title[:60]}")
            continue

        zones = set()
        for loc in f.code_locations:
            z = classify_code_location(loc.file, zone_map)
            zones.add(z.value)

        has_host = "untrusted" in zones
        has_enclave = "trusted" in zones

        if has_host and has_enclave:
            both_sides += 1
        elif has_host:
            host_only += 1
            print(f"  [HOST ONLY] {f.id}: {f.title[:60]}")
        elif has_enclave:
            enclave_only += 1
            print(f"  [ENCLAVE ONLY] {f.id}: {f.title[:60]}")
        else:
            other += 1
            print(f"  [MIXED/OTHER] {f.id}: {f.title[:60]}")

    print(f"\n  Results:")
    print(f"    Both sides:     {both_sides}/{len(tee_findings)}")
    print(f"    HOST only:      {host_only}/{len(tee_findings)}")
    print(f"    ENCLAVE only:   {enclave_only}/{len(tee_findings)}")
    print(f"    No locations:   {no_locs}/{len(tee_findings)}")
    print(f"    Other:          {other}/{len(tee_findings)}")

    score = both_sides / len(tee_findings) if tee_findings else 1.0
    print(f"    Coverage score: {score:.1%}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/validate_boundary.py <repo-name> [repo-name ...]")
        sys.exit(1)
    for repo in sys.argv[1:]:
        validate_repo(repo)
