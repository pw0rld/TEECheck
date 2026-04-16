"""Fingerprint data model — output of Stage 0."""

from __future__ import annotations

from pydantic import BaseModel


class Fingerprint(BaseModel):
    """Repository fingerprint capturing TEE and Web3 signals."""

    repo_root: str
    top_extensions: dict[str, int]
    codeql_languages: list[str]
    tee_platforms: dict[str, list[str]]  # platform -> matched lines
    web3_roles: dict[str, list[str]]  # role -> matched lines
    trust_artifacts: dict[str, list[str]]  # artifact type -> matched lines
    build_flags: dict[str, list[str]]  # flag type -> matched lines
    critical_paths: list[str]
