"""Pydantic v2 models for the TrustIR intermediate representation.

These models mirror ``web3_tee_trustir_docs/spec/trustir.schema.json`` and the
allowed values in ``web3_tee_trustir_docs/spec/enum_registry.yml``. Enum string
values are kept identical to the IR JSON so that ``TrustIR.model_validate`` is a
faithful schema + enum validation (the LLM extractor output is validated through
these models).

Conventions follow the rest of tee-audit: ``from __future__ import annotations``,
``class X(str, Enum)`` with the IR value as the member value, mutable list
defaults, optional fields via ``T | None = None``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


# --------------------------------------------------------------------------- #
# Enumerations (enum_registry.yml)
# --------------------------------------------------------------------------- #


class TaxonomyFamily(str, Enum):
    FLOW = "Flow"
    GUARD = "Guard"
    BINDING = "Binding"
    STATE = "State"
    CONFIG = "Config"
    DESIGN = "Design"
    LEAKAGE = "Leakage"


class TEEDimension(str, Enum):
    INCORRECT_USAGE = "incorrect_usage"
    INAPPROPRIATE_DESIGN = "inappropriate_design"


class EvidenceKind(str, Enum):
    CODE = "code"
    DOCUMENTATION = "documentation"
    CONFIG = "config"
    CONTRACT = "contract"
    COMMENT = "comment"
    BUILD_FILE = "build_file"
    MANIFEST = "manifest"


class SecurityState(str, Enum):
    """security_state_after_producer for a claim field."""

    RAW = "raw"
    PARSED = "parsed"
    AUTHENTIC = "authentic"
    APPRAISED = "appraised"
    SCOPED = "scoped"
    BOUND = "bound"
    UNKNOWN = "unknown"


class FailureBehavior(str, Enum):
    THROWS_OR_RETURNS_ERROR = "throws_or_returns_error"
    REVERTS = "reverts"
    RETURNS_FALSE = "returns_false"
    EXITS_PROCESS = "exits_process"
    LOGS_ONLY = "logs_only"
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    """Final solver status (status_model / finding_status)."""

    CONFIRMED = "confirmed"
    VIOLATED_CANDIDATE = "violated_candidate"
    DELEGATED = "delegated"
    GUARDED_ELSEWHERE = "guarded_elsewhere"
    CONFIGURATION_DEPENDENT = "configuration_dependent"
    TEST_ONLY = "test_only"
    OUT_OF_SCOPE = "out_of_scope"
    UNRESOLVED = "unresolved"


class ClaimFieldRole(str, Enum):
    MEASUREMENT = "measurement"
    SIGNER_IDENTITY = "signer_identity"
    PRODUCT_ID = "product_id"
    SECURITY_VERSION = "security_version"
    REPORT_DATA = "report_data"
    USER_DATA = "user_data"
    ATTESTED_PUBLIC_KEY = "attested_public_key"
    RUNTIME_PUBLIC_KEY = "runtime_public_key"
    WORKER_IDENTITY = "worker_identity"
    PROVER_IDENTITY = "prover_identity"
    ORACLE_IDENTITY = "oracle_identity"
    AGENT_ADDRESS = "agent_address"
    CHAIN_ID = "chain_id"
    CONTRACT_ADDRESS = "contract_address"
    TASK_ID = "task_id"
    EPOCH = "epoch"
    NONCE = "nonce"
    TIMESTAMP = "timestamp"
    TCB_STATUS = "tcb_status"
    DEBUG_FLAG = "debug_flag"
    TEE_TYPE = "tee_type"
    RUNTIME_HASH = "runtime_hash"
    SEALED_STATE_VERSION = "sealed_state_version"


class AuthorityKind(str, Enum):
    REGISTRATION_ACCEPTANCE = "registration_acceptance"
    KEY_RELEASE = "key_release"
    SECRET_ACCESS = "secret_access"
    PROOF_ACCEPTANCE = "proof_acceptance"
    ORACLE_UPDATE = "oracle_update"
    TRUSTED_WORKER_UPDATE = "trusted_worker_update"
    RUNTIME_KEY_ACCEPTANCE = "runtime_key_acceptance"
    CONFIDENTIAL_INPUT_ACCEPTANCE = "confidential_input_acceptance"
    POLICY_CHANGE = "policy_change"
    SETTLEMENT_ACCEPTANCE = "settlement_acceptance"
    STATE_RESTORE_ACCEPTANCE = "state_restore_acceptance"
    OBSERVABLE_OUTPUT = "observable_output"


class AuthoritySubjectRole(str, Enum):
    REGISTERED_WORKER = "registered_worker"
    REGISTERED_PROVER = "registered_prover"
    REGISTERED_ORACLE = "registered_oracle"
    REGISTERED_AGENT = "registered_agent"
    KEY_RELEASE_RECIPIENT = "key_release_recipient"
    PROOF_INSTANCE = "proof_instance"
    ENCRYPTION_KEY = "encryption_key"
    PAYOUT_SUBJECT = "payout_subject"


class GuardKind(str, Enum):
    VERIFIER_SUCCESS_CHECK = "verifier_success_check"
    QUOTE_SIGNATURE_VERIFICATION = "quote_signature_verification"
    CERTIFICATE_CHAIN_VERIFICATION = "certificate_chain_verification"
    TCB_STATUS_APPRAISAL = "tcb_status_appraisal"
    QE_IDENTITY_APPRAISAL = "qe_identity_appraisal"
    COLLATERAL_FRESHNESS_CHECK = "collateral_freshness_check"
    CRL_REVOCATION_CHECK = "crl_revocation_check"
    MEASUREMENT_ALLOWLIST_CHECK = "measurement_allowlist_check"
    SIGNER_ALLOWLIST_CHECK = "signer_allowlist_check"
    REPORT_DATA_INTEGRITY_CHECK = "report_data_integrity_check"
    NONCE_FRESHNESS_CHECK = "nonce_freshness_check"
    TIMESTAMP_FRESHNESS_CHECK = "timestamp_freshness_check"
    EPOCH_FRESHNESS_CHECK = "epoch_freshness_check"
    IDENTITY_VERIFICATION = "identity_verification"
    PRODUCTION_MODE_CHECK = "production_mode_check"


class BindingRelationKind(str, Enum):
    EQUAL = "equal"
    DERIVED_EQUAL = "derived_equal"
    HASH_EQUAL = "hash_equal"
    SIGNATURE_COVERS = "signature_covers"
    TRANSCRIPT_COVERS = "transcript_covers"
    REGISTRY_LOOKUP_MATCHES = "registry_lookup_matches"
    ALLOWLIST_MEMBERSHIP = "allowlist_membership"
    MONOTONIC_GREATER_OR_EQUAL = "monotonic_greater_or_equal"
    FRESHNESS_WITHIN_WINDOW = "freshness_within_window"
    SAME_EPOCH = "same_epoch"
    SAME_CHAIN_CONTEXT = "same_chain_context"


class ConfigSourceKind(str, Enum):
    ENVIRONMENT_VARIABLE = "environment_variable"
    CLI_FLAG = "cli_flag"
    CARGO_FEATURE = "cargo_feature"
    BUILD_TAG = "build_tag"
    CHAIN_CONSTANT = "chain_constant"
    GENESIS_CONFIG = "genesis_config"
    DOCKER_ENV = "docker_env"
    MANIFEST_OPTION = "manifest_option"
    GRAMINE_MANIFEST = "gramine_manifest"
    CONFIG_FILE = "config_file"
    HARDCODED_DEV_KEY = "hardcoded_dev_key"
    TEST_KEY_MATERIAL = "test_key_material"


class WeakMode(str, Enum):
    """security_mode_kind: weak trust modes that may reach authority."""

    PRODUCTION = "production"
    DEBUG = "debug"
    SIMULATION = "simulation"
    MOCK_TEE = "mock_tee"
    NONE_ATTESTATION = "none_attestation"
    SKIP_VERIFICATION = "skip_verification"
    ALLOW_DEBUG_ENCLAVE = "allow_debug_enclave"
    INJECT_KEY = "inject_key"
    USE_DEV_KEY = "use_dev_key"
    UNSAFE_COLLATERAL_SOURCE = "unsafe_collateral_source"


class StateObjectKind(str, Enum):
    SEALED_BLOB = "sealed_blob"
    CHECKPOINT = "checkpoint"
    REPLAY_TRACE = "replay_trace"
    EPOCH_STATE = "epoch_state"
    RUNTIME_STATE_ROOT = "runtime_state_root"
    KEY_ROTATION_STATE = "key_rotation_state"
    COMMITTEE_MEMBERSHIP_STATE = "committee_membership_state"
    MONOTONIC_COUNTER = "monotonic_counter"
    NONCE_CACHE = "nonce_cache"
    FRESHNESS_TOKEN = "freshness_token"


class ObservableSinkRole(str, Enum):
    LOG_OUTPUT = "log_output"
    RPC_ERROR_MESSAGE = "rpc_error_message"
    HTTP_RESPONSE_BODY = "http_response_body"
    HTTP_HEADER = "http_header"
    GRPC_STATUS_DETAIL = "grpc_status_detail"
    CLI_OUTPUT = "cli_output"
    EVENT_EMISSION = "event_emission"
    HOST_FILESYSTEM_WRITE = "host_filesystem_write"
    METRICS_LABEL = "metrics_label"
    DEBUG_TRACE = "debug_trace"


# Claim producer kinds (from design 4.4; schema leaves free-form string).
class ClaimProducerKind(str, Enum):
    ATTESTATION_VERIFIER = "attestation_verifier"
    QUOTE_PARSER = "quote_parser"
    RECEIPT_PARSER = "receipt_parser"
    REPORT_VERIFIER = "report_verifier"
    RUNTIME_KEY_FETCHER = "runtime_key_fetcher"
    CONTRACT_VERIFIER = "contract_verifier"
    KEY_MANAGER_VERIFIER = "key_manager_verifier"
    STATE_UNSEALER = "state_unsealer"
    CONFIG_LOADER = "config_loader"


# --------------------------------------------------------------------------- #
# Structural models (trustir.schema.json)
# --------------------------------------------------------------------------- #


class RepoInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    root: str
    commit: str | None = None
    languages: list[str] = []


class EvidenceSpan(BaseModel):
    id: str
    kind: EvidenceKind
    file: str
    start_line: int
    end_line: int
    quote: str | None = None


class Selector(BaseModel):
    """A code location selector (object form, used by producers/authority/guards)."""

    model_config = ConfigDict(extra="allow")

    language: str | None = None
    file: str | None = None
    qualified_name: str | None = None
    line: int | None = None
    column: int | None = None
    abi_signature: str | None = None


class ClaimProducer(BaseModel):
    id: str
    kind: str  # ClaimProducerKind value, but kept permissive for new kinds
    selector: Selector
    output_object: str | None = None
    output_type: str | None = None
    evidence_span_ids: list[str] = []


class ClaimField(BaseModel):
    id: str
    producer_id: str | None = None
    selector: str  # field-access string, e.g. "receipt.publicKey"
    role: ClaimFieldRole
    semantic_type: str | None = None
    security_state_after_producer: SecurityState | None = None
    evidence_span_ids: list[str] = []


class AuthoritySubject(BaseModel):
    model_config = ConfigDict(extra="allow")

    selector: str | None = None
    role: AuthoritySubjectRole | None = None


class AuthorityPoint(BaseModel):
    id: str
    kind: AuthorityKind
    selector: Selector
    authority_subject: AuthoritySubject | None = None
    protected_asset: str | None = None
    evidence_span_ids: list[str] = []


class Guard(BaseModel):
    id: str
    kind: GuardKind
    selector: Selector | None = None
    checked_fields: list[str] = []
    accepted_values: list[str] = []
    failure_behavior: FailureBehavior | None = None
    must_dominate_authority: bool | None = None


class BindingRelation(BaseModel):
    id: str
    kind: BindingRelationKind
    from_claim_field_id: str | None = None
    to_authority_subject: str | None = None
    evidence_selector: str | None = None
    must_control_authority: bool | None = None


class Obligation(BaseModel):
    id: str
    twe_id: str
    family: TaxonomyFamily
    authority_point_id: str
    required_relation: dict[str, Any] = {}
    must_dominate: bool | None = None


class TrustIR(BaseModel):
    """Top-level TrustIR candidate / resolved IR object."""

    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.0"
    repo: RepoInfo
    candidate_id: str
    twe_id: str
    taxonomy_family: TaxonomyFamily
    tee_dimension: TEEDimension | None = None
    trust_context: str
    evidence_spans: list[EvidenceSpan] = []

    claim_producers: list[ClaimProducer] = []
    claim_fields: list[ClaimField] = []
    flow_sources: list[dict[str, Any]] = []
    flow_sinks: list[dict[str, Any]] = []
    authority_points: list[AuthorityPoint] = []
    guards: list[Guard] = []
    binding_relations: list[BindingRelation] = []
    state_objects: list[dict[str, Any]] = []
    config_sources: list[dict[str, Any]] = []
    observable_sinks: list[dict[str, Any]] = []
    suppressors: list[dict[str, Any]] = []
    required_obligations: list[Obligation] = []

    # Only present on *resolved* IR (populated by the binder).
    resolution_summary: dict[str, Any] | None = None


__all__ = [
    # enums
    "TaxonomyFamily",
    "TEEDimension",
    "EvidenceKind",
    "SecurityState",
    "FailureBehavior",
    "FindingStatus",
    "ClaimFieldRole",
    "AuthorityKind",
    "AuthoritySubjectRole",
    "GuardKind",
    "BindingRelationKind",
    "ConfigSourceKind",
    "WeakMode",
    "StateObjectKind",
    "ObservableSinkRole",
    "ClaimProducerKind",
    # models
    "RepoInfo",
    "EvidenceSpan",
    "Selector",
    "ClaimProducer",
    "ClaimField",
    "AuthoritySubject",
    "AuthorityPoint",
    "Guard",
    "BindingRelation",
    "Obligation",
    "TrustIR",
]
