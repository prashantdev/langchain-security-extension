"""
Centralized constants for the Security Framework.

Prevents hardcoded strings and inline parameter defaults across the codebase.
Defines decision outcomes, actions, envelope keys, classification levels,
enforcement point identifiers, audit severities, security event taxonomies,
and system operational limits as specified in library-specs.
"""

# Decision Outcomes (Spec 4: PDP Specification)
DECISION_PERMIT: str = "PERMIT"
"""PDP decision granting permission to execute the requested action."""

DECISION_DENY: str = "DENY"
"""PDP decision denying permission to execute the requested action."""

DECISION_NOT_APPLICABLE: str = "NOT_APPLICABLE"
"""PDP decision indicating no matching policy rule was applicable for evaluation."""

DECISION_INDETERMINATE: str = "INDETERMINATE"
"""PDP decision indicating an internal error or evaluation syntax failure occurred during check."""


# Actions (Spec 0 & Spec 4)
ACTION_AGENT_INVOKE: str = "agent:invoke"
"""Action identifier for agent-level execution requests."""

ACTION_TOOL_EXECUTE: str = "tool:execute"
"""Action identifier for tool execution requests intercepted by PEP."""

ACTION_CHUNK_RETRIEVE: str = "chunk:retrieve"
"""Action identifier for vector store document chunk retrieval requests."""

ACTION_MODEL_CHAT: str = "model:chat"
"""Action identifier for downstream LLM model chat invocations."""


# Violation Handling Strategies (Spec 2: Tool Execution Interceptor)
STRATEGY_HARD_ABORT: str = "HARD_ABORT"
"""Strategy raising a ToolExecutionDeniedError immediately upon policy denial."""

STRATEGY_RETURN_FEEDBACK: str = "RETURN_FEEDBACK"
"""Strategy returning sanitized feedback error payload to LLM within retry budget."""


# Metadata Envelope Keys (sec: namespace - Spec 1: Secure Ingestion Pipeline)
SEC_SCHEMA_VERSION: str = "sec:schema_version"
"""Document metadata key holding the security envelope schema version."""

SEC_DOCUMENT_ID: str = "sec:document_id"
"""Document metadata key specifying the unique root document identifier."""

SEC_CHUNK_INDEX: str = "sec:chunk_index"
"""Document metadata key specifying the zero-based index of a chunk within its parent document."""

SEC_TENANT_ID: str = "sec:tenant_id"
"""Document metadata key identifying the target tenant boundary for isolation."""

SEC_CLASSIFICATION_LEVEL: str = "sec:classification_level"
"""Document metadata key storing security classification label (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)."""

SEC_ALLOWED_ROLES: str = "sec:allowed_roles"
"""Document metadata key containing comma-separated list or collection of authorized roles."""

SEC_REQUIRED_ROLES: str = "sec:required_roles"
"""Document metadata key containing mandatory role list for retrieval access."""

SEC_DEPARTMENT_ID: str = "sec:department_id"
"""Document metadata key specifying department organizational boundary."""

SEC_CLEARANCE_FLOOR: str = "sec:clearance_floor"
"""Document metadata key enforcing minimum numeric clearance rank required for retrieval."""

SEC_ENVELOPE_HASH: str = "sec:envelope_hash"
"""Document metadata key holding the HMAC-SHA256 signature verifying metadata integrity."""

SEC_QUARANTINED: str = "sec:quarantined"
"""Document metadata key flag indicating if document is in quarantine status."""


# Classification Level Ranks (Spec 1 & Spec 3)
CLASSIFICATION_PUBLIC: str = "PUBLIC"
"""Public classification label (clearance rank 0)."""

CLASSIFICATION_INTERNAL: str = "INTERNAL"
"""Internal classification label (clearance rank 1)."""

CLASSIFICATION_CONFIDENTIAL: str = "CONFIDENTIAL"
"""Confidential classification label (clearance rank 2)."""

CLASSIFICATION_RESTRICTED: str = "RESTRICTED"
"""Restricted classification label (clearance rank 3)."""

CLEARANCE_RANK_PUBLIC: int = 0
"""Numeric clearance rank assigned to Public classification level."""

CLEARANCE_RANK_INTERNAL: int = 1
"""Numeric clearance rank assigned to Internal classification level."""

CLEARANCE_RANK_CONFIDENTIAL: int = 2
"""Numeric clearance rank assigned to Confidential classification level."""

CLEARANCE_RANK_RESTRICTED: int = 3
"""Numeric clearance rank assigned to Restricted classification level."""

CLASSIFICATION_TO_RANK: dict = {
    CLASSIFICATION_PUBLIC: CLEARANCE_RANK_PUBLIC,
    CLASSIFICATION_INTERNAL: CLEARANCE_RANK_INTERNAL,
    CLASSIFICATION_CONFIDENTIAL: CLEARANCE_RANK_CONFIDENTIAL,
    CLASSIFICATION_RESTRICTED: CLEARANCE_RANK_RESTRICTED,
}
"""Mapping dictionary from classification string labels to numeric clearance ranks."""


# Default Security Attributes & Limits (Spec 4: PDP & Identity Bridge)
DEFAULT_SCHEMA_VERSION: str = "1.0"
"""Default security envelope schema version identifier."""

DEFAULT_TENANT_ID: str = "DEFAULT_TENANT"
"""Fallback tenant identifier assigned when no explicit tenant identity is provided."""

DEFAULT_CLEARANCE_LEVEL: int = 0
"""Default clearance level rank assigned to unprivileged identity contexts."""

DEFAULT_DEPARTMENT_ID: str = "GENERAL"
"""Default department ID assigned when missing from identity attributes."""

ANONYMOUS_SUBJECT_ID: str = "ANONYMOUS"
"""Subject identifier representing an unauthenticated or anonymous user context."""


# Ingestion Policy Modes (Spec 1: Secure Ingestion Pipeline)
INGEST_MODE_STRICT_FAIL_CLOSED: str = "STRICT_FAIL_CLOSED"
"""Ingestion mode rejecting document chunks missing required security metadata."""

INGEST_MODE_EVERYTHING_CLASSIFIED: str = "EVERYTHING_CLASSIFIED"
"""Ingestion mode defaulting missing security metadata to RESTRICTED classification."""

INGEST_MODE_EVERYTHING_PUBLIC: str = "EVERYTHING_PUBLIC"
"""Ingestion mode defaulting missing security metadata to PUBLIC classification."""


# In-Band Security State Key (Spec 4: Identity Bridge)
SECURITY_INVOCATION_PARAMS_KEY: str = "sec:invocation_parameters"
"""Key used to store and extract InvocationParameters from request state or config context."""

SECURITY_METADATA_PREFIX: str = "sec:"
"""Prefix identifying reserved security envelope metadata keys."""

RETRY_COUNT_CONFIG_KEY: str = "sec:retry_count"
"""Key storing tool feedback retry count in invocation configuration."""


# Enforcement Point Identifiers (Spec 0: Architecture Overview)
PEP_AGENT_GUARD: str = "AGENT_GUARD"
"""Policy Enforcement Point for agent execution entry points."""

PEP_TOOL_INTERCEPTOR: str = "TOOL_INTERCEPTOR"
"""Policy Enforcement Point intercepting tool execution requests."""

PEP_RAG_FILTER: str = "RAG_FILTER"
"""Policy Enforcement Point filtering vector store search and retrieval outputs."""

PEP_INGESTION_PIPELINE: str = "INGESTION_PIPELINE"
"""Policy Enforcement Point inspecting and enriching document ingestion pipelines."""

PEP_IDENTITY_BRIDGE: str = "IDENTITY_BRIDGE"
"""Policy Enforcement Point resolving and validating caller identity tokens."""


# Diagnostic Reason Codes (Spec 4 & Spec 5)
REASON_AUTHORIZED: str = "AUTHORIZED"
"""Diagnostic reason code indicating successful policy authorization."""

REASON_TENANT_MISMATCH: str = "TENANT_MISMATCH"
"""Diagnostic reason code indicating tenant ID boundary isolation violation."""

REASON_INSUFFICIENT_CLEARANCE: str = "INSUFFICIENT_CLEARANCE"
"""Diagnostic reason code indicating identity clearance level below required document clearance floor."""

REASON_MISSING_REQUIRED_ROLE: str = "MISSING_REQUIRED_ROLE"
"""Diagnostic reason code indicating caller identity lacks required role entitlement."""

REASON_PARAMETER_CONSTRAINT_FAILED: str = "PARAMETER_CONSTRAINT_FAILED"
"""Diagnostic reason code indicating parameter validation expression evaluated to false."""

REASON_INTERNAL_ERROR: str = "INTERNAL_ERROR"
"""Diagnostic reason code indicating unhandled internal error during policy decision evaluation."""

REASON_UNAUTHENTICATED: str = "UNAUTHENTICATED"
"""Diagnostic reason code indicating missing identity or invalid caller context."""

REASON_INVALID_HMAC: str = "INVALID_HMAC"
"""Diagnostic reason code indicating metadata envelope HMAC signature mismatch."""


# Audit Severities (OCSF/ECS Aligned - Spec 5: Audit & Observability)
SEVERITY_INFORMATIONAL: str = "INFORMATIONAL"
"""Informational log severity for standard operational activity."""

SEVERITY_NOTICE: str = "NOTICE"
"""Notice severity for normal but significant security events."""

SEVERITY_WARNING: str = "WARNING"
"""Warning severity for non-fatal policy violations or retry attempts."""

SEVERITY_SECURITY_ALERT: str = "SECURITY_ALERT"
"""Security alert severity for denied access requests or parameter privilege escalation attempts."""

SEVERITY_CRITICAL_ALERT: str = "CRITICAL_ALERT"
"""Critical alert severity for active policy tampering, identity spoofing, or tenant violation."""


# Backward compatibility aliases (Spec 5)
AUDIT_SEVERITY_INFO: str = SEVERITY_INFORMATIONAL
"""Alias for SEVERITY_INFORMATIONAL."""

AUDIT_SEVERITY_WARN: str = SEVERITY_WARNING
"""Alias for SEVERITY_WARNING."""

AUDIT_SEVERITY_ERROR: str = SEVERITY_SECURITY_ALERT
"""Alias for SEVERITY_SECURITY_ALERT."""

AUDIT_SEVERITY_CRITICAL: str = SEVERITY_CRITICAL_ALERT
"""Alias for SEVERITY_CRITICAL_ALERT."""


# Security Event Taxonomy (21 Standard Events - Spec 5: Audit & Observability)
EVENT_AGENT_ACCESS_PERMITTED: str = "AGENT_ACCESS_PERMITTED"
"""Audit event emitted when agent execution request is granted by PDP."""

EVENT_AGENT_ACCESS_DENIED: str = "AGENT_ACCESS_DENIED"
"""Audit event emitted when agent execution request is denied by PDP."""

EVENT_TOOL_EXECUTE_PERMITTED: str = "TOOL_EXECUTE_PERMITTED"
"""Audit event emitted when tool invocation passes PDP evaluation and parameter constraints."""

EVENT_TOOL_FEEDBACK_VIOLATION: str = "TOOL_FEEDBACK_VIOLATION"
"""Audit event emitted when tool constraint failure triggers return feedback to LLM."""

EVENT_TOOL_HARD_ABORT_TRIGGERED: str = "TOOL_HARD_ABORT_TRIGGERED"
"""Audit event emitted when tool execution is denied under HARD_ABORT strategy."""

EVENT_TOOL_RETRY_BUDGET_EXCEEDED: str = "TOOL_RETRY_BUDGET_EXCEEDED"
"""Audit event emitted when maximum tool retry attempts have been reached."""

EVENT_RAG_UNAUTHORIZED_PRUNING: str = "RAG_UNAUTHORIZED_PRUNING"
"""Audit event emitted when retrieved document chunks are pruned due to clearance/role mismatch."""

EVENT_RAG_RESULT_STARVATION: str = "EVENT_RAG_RESULT_STARVATION"
"""Audit event emitted when all retrieved vector store candidates are pruned by security filter."""

EVENT_INGEST_CHUNK_REJECTED: str = "INGEST_CHUNK_REJECTED"
"""Audit event emitted when document ingestion fails strict validation mode."""

EVENT_INGEST_CHUNK_QUARANTINED: str = "INGEST_CHUNK_QUARANTINED"
"""Audit event emitted when ingested chunk fails integrity checks and is placed in quarantine."""

EVENT_INGEST_CHUNK_DEFAULT_PUBLIC: str = "INGEST_CHUNK_DEFAULT_PUBLIC"
"""Audit event emitted when ingested chunk lacking security tags defaults to public."""

EVENT_POLICY_TAMPER_DETECTED: str = "POLICY_TAMPER_DETECTED"
"""Audit event emitted when metadata HMAC verification fails or envelope tampering is detected."""

EVENT_PROMPT_INJECTION_DETECTED: str = "PROMPT_INJECTION_DETECTED"
"""Audit event emitted when prompt injection scanner identifies suspicious input patterns."""

EVENT_INSTRUCTION_OVERRIDE_ATTEMPT: str = "INSTRUCTION_OVERRIDE_ATTEMPT"
"""Audit event emitted when input text contains jailbreak or system prompt override instructions."""

EVENT_IDENTITY_SPOOFING_ATTEMPT: str = "IDENTITY_SPOOFING_ATTEMPT"
"""Audit event emitted when caller identity context does not match authenticated token."""

EVENT_TENANT_BOUND_VIOLATION: str = "TENANT_BOUND_VIOLATION"
"""Audit event emitted when access request crosses isolated tenant boundaries."""

EVENT_IDENTITY_CONTEXT_TAMPERING: str = "IDENTITY_CONTEXT_TAMPERING"
"""Audit event emitted when security context holder detects modified identity state."""

EVENT_ROLE_ELEVATION_ATTEMPT: str = "ROLE_ELEVATION_ATTEMPT"
"""Audit event emitted when caller attempts unauthorized role escalation."""

EVENT_CLEARANCE_VIOLATION_ATTEMPT: str = "CLEARANCE_VIOLATION_ATTEMPT"
"""Audit event emitted when caller identity attempts to access higher clearance document."""

EVENT_PARAMETER_PRIVILEGE_ESCALATION: str = "PARAMETER_PRIVILEGE_ESCALATION"
"""Audit event emitted when tool invocation parameters attempt privilege escalation."""

EVENT_POLICY_BRUTE_FORCE_DETECTED: str = "POLICY_BRUTE_FORCE_DETECTED"
"""Audit event emitted when rapid repeated access denials suggest policy brute force scanning."""


# Limits & System Defaults (Spec 2, Spec 3, Spec 4, Spec 5)
DEFAULT_MAX_FEEDBACK_VIOLATIONS: int = 2
"""Default maximum feedback violation retries permitted per tool execution before hard abort."""

DEFAULT_OVERSAMPLING_FACTOR: float = 3.0
"""Default retrieval oversampling multiplier applied to k candidates before security pruning."""

DEFAULT_MAX_FETCH_CAP: int = 50
"""Default absolute upper limit on vector store candidate fetch size."""

DEFAULT_RING_BUFFER_CAPACITY: int = 16384
"""Default maximum capacity for async in-memory audit log ring buffer."""

DEFAULT_PAYLOAD_MAX_CHARS: int = 2048
"""Default maximum character limit for sanitized audit payload details."""

DEFAULT_REMOTE_PDP_TIMEOUT_SECONDS: float = 0.250
"""Default timeout in seconds for remote HTTP PDP evaluation requests."""

DEFAULT_CIRCUIT_BREAKER_THRESHOLD: int = 5
"""Default consecutive error count triggering remote PDP circuit breaker open state."""


# Vector Store Capability Profiles (Spec 3: Contextual Retrieval Filter)
STORE_PROFILE_FULL_AST: str = "FULL_AST"
"""Vector store capability profile supporting full translation of security filter AST to native queries."""

STORE_PROFILE_CONSTRAINED: str = "CONSTRAINED"
"""Vector store capability profile supporting simplified metadata equality filtering."""

STORE_PROFILE_NO_FILTER: str = "NO_FILTER"
"""Vector store capability profile performing zero native filtering, relying entirely on post-pruning."""


# Secondary Paging & Retrieval Defaults (Spec 3)
DEFAULT_MAX_SECONDARY_FETCHES: int = 2
"""Maximum number of secondary fetch iterations attempted during vector retrieval pagination."""

DEFAULT_SIMILARITY_CUTOFF: float = 0.0
"""Default similarity score threshold below which vector search candidates are discarded."""


# Diagnostic Reason Codes (Extended - Spec 4 & Spec 5)
REASON_POLICY_BRUTE_FORCE: str = "POLICY_BRUTE_FORCE"
"""Diagnostic reason code for suspected policy brute force detection."""

REASON_PARAMETER_PRIVILEGE_ESCALATION: str = "PARAMETER_PRIVILEGE_ESCALATION"
"""Diagnostic reason code for parameter privilege escalation violation."""

REASON_RAG_STARVATION: str = "RAG_STARVATION"
"""Diagnostic reason code when all vector store results are pruned by security filter."""

REASON_RAG_UNAUTHORIZED: str = "RAG_UNAUTHORIZED"
"""Diagnostic reason code when vector store candidate fails clearance or role checks."""

# Retry Budget & Violation Codes (Spec 2: Tool Execution Interceptor)
DEFAULT_MAX_FEEDBACK_VIOLATIONS: int = 2
"""Default retry allowance before escalating tool feedback denial to hard abort."""

EVENT_TOOL_RETRY_BUDGET_EXCEEDED: str = "TOOL_RETRY_BUDGET_EXCEEDED"
"""Security audit event when model repeatedly attempts unauthorized actions exceeding retry budget."""

REASON_FAIL_CLOSED_NULL_ENTITY: str = "FAIL_CLOSED_NULL_ENTITY"
"""Diagnostic reason when an entity attribute resolution encounters an unresolvable or null entity ID."""

REASON_INVALID_ENTITY: str = "INVALID_ENTITY"
"""Diagnostic reason when an operation targets an invalid or non-existent entity."""

CONFIG_KEY_RETRY_COUNT: str = "sec:retry_count"
"""RunnableConfig configurable key holding the invocation-scoped tool denial retry count."""

CONFIG_KEY_PREV_ARGS: str = "sec:prev_args"
"""RunnableConfig configurable key storing previous tool arguments for privilege escalation detection."""

CONFIG_KEY_DECISION_CACHE: str = "sec:decision_cache"
"""RunnableConfig configurable key storing Tier 1 invocation-scoped PDP decisions."""

CONFIG_KEY_ENTITY_CACHE: str = "sec:entity_cache"
"""RunnableConfig configurable key storing invocation-scoped hydrated entity attributes."""

# Circuit Breaker State Machine Constants (Spec 4)
CB_STATE_CLOSED: str = "CLOSED"
"""Circuit breaker normal operating state."""

CB_STATE_OPEN: str = "OPEN"
"""Circuit breaker tripped state failing closed immediately."""

CB_STATE_HALF_OPEN: str = "HALF_OPEN"
"""Circuit breaker recovery probe state."""

DEFAULT_CIRCUIT_BREAKER_RECOVERY_SECONDS: float = 30.0
"""Default recovery window in seconds before transitioning from OPEN to HALF_OPEN."""

EVENT_CIRCUIT_BREAKER_OPEN: str = "CIRCUIT_BREAKER_OPEN"
"""Audit event reason code emitted when remote PDP circuit breaker trips to OPEN."""

EVENT_CIRCUIT_BREAKER_TRANSITION: str = "CIRCUIT_BREAKER_TRANSITION"
"""Audit event reason code emitted when remote PDP circuit breaker transitions state."""

# Two-Tier Decision Cache Constants (Spec 4)
DEFAULT_CACHE_TTL_SECONDS: float = 300.0
"""Default time-to-live in seconds for Tier 2 static decision cache."""

DEFAULT_CACHE_MAX_ENTRIES: int = 4096
"""Default maximum number of entries in Tier 2 static decision cache."""

EVENT_CACHE_EVICTED: str = "CACHE_EVICTED"
"""Audit event reason code emitted when L1/L2 PDP cache is invalidated on identity/role change."""

REASON_QUARANTINED_CHUNK: str = "QUARANTINED_CHUNK_RESTRICTED"
"""Diagnostic reason code when a quarantined document chunk is denied during retrieval."""

# Enricher & Schema Concealment Constants (Spec 1 & Spec 2)
SEC_MONOTONIC_ELEVATION_ENFORCED: str = "sec:monotonic_elevation_enforced"
"""Document metadata key indicating monotonic classification elevation or de-escalation rejection."""

SEC_DLP_FLAGGED: str = "sec:dlp_flagged"
"""Document metadata key indicating DLP scanner detected sensitive content in chunk."""

EVENT_MONOTONIC_ELEVATION_ENFORCED: str = "MONOTONIC_ELEVATION_ENFORCED"
"""Audit event reason code when monotonic classification elevation blocks a de-escalation attempt."""

EVENT_INGEST_HEADER_ELEVATED: str = "INGEST_HEADER_ELEVATED"
"""Audit event reason code when structural heading or SPI enricher elevates chunk classification floor."""

EVENT_SCHEMA_HIDING_VERIFIED: str = "SCHEMA_HIDING_VERIFIED"
"""Audit/telemetry marker confirming injected security parameters are hidden from LLM tool schemas."""

HIDDEN_SECURITY_PARAMS: tuple = ("security_identity", "config", "runnable_config", "sec_context")
"""Parameter names automatically concealed from model-facing tool JSON schemas."""

# Abuse Throttle Constants (Spec 2 & Spec 5)
DEFAULT_ABUSE_WINDOW_SECONDS: float = 60.0
"""Sliding window in seconds for per-subject denial abuse throttling."""

DEFAULT_ABUSE_MAX_DENIALS: int = 3
"""Maximum denied tool executions allowed within sliding window before emitting brute-force scanning alert."""

EVENT_POLICY_BRUTE_FORCE_SCANNING: str = "POLICY_BRUTE_FORCE_SCANNING"
"""Audit event reason code emitted when rapid denied executions trigger brute-force scanning alert."""

PEP_RUNNABLE_ENTRY: str = PEP_AGENT_GUARD
"""Alias for PEP_AGENT_GUARD used at SecureRunnable entry gates."""

CONFIG_KEY_SECURITY_IDENTITY: str = "security_identity"
"""RunnableConfig configurable key holding the active SecurityIdentity instance."""

CONFIG_KEY_INVOCATION_PARAMS: str = SECURITY_INVOCATION_PARAMS_KEY
"""RunnableConfig configurable key holding serialized InvocationParameters."""



