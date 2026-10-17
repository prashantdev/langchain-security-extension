"""
Security Core package exports.

Re-exports core primitives including SecurityIdentity, PolicyDecisionEngine,
AuditManager, CELEvaluator, and exception classes for zero-trust LLM security architecture.
"""

from security_core.identity import (
    SecurityIdentity,
    InvocationParameters,
    IdentityBridge,
)
from security_core.pdp import (
    PolicyEvaluationRequest,
    PolicyDecision,
    PolicyDecisionEngine,
    EmbeddedPolicyEngine,
    RoleGraph,
)
from security_core.cel_evaluator import CELEvaluator
from security_core.registry import SecurityRegistry
from security_core.audit import (
    AuditEvent,
    AuditManager,
    AuditPublisherSPI,
    ConsoleAuditLogger,
)
from security_core.prompt_injection import (
    PromptInjectionScanner,
    PromptInjectionScanResult,
)
from security_core.exceptions import (
    DiagnosticReasonEnum,
    SecurityAuthorizationError,
    AgentAccessDeniedException,
    TenantIsolationError,
    ToolExecutionDeniedError,
    ToolExecutionFeedbackException,
    PolicyViolationError,
)
from security_core.constants import (
    DECISION_PERMIT,
    DECISION_DENY,
    ACTION_AGENT_INVOKE,
    ACTION_TOOL_EXECUTE,
    ACTION_CHUNK_RETRIEVE,
    STRATEGY_HARD_ABORT,
    STRATEGY_RETURN_FEEDBACK,
)
from security_core.pii import (
    PiiSanitizerSPI,
    BuiltInPiiSanitizer,
    PiiContext,
    get_pii_sanitizer,
    set_pii_sanitizer,
    reset_pii_sanitizer,
    get_pii_scope,
    set_pii_scope,
    reset_pii_scope,
    is_valid_luhn,
)

__all__ = [
    "SecurityIdentity",
    "InvocationParameters",
    "IdentityBridge",
    "PolicyEvaluationRequest",
    "PolicyDecision",
    "PolicyDecisionEngine",
    "EmbeddedPolicyEngine",
    "RoleGraph",
    "CELEvaluator",
    "SecurityRegistry",
    "AuditEvent",
    "AuditManager",
    "AuditPublisherSPI",
    "ConsoleAuditLogger",
    "PromptInjectionScanner",
    "PromptInjectionScanResult",
    "DiagnosticReasonEnum",
    "SecurityAuthorizationError",
    "AgentAccessDeniedException",
    "TenantIsolationError",
    "ToolExecutionDeniedError",
    "ToolExecutionFeedbackException",
    "PolicyViolationError",
    "DECISION_PERMIT",
    "DECISION_DENY",
    "ACTION_AGENT_INVOKE",
    "ACTION_TOOL_EXECUTE",
    "ACTION_CHUNK_RETRIEVE",
    "STRATEGY_HARD_ABORT",
    "STRATEGY_RETURN_FEEDBACK",
    "PiiSanitizerSPI",
    "BuiltInPiiSanitizer",
    "PiiContext",
    "get_pii_sanitizer",
    "set_pii_sanitizer",
    "reset_pii_sanitizer",
    "get_pii_scope",
    "set_pii_scope",
    "reset_pii_scope",
    "is_valid_luhn",
]


