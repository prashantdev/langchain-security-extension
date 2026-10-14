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
    InMemoryAuditLogger,
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
    "InMemoryAuditLogger",
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
]

