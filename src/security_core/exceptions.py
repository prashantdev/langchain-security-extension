"""
Exception taxonomy for security authorization and PEP violations.

Provides typed exceptions for agent access denials, tool execution constraints,
ingestion rejections, audit buffer overflows, and prompt injection detections
as specified in library-specs.
"""

from enum import Enum
from typing import Optional, Dict, Any
from security_core.constants import (
    REASON_AUTHORIZED,
    REASON_TENANT_MISMATCH,
    REASON_INSUFFICIENT_CLEARANCE,
    REASON_MISSING_REQUIRED_ROLE,
    REASON_PARAMETER_CONSTRAINT_FAILED,
    REASON_FAIL_CLOSED_NULL_ENTITY,
    REASON_INVALID_ENTITY,
    REASON_INTERNAL_ERROR,
    REASON_UNAUTHENTICATED,
    REASON_INVALID_HMAC,
)


class DiagnosticReasonEnum(str, Enum):
    """Structured diagnostic reason enumeration for policy decisions and exceptions."""
    AUTHORIZED = REASON_AUTHORIZED
    TENANT_MISMATCH = REASON_TENANT_MISMATCH
    INSUFFICIENT_CLEARANCE = REASON_INSUFFICIENT_CLEARANCE
    MISSING_REQUIRED_ROLE = REASON_MISSING_REQUIRED_ROLE
    PARAMETER_CONSTRAINT_FAILED = REASON_PARAMETER_CONSTRAINT_FAILED
    FAIL_CLOSED_NULL_ENTITY = REASON_FAIL_CLOSED_NULL_ENTITY
    INVALID_ENTITY = REASON_INVALID_ENTITY
    INTERNAL_ERROR = REASON_INTERNAL_ERROR
    UNAUTHENTICATED = REASON_UNAUTHENTICATED
    INVALID_HMAC = REASON_INVALID_HMAC


class SecurityAuthorizationError(Exception):
    """Base exception for all security authorization failures across PEP enforcement points.

    Attributes:
        message (str): Human-readable error description.
        diagnostic_reason (Optional[str]): Standard diagnostic reason code.
        obligations (Optional[Dict[str, Any]]): Map of policy enforcement obligations.
    """

    def __init__(self, message: str, diagnostic_reason: Optional[str], obligations: Optional[Dict[str, Any]]):
        """Initialize SecurityAuthorizationError.

        Args:
            message: Human-readable error description.
            diagnostic_reason: Diagnostic reason code from PDP evaluation.
            obligations: Key-value mapping of policy enforcement obligations.
        """
        super().__init__(message)
        self.message = message
        self.diagnostic_reason = diagnostic_reason
        self.obligations = obligations

    @property
    def is_tenant_violation(self) -> bool:
        """Check whether this authorization failure is a cross-tenant isolation violation."""
        return self.diagnostic_reason == DiagnosticReasonEnum.TENANT_MISMATCH

    @classmethod
    def create(cls, message: str, diagnostic_reason: Optional[str], obligations: Optional[Dict[str, Any]]):
        """Factory method to instantiate a SecurityAuthorizationError.

        Args:
            message: Human-readable error description.
            diagnostic_reason: Diagnostic reason code.
            obligations: Dictionary of obligations.

        Returns:
            SecurityAuthorizationError: New exception instance.
        """
        return cls(message, diagnostic_reason, obligations)


class AgentAccessDeniedException(SecurityAuthorizationError):
    """Exception raised when entry invocation to an agent or Runnable is denied by PDP.

    Attributes:
        agent_name (str): Identifier of the agent or Runnable target.
    """

    def __init__(self, agent_name: str, message: str, diagnostic_reason: Optional[str]):
        """Initialize AgentAccessDeniedException.

        Args:
            agent_name: Name or ID of the protected agent.
            message: Error description message.
            diagnostic_reason: Reason code explaining denial.
        """
        super().__init__(message, diagnostic_reason, None)
        self.agent_name = agent_name

    @classmethod
    def for_agent(cls, agent_name: str, message: str, diagnostic_reason: Optional[str]):
        """Factory method creating an AgentAccessDeniedException or TenantIsolationError for a named agent.

        Args:
            agent_name: Target agent identifier.
            message: Exception message.
            diagnostic_reason: Reason code explaining the decision.

        Returns:
            AgentAccessDeniedException: Constructed exception instance.
        """
        if diagnostic_reason == DiagnosticReasonEnum.TENANT_MISMATCH:
            return TenantIsolationError(agent_name, message, diagnostic_reason)
        return cls(agent_name, message, diagnostic_reason)


class TenantIsolationError(AgentAccessDeniedException):
    """Typed exception raised when an agent invocation violates tenant boundary isolation."""
    pass


class ToolExecutionDeniedError(SecurityAuthorizationError):
    """Hard abort exception raised when a tool execution is prohibited by policy.

    Attributes:
        tool_name (str): Name of the tool execution attempt that was aborted.
    """

    def __init__(self, tool_name: str, message: str, diagnostic_reason: Optional[str]):
        """Initialize ToolExecutionDeniedError.

        Args:
            tool_name: Name of the prohibited tool.
            message: Error details.
            diagnostic_reason: Diagnostic reason for denial.
        """
        super().__init__(message, diagnostic_reason, None)
        self.tool_name = tool_name

    @classmethod
    def for_tool(cls, tool_name: str, message: str, diagnostic_reason: Optional[str]):
        """Factory method creating a ToolExecutionDeniedError for a named tool.

        Args:
            tool_name: Prohibited tool identifier.
            message: Detailed error message.
            diagnostic_reason: Diagnostic reason code.

        Returns:
            ToolExecutionDeniedError: Constructed exception instance.
        """
        return cls(tool_name, message, diagnostic_reason)


# Spec alias for ToolExecutionDeniedError
ToolExecutionDeniedException = ToolExecutionDeniedError
"""Alias for ToolExecutionDeniedError for specification naming compatibility."""


class ToolExecutionFeedbackException(SecurityAuthorizationError):
    """Exception carrying synthetic model refusal feedback for non-mutative tool violations.

    Attributes:
        tool_name (str): Tool that encountered constraint violation.
        refusal_payload (Dict[str, Any]): Structured feedback dictionary returned to LLM.
    """

    def __init__(self, tool_name: str, refusal_payload: Dict[str, Any]):
        """Initialize ToolExecutionFeedbackException.

        Args:
            tool_name: Name of tool being invoked.
            refusal_payload: Structured refusal payload for model consumption.
        """
        super().__init__(f"Tool execution denied with feedback: {tool_name}", None, None)
        self.tool_name = tool_name
        self.refusal_payload = refusal_payload

    @classmethod
    def create_payload(cls, tool_name: str, refusal_payload: Dict[str, Any]):
        """Factory method creating a ToolExecutionFeedbackException with refusal payload.

        Args:
            tool_name: Name of target tool.
            refusal_payload: Refusal details for model retry loop.

        Returns:
            ToolExecutionFeedbackException: Exception instance containing feedback.
        """
        return cls(tool_name, refusal_payload)


class IngestionRejectedException(SecurityAuthorizationError):
    """Exception raised when a document chunk fails validation under strict fail-closed ingestion mode.

    Attributes:
        document_id (str): Document root ID.
        chunk_index (int): Index of the rejected document chunk.
    """

    def __init__(self, document_id: str, chunk_index: int, message: str):
        """Initialize IngestionRejectedException.

        Args:
            document_id: Identifier of document being ingested.
            chunk_index: Index of problematic chunk.
            message: Rejection error message.
        """
        super().__init__(message, "INGEST_REJECTED", None)
        self.document_id = document_id
        self.chunk_index = chunk_index

    @classmethod
    def create_rejection(cls, document_id: str, chunk_index: int, message: str):
        """Factory method creating an IngestionRejectedException for a document chunk.

        Args:
            document_id: Document root ID.
            chunk_index: Chunk index.
            message: Rejection message.

        Returns:
            IngestionRejectedException: Constructed exception instance.
        """
        return cls(document_id, chunk_index, message)


class AuditBufferFullException(SecurityAuthorizationError):
    """Exception raised or metric logged when the security audit queue buffer overflows."""

    def __init__(self, message: str):
        """Initialize AuditBufferFullException.

        Args:
            message: Error description of buffer overflow condition.
        """
        super().__init__(message, "AUDIT_BUFFER_FULL", None)

    @classmethod
    def create_overflow(cls, message: str):
        """Factory method creating an AuditBufferFullException.

        Args:
            message: Description of overflow state.

        Returns:
            AuditBufferFullException: New exception instance.
        """
        return cls(message)


class PolicyViolationError(SecurityAuthorizationError):
    """Exception raised when policy configuration or static rule validation fails."""
    pass


class PromptInjectionDetectedException(SecurityAuthorizationError):
    """Exception raised when a prompt injection or jailbreak instruction is detected.

    Attributes:
        pattern_id (str): Identifier of the matching prompt injection pattern.
        scan_result (Any): Scan result detail object.
    """

    def __init__(self, pattern_id: str, message: str, scan_result: Any):
        """Initialize PromptInjectionDetectedException.

        Args:
            pattern_id: Matched injection pattern ID.
            message: Scan result message.
            scan_result: Detail result object from scanner.
        """
        super().__init__(message, f"PROMPT_INJECTION_DETECTED:{pattern_id}", None)
        self.pattern_id = pattern_id
        self.scan_result = scan_result

    @classmethod
    def create(cls, pattern_id: str, message: str, scan_result: Any):
        """Factory method creating a PromptInjectionDetectedException.

        Args:
            pattern_id: Injection pattern identifier.
            message: Detailed error message.
            scan_result: Full scanner result object.

        Returns:
            PromptInjectionDetectedException: Constructed exception instance.
        """
        return cls(pattern_id, message, scan_result)


SecurityValidationException = IngestionRejectedException
"""Alias for IngestionRejectedException for specification naming compatibility."""




