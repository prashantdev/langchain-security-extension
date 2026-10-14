"""
Tool violation handler, retry budget tracking, and abuse throttle components.

Implements anti-loop retry budget caps and abuse throttling boundaries
for function-calling agent loops as specified in Spec 2 and Spec 5.
"""

import time
from typing import Dict, Any, Optional, List
from security_core.identity import SecurityIdentity, IdentityBridge
from security_core.pdp import PolicyDecisionEngine
from security_core.audit import AuditEvent
from security_core.constants import (
    ACTION_TOOL_EXECUTE,
    PEP_TOOL_INTERCEPTOR,
    SEVERITY_CRITICAL_ALERT,
    EVENT_POLICY_BRUTE_FORCE_DETECTED,
    EVENT_POLICY_BRUTE_FORCE_SCANNING,
    DEFAULT_ABUSE_WINDOW_SECONDS,
    DEFAULT_ABUSE_MAX_DENIALS,
)
from security_core.exceptions import ToolExecutionDeniedError

STATUS_BLOCKED_BY_POLICY: str = "BLOCKED_BY_POLICY"
REMED_SEC_BLOCKED_POLICY: str = "BLOCKED_POLICY"
REMED_EXEC_ABORTED: str = "ABORTED"
DEFAULT_MAX_FEEDBACK_VIOLATIONS: int = 2
CONFIG_RETRY_COUNT_KEY: str = "sec:retry_count"
CONFIG_PREV_ARGS_KEY: str = "sec:prev_args"
CONFIG_LAST_VIOLATION_KEY: str = "sec:last_violation"


class ViolationResolution:
    """Represents the structured resolution of a policy violation.

    Attributes:
        status (str): Overall final status token.
        action_entry (str): Telemetry action string to record.
        root_cause (str): Diagnostic root cause classification.
        user_message (str): Sanitized explanation for end-user.
        remediation_security (str): Security stage evaluation status.
        remediation_execution (str): Execution stage evaluation status.
        should_abort (bool): Whether agent loop must abort immediately.
        diagnostic_reason (Optional[str]): Detailed diagnostic reason code.
        tool_name (Optional[str]): Target tool name associated with violation.
    """

    def __init__(
        self,
        status: str,
        action_entry: str,
        root_cause: str,
        user_message: str,
        remediation_security: str,
        remediation_execution: str,
        should_abort: bool,
        diagnostic_reason: Optional[str],
        tool_name: Optional[str],
    ):
        self._status = status
        self._action_entry = action_entry
        self._root_cause = root_cause
        self._user_message = user_message
        self._remediation_security = remediation_security
        self._remediation_execution = remediation_execution
        self._should_abort = should_abort
        self._diagnostic_reason = diagnostic_reason
        self._tool_name = tool_name

    @classmethod
    def create(
        cls,
        status: str,
        action_entry: str,
        root_cause: str,
        user_message: str,
        remediation_security: str,
        remediation_execution: str,
        should_abort: bool,
        diagnostic_reason: Optional[str],
        tool_name: Optional[str],
    ) -> "ViolationResolution":
        return cls(
            status=status,
            action_entry=action_entry,
            root_cause=root_cause,
            user_message=user_message,
            remediation_security=remediation_security,
            remediation_execution=remediation_execution,
            should_abort=should_abort,
            diagnostic_reason=diagnostic_reason,
            tool_name=tool_name,
        )

    @property
    def status(self) -> str:
        return self._status

    @property
    def action_entry(self) -> str:
        return self._action_entry

    @property
    def root_cause(self) -> str:
        return self._root_cause

    @property
    def user_message(self) -> str:
        return self._user_message

    @property
    def remediation_security(self) -> str:
        return self._remediation_security

    @property
    def remediation_execution(self) -> str:
        return self._remediation_execution

    @property
    def should_abort(self) -> bool:
        return self._should_abort

    @property
    def diagnostic_reason(self) -> Optional[str]:
        return self._diagnostic_reason

    @property
    def tool_name(self) -> Optional[str]:
        return self._tool_name


class RetryBudgetTracker:
    """Invocation-scoped retry budget tracker preventing recursive LLM retry loops."""

    def __init__(self, max_feedback_violations: int):
        self._max_feedback_violations = max_feedback_violations

    @classmethod
    def create(cls, max_feedback_violations: int) -> "RetryBudgetTracker":
        return cls(max_feedback_violations=max_feedback_violations)

    @property
    def max_feedback_violations(self) -> int:
        return self._max_feedback_violations

    def get_retry_count(self, config: Optional[Dict[str, Any]]) -> int:
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            return int(config["configurable"].get(CONFIG_RETRY_COUNT_KEY, 0))
        return 0

    def increment_retry_count(self, config: Optional[Dict[str, Any]]) -> int:
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            count = int(config["configurable"].get(CONFIG_RETRY_COUNT_KEY, 0)) + 1
            config["configurable"][CONFIG_RETRY_COUNT_KEY] = count
            return count
        return 0

    def is_budget_exceeded(self, config: Optional[Dict[str, Any]]) -> bool:
        return self.get_retry_count(config) > self._max_feedback_violations

    def reset(self, config: Optional[Dict[str, Any]]) -> None:
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"][CONFIG_RETRY_COUNT_KEY] = 0


class AbuseThrottleTracker:
    """Sliding-window abuse throttle tracker detecting rapid cross-invocation denial floods."""

    def __init__(self, window_seconds: float, max_denials: int):
        self._window_seconds = window_seconds
        self._max_denials = max_denials
        self._denial_history: Dict[str, List[float]] = {}

    @classmethod
    def create(cls, window_seconds: float, max_denials: int) -> "AbuseThrottleTracker":
        return cls(window_seconds=window_seconds, max_denials=max_denials)

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    @property
    def max_denials(self) -> int:
        return self._max_denials

    def _prune(self, subject_id: str, current_time: float) -> List[float]:
        cutoff = current_time - self._window_seconds
        timestamps = [t for t in self._denial_history.get(subject_id, []) if t >= cutoff]
        self._denial_history[subject_id] = timestamps
        return timestamps

    def record_denial(self, subject_id: str, timestamp: float) -> bool:
        timestamps = self._prune(subject_id, timestamp)
        timestamps.append(timestamp)
        self._denial_history[subject_id] = timestamps
        return len(timestamps) >= self._max_denials

    def is_throttled(self, subject_id: str, timestamp: float) -> bool:
        timestamps = self._prune(subject_id, timestamp)
        return len(timestamps) >= self._max_denials


class ToolViolationHandler:
    """PEP violation handler integrating retry tracking, abuse throttling, and fallback generation."""

    def __init__(
        self,
        pdp_engine: PolicyDecisionEngine,
        retry_tracker: RetryBudgetTracker,
        abuse_tracker: AbuseThrottleTracker,
    ):
        self._pdp_engine = pdp_engine
        self._retry_tracker = retry_tracker
        self._abuse_tracker = abuse_tracker

    @classmethod
    def create(
        cls,
        pdp_engine: PolicyDecisionEngine,
        retry_tracker: RetryBudgetTracker,
        abuse_tracker: AbuseThrottleTracker,
    ) -> "ToolViolationHandler":
        return cls(
            pdp_engine=pdp_engine,
            retry_tracker=retry_tracker,
            abuse_tracker=abuse_tracker,
        )

    @classmethod
    def default_handler(cls, pdp_engine: PolicyDecisionEngine) -> "ToolViolationHandler":
        retry_tracker = RetryBudgetTracker.create(max_feedback_violations=DEFAULT_MAX_FEEDBACK_VIOLATIONS)
        abuse_tracker = AbuseThrottleTracker.create(
            window_seconds=DEFAULT_ABUSE_WINDOW_SECONDS,
            max_denials=DEFAULT_ABUSE_MAX_DENIALS,
        )
        return cls.create(
            pdp_engine=pdp_engine,
            retry_tracker=retry_tracker,
            abuse_tracker=abuse_tracker,
        )

    @property
    def pdp_engine(self) -> PolicyDecisionEngine:
        return self._pdp_engine

    @property
    def retry_tracker(self) -> RetryBudgetTracker:
        return self._retry_tracker

    @property
    def abuse_tracker(self) -> AbuseThrottleTracker:
        return self._abuse_tracker

    def resolve_tool_exception(
        self,
        exc: Exception,
        config: Optional[Dict[str, Any]],
    ) -> ViolationResolution:
        tool_name = getattr(exc, "tool_name", "unknown_tool")
        diagnostic_reason = getattr(exc, "diagnostic_reason", None) or str(exc)

        is_budget_exceeded = self._retry_tracker.is_budget_exceeded(config)
        caller_identity = IdentityBridge.extract_from_config(config)

        if caller_identity is not None and self._abuse_tracker.record_denial(caller_identity.subject_id, time.time()):
            audit_mgr = getattr(self._pdp_engine, "audit_manager", None)
            if audit_mgr is not None:
                audit_mgr.record_event(
                    AuditEvent.create(
                        subject_id=caller_identity.subject_id,
                        tenant_id=caller_identity.tenant_id,
                        action=ACTION_TOOL_EXECUTE,
                        resource=tool_name,
                        decision="HARD_ABORT",
                        diagnostic_reason="Abuse throttle threshold exceeded: Brute-force scanning detected across window",
                        severity=SEVERITY_CRITICAL_ALERT,
                        metadata={"tool_name": tool_name},
                        enforcement_point=PEP_TOOL_INTERCEPTOR,
                        reason_code=EVENT_POLICY_BRUTE_FORCE_SCANNING,
                    )
                )

        if is_budget_exceeded:
            audit_mgr = getattr(self._pdp_engine, "audit_manager", None)
            if audit_mgr is not None and caller_identity is not None:
                audit_mgr.record_event(
                    AuditEvent.create(
                        subject_id=caller_identity.subject_id,
                        tenant_id=caller_identity.tenant_id,
                        action=ACTION_TOOL_EXECUTE,
                        resource=tool_name,
                        decision="HARD_ABORT",
                        diagnostic_reason="Retry budget exceeded: Policy brute force probe detected",
                        severity=SEVERITY_CRITICAL_ALERT,
                        metadata={"tool_name": tool_name},
                        enforcement_point=PEP_TOOL_INTERCEPTOR,
                        reason_code=EVENT_POLICY_BRUTE_FORCE_DETECTED,
                    )
                )
            root_cause = "Policy Abort: POLICY_BRUTE_FORCE_SCANNING"
            user_msg = f"Execution halted: retry budget exceeded (POLICY_BRUTE_FORCE_DETECTED on {tool_name})"
            action_entry = f"Blocked execution of tool '{tool_name}' (retry budget exceeded)"
        else:
            root_cause = f"Policy violation: Access denied for tool '{tool_name}' ({diagnostic_reason})"
            user_msg = f"Policy violation: Access denied for tool '{tool_name}' ({diagnostic_reason})"
            action_entry = f"Blocked execution of tool '{tool_name}' ({diagnostic_reason})"

        resolution = ViolationResolution.create(
            status=STATUS_BLOCKED_BY_POLICY,
            action_entry=action_entry,
            root_cause=root_cause,
            user_message=user_msg,
            remediation_security=REMED_SEC_BLOCKED_POLICY,
            remediation_execution=REMED_EXEC_ABORTED,
            should_abort=True,
            diagnostic_reason=diagnostic_reason,
            tool_name=tool_name,
        )

        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"][CONFIG_LAST_VIOLATION_KEY] = resolution

        return resolution


__all__ = [
    "STATUS_BLOCKED_BY_POLICY",
    "REMED_SEC_BLOCKED_POLICY",
    "REMED_EXEC_ABORTED",
    "DEFAULT_MAX_FEEDBACK_VIOLATIONS",
    "ViolationResolution",
    "RetryBudgetTracker",
    "AbuseThrottleTracker",
    "ToolViolationHandler",
]
