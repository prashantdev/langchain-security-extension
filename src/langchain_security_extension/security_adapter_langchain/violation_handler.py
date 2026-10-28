"""
Tool violation handler, retry budget tracking, and abuse throttle components.

Implements anti-loop retry budget caps and abuse throttling boundaries
for function-calling agent loops as specified in Spec 2 and Spec 5.
"""

import time
from typing import Dict, Any, Optional, List
from langchain_security_extension.security_core.identity import SecurityIdentity, IdentityBridge
from langchain_security_extension.security_core.pdp import PolicyDecisionEngine
from langchain_security_extension.security_core.audit import AuditEvent
from langchain_security_extension.security_core.constants import (
    ACTION_TOOL_EXECUTE,
    PEP_TOOL_INTERCEPTOR,
    SEVERITY_CRITICAL_ALERT,
    EVENT_POLICY_BRUTE_FORCE_DETECTED,
    EVENT_POLICY_BRUTE_FORCE_SCANNING,
    DEFAULT_ABUSE_WINDOW_SECONDS,
    DEFAULT_ABUSE_MAX_DENIALS,
)

STATUS_BLOCKED_BY_POLICY: str = "BLOCKED_BY_POLICY"
POLICY_STATUS_BLOCKED: str = "BLOCKED_POLICY"
POLICY_STATUS_FEEDBACK: str = "FEEDBACK_REFUSAL"
EXECUTION_ACTION_ABORTED: str = "ABORTED"
EXECUTION_ACTION_FEEDBACK: str = "SYNTHETIC_PAYLOAD"
REMED_SEC_BLOCKED_POLICY: str = POLICY_STATUS_BLOCKED
REMED_EXEC_ABORTED: str = EXECUTION_ACTION_ABORTED
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
        policy_decision (str): Policy evaluation outcome (e.g., BLOCKED_POLICY, FEEDBACK_REFUSAL).
        execution_action (str): Runtime execution action (e.g., ABORTED, SYNTHETIC_PAYLOAD).
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
        policy_decision: str,
        execution_action: str,
        should_abort: bool,
        diagnostic_reason: Optional[str],
        tool_name: Optional[str],
    ):
        """Initialize ViolationResolution.

        Args:
            status: Overall final status token (e.g. BLOCKED_BY_POLICY, ACCESS_DENIED).
            action_entry: Telemetry log entry action description.
            root_cause: Diagnostic root cause classification.
            user_message: Sanitized explanation suitable for end-user.
            policy_decision: Policy evaluation verdict token (e.g. BLOCKED_POLICY, FEEDBACK_REFUSAL).
            execution_action: Runtime execution action (e.g. ABORTED, SYNTHETIC_PAYLOAD).
            should_abort: True if agent loop execution must abort immediately.
            diagnostic_reason: Detailed diagnostic reason code.
            tool_name: Name of target tool associated with violation.
        """
        self._status = status
        self._action_entry = action_entry
        self._root_cause = root_cause
        self._user_message = user_message
        self._policy_decision = policy_decision
        self._execution_action = execution_action
        self._should_abort = should_abort
        self._diagnostic_reason = diagnostic_reason
        self._tool_name = tool_name

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "ViolationResolution":
        """Factory method to construct ViolationResolution.

        Args:
            *args: Optional positional arguments (status, action_entry, root_cause, user_message, policy_decision, execution_action, should_abort, diagnostic_reason, tool_name).
            **kwargs: Optional keyword arguments.

        Returns:
            ViolationResolution: Constructed structured resolution object.
        """
        status = str(kwargs.get("status", args[0] if len(args) > 0 else ""))
        action_entry = str(kwargs.get("action_entry", args[1] if len(args) > 1 else ""))
        root_cause = str(kwargs.get("root_cause", args[2] if len(args) > 2 else ""))
        user_message = str(kwargs.get("user_message", args[3] if len(args) > 3 else ""))
        policy_decision = str(kwargs.get("policy_decision", kwargs.get("remediation_security", args[4] if len(args) > 4 else "")))
        execution_action = str(kwargs.get("execution_action", kwargs.get("remediation_execution", args[5] if len(args) > 5 else "")))
        should_abort = bool(kwargs.get("should_abort", args[6] if len(args) > 6 else False))
        diagnostic_reason = kwargs.get("diagnostic_reason", args[7] if len(args) > 7 else None)
        tool_name = kwargs.get("tool_name", args[8] if len(args) > 8 else None)
        return cls(
            status,
            action_entry,
            root_cause,
            user_message,
            policy_decision,
            execution_action,
            should_abort,
            diagnostic_reason,
            tool_name,
        )

    @property
    def status(self) -> str:
        """Get overall violation status token."""
        return self._status

    @property
    def action_entry(self) -> str:
        """Get log action description."""
        return self._action_entry

    @property
    def root_cause(self) -> str:
        """Get diagnostic root cause token."""
        return self._root_cause

    @property
    def user_message(self) -> str:
        """Get sanitized user-facing error message."""
        return self._user_message

    @property
    def policy_decision(self) -> str:
        """Get policy evaluation decision verdict token."""
        return self._policy_decision

    @property
    def execution_action(self) -> str:
        """Get runtime execution remediation action."""
        return self._execution_action

    @property
    def remediation_security(self) -> str:
        """Backward-compatibility accessor for policy_decision."""
        return self._policy_decision

    @property
    def remediation_execution(self) -> str:
        """Backward-compatibility accessor for execution_action."""
        return self._execution_action

    @property
    def should_abort(self) -> bool:
        """Check whether the agent execution loop should abort immediately."""
        return self._should_abort

    @property
    def diagnostic_reason(self) -> Optional[str]:
        """Get detailed diagnostic reason code."""
        return self._diagnostic_reason

    @property
    def tool_name(self) -> Optional[str]:
        """Get name of tool associated with violation, if applicable."""
        return self._tool_name


class RetryBudgetTracker:
    """Invocation-scoped retry budget tracker preventing recursive LLM retry loops."""

    def __init__(self, max_feedback_violations: int):
        """Initialize RetryBudgetTracker.

        Args:
            max_feedback_violations: Maximum feedback violation retry allowance before escalating to hard abort.
        """
        self._max_feedback_violations = max_feedback_violations

    @classmethod
    def create(cls, max_feedback_violations: int) -> "RetryBudgetTracker":
        """Factory method to construct RetryBudgetTracker.

        Args:
            max_feedback_violations: Maximum retry threshold integer.

        Returns:
            RetryBudgetTracker: Configured tracker instance.
        """
        return cls(max_feedback_violations=max_feedback_violations)

    @property
    def max_feedback_violations(self) -> int:
        """Get maximum feedback violation retry allowance."""
        return self._max_feedback_violations

    def get_retry_count(self, config: Optional[Dict[str, Any]]) -> int:
        """Retrieve the current retry violation count from invocation configuration.

        Args:
            config: RunnableConfig dictionary containing configurable metadata.

        Returns:
            int: Current integer retry count.
        """
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            return int(config["configurable"].get(CONFIG_RETRY_COUNT_KEY, 0))
        return 0

    def increment_retry_count(self, config: Optional[Dict[str, Any]]) -> int:
        """Increment and persist the retry count inside the invocation configuration.

        Args:
            config: Target RunnableConfig dictionary.

        Returns:
            int: Newly updated retry count integer.
        """
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            count = int(config["configurable"].get(CONFIG_RETRY_COUNT_KEY, 0)) + 1
            config["configurable"][CONFIG_RETRY_COUNT_KEY] = count
            return count
        return 0

    def is_budget_exceeded(self, config: Optional[Dict[str, Any]]) -> bool:
        """Check if invocation-scoped retries have exceeded the maximum feedback limit.

        Args:
            config: Target RunnableConfig dictionary.

        Returns:
            bool: True if retry budget is exhausted, False otherwise.
        """
        return self.get_retry_count(config) > self._max_feedback_violations

    def reset(self, config: Optional[Dict[str, Any]]) -> None:
        """Reset the invocation retry counter to zero.

        Args:
            config: Target RunnableConfig dictionary.
        """
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"][CONFIG_RETRY_COUNT_KEY] = 0


class AbuseThrottleTracker:
    """Sliding-window abuse throttle tracker detecting rapid cross-invocation denial floods."""

    def __init__(self, window_seconds: float, max_denials: int):
        """Initialize AbuseThrottleTracker.

        Args:
            window_seconds: Duration of sliding evaluation window in seconds.
            max_denials: Maximum allowed denial events within window before throttling.
        """
        self._window_seconds = window_seconds
        self._max_denials = max_denials
        self._denial_history: Dict[str, List[float]] = {}

    @classmethod
    def create(cls, window_seconds: float, max_denials: int) -> "AbuseThrottleTracker":
        """Factory method to construct AbuseThrottleTracker.

        Args:
            window_seconds: Window duration in seconds.
            max_denials: Threshold count of denials.

        Returns:
            AbuseThrottleTracker: Configured tracker instance.
        """
        return cls(window_seconds=window_seconds, max_denials=max_denials)

    @property
    def window_seconds(self) -> float:
        """Get sliding window duration in seconds."""
        return self._window_seconds

    @property
    def max_denials(self) -> int:
        """Get maximum allowed denials threshold."""
        return self._max_denials

    def _prune(self, subject_id: str, current_time: float) -> List[float]:
        cutoff = current_time - self._window_seconds
        timestamps = [t for t in self._denial_history.get(subject_id, []) if t >= cutoff]
        self._denial_history[subject_id] = timestamps
        return timestamps

    def record_denial(self, subject_id: str, timestamp: float) -> bool:
        """Record a denial occurrence for a subject and check if abuse threshold is breached.

        Args:
            subject_id: Subject identifier.
            timestamp: Epoch timestamp in seconds.

        Returns:
            bool: True if subject exceeds abuse threshold (is abusing), False otherwise.
        """
        timestamps = self._prune(subject_id, timestamp)
        timestamps.append(timestamp)
        self._denial_history[subject_id] = timestamps
        return len(timestamps) >= self._max_denials

    def is_throttled(self, subject_id: str, timestamp: float) -> bool:
        """Check if subject is currently throttled due to recent denial density.

        Args:
            subject_id: Subject identifier.
            timestamp: Epoch timestamp in seconds.

        Returns:
            bool: True if subject is throttled, False otherwise.
        """
        timestamps = self._prune(subject_id, timestamp)
        return len(timestamps) >= self._max_denials

    def reset(self, *args: Any, **kwargs: Any) -> None:
        """Reset denial history for a specific subject or all subjects.

        Args:
            *args: Optional positional subject_id.
            **kwargs: Optional keyword subject_id.
        """
        subject_id = args[0] if len(args) > 0 else kwargs.get("subject_id")
        if subject_id is not None:
            self._denial_history.pop(str(subject_id), None)
        else:
            self._denial_history.clear()


class ToolViolationHandler:
    """PEP violation handler integrating retry tracking, abuse throttling, and fallback generation."""

    def __init__(
        self,
        pdp_engine: PolicyDecisionEngine,
        retry_tracker: RetryBudgetTracker,
        abuse_tracker: AbuseThrottleTracker,
    ):
        """Initialize ToolViolationHandler.

        Args:
            pdp_engine: PDP decision engine for evaluating and logging violations.
            retry_tracker: RetryBudgetTracker instance.
            abuse_tracker: AbuseThrottleTracker instance.
        """
        self._pdp_engine = pdp_engine
        self._retry_tracker = retry_tracker
        self._abuse_tracker = abuse_tracker
        if hasattr(self._pdp_engine, "register_invalidation_callback"):
            self._pdp_engine.register_invalidation_callback(self.reset_abuse)

    def reset_abuse(self, *args: Any, **kwargs: Any) -> None:
        """Reset abuse tracking for a specific subject or all subjects.

        Args:
            *args: Optional positional subject_id.
            **kwargs: Optional keyword subject_id.
        """
        self._abuse_tracker.reset(*args, **kwargs)

    @classmethod
    def create(
        cls,
        pdp_engine: PolicyDecisionEngine,
        retry_tracker: RetryBudgetTracker,
        abuse_tracker: AbuseThrottleTracker,
    ) -> "ToolViolationHandler":
        """Factory method constructing a ToolViolationHandler.

        Args:
            pdp_engine: PDP decision engine.
            retry_tracker: Tracker for model feedback retries.
            abuse_tracker: Tracker for subject-level abuse denial bursts.

        Returns:
            ToolViolationHandler: New handler instance.
        """
        return cls(
            pdp_engine=pdp_engine,
            retry_tracker=retry_tracker,
            abuse_tracker=abuse_tracker,
        )

    @classmethod
    def default_handler(cls, pdp_engine: PolicyDecisionEngine) -> "ToolViolationHandler":
        """Factory method constructing default handler with standard limits.

        Args:
            pdp_engine: PDP decision engine instance.

        Returns:
            ToolViolationHandler: Handler initialized with standard 2-retry budget and 60s sliding abuse window.
        """
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
        """Get the bound PolicyDecisionEngine."""
        return self._pdp_engine

    @property
    def retry_tracker(self) -> RetryBudgetTracker:
        """Get the bound RetryBudgetTracker."""
        return self._retry_tracker

    @property
    def abuse_tracker(self) -> AbuseThrottleTracker:
        """Get the bound AbuseThrottleTracker."""
        return self._abuse_tracker

    def record_tool_violation(
        self,
        tool_name: str,
        diagnostic_reason: str,
        is_mutative: bool,
        config: Optional[Dict[str, Any]],
        caller_identity: Optional[SecurityIdentity],
    ) -> ViolationResolution:
        """Record a tool policy violation, tracks abuse/retries, and returns structured resolution.

        Args:
            tool_name: Name of tool whose execution was denied.
            diagnostic_reason: Diagnostic reason string from PDP decision.
            is_mutative: True if tool modifies system state, triggering immediate hard abort.
            config: Optional RunnableConfig dictionary for tracking state and retry counts.
            caller_identity: Optional SecurityIdentity envelope of calling subject.

        Returns:
            ViolationResolution: Structured resolution detailing telemetry, status, and abort flags.
        """
        is_budget_exceeded = self._retry_tracker.is_budget_exceeded(config)
        is_abusing = False

        if caller_identity is not None and self._abuse_tracker.record_denial(caller_identity.subject_id, time.time()):
            is_abusing = True
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
            should_abort = True
            status = STATUS_BLOCKED_BY_POLICY
            policy_decision = POLICY_STATUS_BLOCKED
            execution_action = EXECUTION_ACTION_ABORTED
        elif is_mutative:
            root_cause = f"Policy violation: Access denied for tool '{tool_name}' ({diagnostic_reason})"
            user_msg = f"Policy violation: Access denied for tool '{tool_name}' ({diagnostic_reason})"
            action_entry = f"Blocked execution of tool '{tool_name}' ({diagnostic_reason})"
            should_abort = True
            status = STATUS_BLOCKED_BY_POLICY
            policy_decision = POLICY_STATUS_BLOCKED
            execution_action = EXECUTION_ACTION_ABORTED
        else:
            root_cause = f"Policy restriction: Informational tool '{tool_name}' access denied ({diagnostic_reason})"
            user_msg = f"Policy restriction: Informational tool '{tool_name}' access denied ({diagnostic_reason})"
            action_entry = f"Blocked execution of tool '{tool_name}' ({diagnostic_reason})"
            should_abort = is_abusing
            status = STATUS_BLOCKED_BY_POLICY if is_abusing else "ACCESS_DENIED"
            policy_decision = POLICY_STATUS_BLOCKED if is_abusing else POLICY_STATUS_FEEDBACK
            execution_action = EXECUTION_ACTION_ABORTED if is_abusing else EXECUTION_ACTION_FEEDBACK

        resolution = ViolationResolution.create(
            status=status,
            action_entry=action_entry,
            root_cause=root_cause,
            user_message=user_msg,
            policy_decision=policy_decision,
            execution_action=execution_action,
            should_abort=should_abort,
            diagnostic_reason=diagnostic_reason,
            tool_name=tool_name,
        )

        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"][CONFIG_LAST_VIOLATION_KEY] = resolution

        return resolution

    def resolve_tool_exception(
        self,
        exc: Exception,
        config: Optional[Dict[str, Any]],
    ) -> ViolationResolution:
        """Resolve an uncaught tool exception into a structured ViolationResolution.

        Args:
            exc: Exception raised during tool execution.
            config: Optional RunnableConfig dictionary.

        Returns:
            ViolationResolution: Structured violation resolution object.
        """
        tool_name = getattr(exc, "tool_name", "unknown_tool")
        diagnostic_reason = getattr(exc, "diagnostic_reason", None) or str(exc)
        caller_identity = IdentityBridge.extract_from_config(config)
        return self.record_tool_violation(
            tool_name,
            diagnostic_reason,
            True,
            config,
            caller_identity,
        )


__all__ = [
    "STATUS_BLOCKED_BY_POLICY",
    "POLICY_STATUS_BLOCKED",
    "POLICY_STATUS_FEEDBACK",
    "EXECUTION_ACTION_ABORTED",
    "EXECUTION_ACTION_FEEDBACK",
    "REMED_SEC_BLOCKED_POLICY",
    "REMED_EXEC_ABORTED",
    "DEFAULT_MAX_FEEDBACK_VIOLATIONS",
    "ViolationResolution",
    "RetryBudgetTracker",
    "AbuseThrottleTracker",
    "ToolViolationHandler",
]
