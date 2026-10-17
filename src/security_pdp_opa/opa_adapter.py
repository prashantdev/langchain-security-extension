"""
Remote Policy Decision Point (PDP) adapter for Open Policy Agent (OPA) integration.

Provides network resilience, timeout control, fail-closed circuit breaking, and static cache invalidation
as specified in Spec 4.
"""

import time
from enum import Enum
from typing import Dict, Any, Optional
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest, PolicyDecision, TwoTierDecisionCache
from security_core.audit import AuditManager, AuditEvent
from security_core.constants import (
    DECISION_PERMIT,
    DECISION_DENY,
    DEFAULT_REMOTE_PDP_TIMEOUT_SECONDS,
    DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_RECOVERY_SECONDS,
    CB_STATE_CLOSED,
    CB_STATE_OPEN,
    CB_STATE_HALF_OPEN,
    EVENT_CIRCUIT_BREAKER_OPEN,
    EVENT_CIRCUIT_BREAKER_TRANSITION,
    SEVERITY_WARNING,
)


class CircuitBreakerState(str, Enum):
    """Circuit breaker state enumeration for remote PDP resilience."""
    CLOSED = CB_STATE_CLOSED
    OPEN = CB_STATE_OPEN
    HALF_OPEN = CB_STATE_HALF_OPEN


class RemotePDPAdapter(PolicyDecisionEngine):
    """Remote PDP adapter connecting to OPA REST API with circuit breaker and fail-closed security.

    Attributes:
        is_circuit_open (bool): True if circuit breaker is tripped due to consecutive failures.
    """

    def __init__(
        self,
        endpoint_url: str,
        *args: Any,
        **kwargs: Any,
    ):
        """Initialize RemotePDPAdapter.

        Args:
            endpoint_url: OPA server REST endpoint URL.
            *args: Optional positional arguments (timeout_seconds, failure_threshold, decision_cache, recovery_timeout_seconds, fallback_engine, audit_manager).
            **kwargs: Optional keyword arguments.
        """
        timeout_seconds = kwargs.get("timeout_seconds", args[0] if len(args) > 0 else DEFAULT_REMOTE_PDP_TIMEOUT_SECONDS)
        failure_threshold = kwargs.get("failure_threshold", args[1] if len(args) > 1 else DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        decision_cache = kwargs.get("decision_cache", args[2] if len(args) > 2 else None)
        recovery_timeout_seconds = kwargs.get(
            "recovery_timeout_seconds",
            args[3] if len(args) > 3 else DEFAULT_CIRCUIT_BREAKER_RECOVERY_SECONDS,
        )
        audit_manager = kwargs.get("audit_manager", args[4] if len(args) > 4 else None)

        self._endpoint_url = endpoint_url
        self._timeout_seconds = float(timeout_seconds)
        self._failure_threshold = int(failure_threshold)
        self._recovery_timeout_seconds = float(recovery_timeout_seconds)
        self._consecutive_failures = 0
        self._state = CircuitBreakerState.CLOSED
        self._opened_at: Optional[float] = None
        self._decision_cache: Optional[TwoTierDecisionCache] = decision_cache
        self._audit_manager: Optional[AuditManager] = audit_manager

    @classmethod
    def create(
        cls,
        endpoint_url: str,
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method to construct a RemotePDPAdapter.

        Args:
            endpoint_url: OPA endpoint URL.
            *args: Optional positional arguments.
            **kwargs: Optional keyword arguments.

        Returns:
            RemotePDPAdapter: Constructed adapter instance.
        """
        return cls(endpoint_url, *args, **kwargs)

    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state, transitioning OPEN -> HALF_OPEN if recovery window elapsed."""
        if self._state == CircuitBreakerState.OPEN and self._opened_at is not None:
            if time.time() - self._opened_at >= self._recovery_timeout_seconds:
                self._state = CircuitBreakerState.HALF_OPEN
        return self._state

    @property
    def is_circuit_open(self) -> bool:
        """Check if circuit breaker is currently OPEN (tripped)."""
        return self.state == CircuitBreakerState.OPEN

    @property
    def role_graph(self):
        """No embedded role graph in remote adapter."""
        return None

    @property
    def audit_manager(self) -> Optional[AuditManager]:
        """Get configured AuditManager."""
        return self._audit_manager

    @property
    def circuit_state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self.state

    @property
    def decision_cache(self) -> Optional[TwoTierDecisionCache]:
        """Get configured TwoTierDecisionCache."""
        return self._decision_cache

    def register_invalidation_callback(self, callback: Any) -> None:
        """Register a callback for cache invalidation events."""
        callbacks = getattr(self, "_invalidation_callbacks", None)
        if callbacks is None:
            self._invalidation_callbacks = []
        self._invalidation_callbacks.append(callback)

    def clear_cache(self) -> None:
        """Flush decision cache."""
        self.invalidate_cache()

    def evict_subject_cache(self, subject_id: str, *args: Any, **kwargs: Any) -> int:
        """Evict cached decisions for a specific subject."""
        if self._decision_cache:
            return self._decision_cache.evict_subject(subject_id, *args, **kwargs)
        return 0

    def invalidate_cache(self) -> None:
        """Flushes cross-request static PDP decision cache upon OPA policy bundle reload."""
        if self._decision_cache:
            self._decision_cache.flush()

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Synchronously evaluate policy request against remote OPA endpoint.

        Args:
            request: Evaluation request envelope.

        Returns:
            PolicyDecision: Remote PDP decision verdict.
        """
        current_state = self.state
        if current_state == CircuitBreakerState.OPEN:
            return self._handle_fail_closed(
                request=request,
                reason="Remote PDP circuit breaker OPEN (fail-closed) [CIRCUIT_BREAKER_OPEN | LOCAL_PDP_FALLBACK]",
            )

        payload = self._build_payload(request)

        try:
            import urllib.request
            import json

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._endpoint_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    result = resp_data.get("result", {})
                    allow = result.get("allow", False) if isinstance(result, dict) else bool(result)
                    self._record_success(request)
                    if allow:
                        return PolicyDecision.permit("Authorized by Remote OPA PDP", {})
                    return PolicyDecision.deny("Denied by Remote OPA PDP", {})

            self._record_failure(request, "HTTP non-200 response")
            return self._handle_fail_closed(
                request=request,
                reason="Remote OPA PDP returned invalid HTTP response",
            )

        except Exception as err:
            self._record_failure(request, str(err))
            return self._handle_fail_closed(
                request=request,
                reason=f"Remote OPA PDP request error: {str(err)}",
            )

    async def evaluate_async(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Asynchronous policy evaluation with httpx or asyncio fallback and fail-closed circuit breaker.

        Args:
            request: Evaluation request envelope.

        Returns:
            PolicyDecision: Async decision verdict.
        """
        current_state = self.state
        if current_state == CircuitBreakerState.OPEN:
            return self._handle_fail_closed(
                request=request,
                reason="Remote PDP circuit breaker OPEN (fail-closed) [CIRCUIT_BREAKER_OPEN | LOCAL_PDP_FALLBACK]",
            )

        payload = self._build_payload(request)

        try:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                    resp = await client.post(self._endpoint_url, json=payload)
                    if resp.status_code == 200:
                        resp_data = resp.json()
                        result = resp_data.get("result", {})
                        allow = result.get("allow", False) if isinstance(result, dict) else bool(result)
                        self._record_success(request)
                        if allow:
                            return PolicyDecision.permit("Authorized by Remote OPA PDP", {})
                        return PolicyDecision.deny("Denied by Remote OPA PDP", {})
            except ImportError:
                import asyncio
                return await asyncio.to_thread(self.evaluate, request)

            self._record_failure(request, "HTTP non-200 response")
            return self._handle_fail_closed(
                request=request,
                reason="Remote OPA PDP returned invalid HTTP response",
            )

        except Exception as err:
            self._record_failure(request, str(err))
            return self._handle_fail_closed(
                request=request,
                reason=f"Remote OPA PDP request error: {str(err)}",
            )

    def _build_payload(self, request: PolicyEvaluationRequest) -> Dict[str, Any]:
        safe_context = {k: v for k, v in request.context.items() if k != "config"}
        return {
            "input": {
                "subject": request.subject.to_dict(),
                "action": request.action,
                "resource": request.resource,
                "context": safe_context,
            }
        }

    def _record_success(self, request: PolicyEvaluationRequest) -> None:
        prev_state = self._state
        self._consecutive_failures = 0
        self._state = CircuitBreakerState.CLOSED
        self._opened_at = None
        if prev_state != CircuitBreakerState.CLOSED:
            self._emit_circuit_event(
                request=request,
                reason_code=EVENT_CIRCUIT_BREAKER_TRANSITION,
                diagnostic=f"{EVENT_CIRCUIT_BREAKER_TRANSITION}: {prev_state.value} -> {CircuitBreakerState.CLOSED.value}",
            )

    def _record_failure(self, request: PolicyEvaluationRequest, error_detail: str) -> None:
        prev_state = self._state
        self._consecutive_failures += 1
        if prev_state == CircuitBreakerState.HALF_OPEN or self._consecutive_failures >= self._failure_threshold:
            self._state = CircuitBreakerState.OPEN
            self._opened_at = time.time()
            self._emit_circuit_event(
                request=request,
                reason_code=EVENT_CIRCUIT_BREAKER_OPEN,
                diagnostic=(
                    f"{EVENT_CIRCUIT_BREAKER_OPEN} | {EVENT_CIRCUIT_BREAKER_TRANSITION} "
                    f"({prev_state.value} -> {self._state.value}) | LOCAL_PDP_FALLBACK: {error_detail}"
                ),
            )

    def _emit_circuit_event(self, request: PolicyEvaluationRequest, reason_code: str, diagnostic: str) -> None:
        req_config = request.context.get("config") if isinstance(request.context, dict) else None
        if isinstance(req_config, dict) and isinstance(req_config.get("configurable"), dict):
            req_config["configurable"]["sec:circuit_breaker_state"] = self._state.value
            req_config["configurable"]["sec:circuit_breaker_transition"] = diagnostic

        mgr = self.audit_manager
        if mgr:
            event = AuditEvent.create(
                subject_id=request.subject.subject_id,
                tenant_id=request.subject.tenant_id,
                action=request.action,
                resource=str(request.resource.get("name") or request.resource.get("target_id") or "RemotePDPAdapter"),
                decision=DECISION_DENY,
                diagnostic_reason=diagnostic,
                severity=SEVERITY_WARNING,
                metadata={"circuit_state": self._state.value},
                reason_code=reason_code,
            )
            mgr.record_event(event)

    def _handle_fail_closed(self, request: PolicyEvaluationRequest, reason: str) -> PolicyDecision:
        req_config = request.context.get("config") if isinstance(request.context, dict) else None
        if isinstance(req_config, dict) and isinstance(req_config.get("configurable"), dict):
            req_config["configurable"]["sec:circuit_breaker_state"] = self._state.value

        return PolicyDecision.deny(
            diagnostic_reason=reason,
            obligations={},
        )

    def reset_circuit_breaker(self) -> None:
        """Reset the circuit breaker status to CLOSED and clear failure counts."""
        self._state = CircuitBreakerState.CLOSED
        self._opened_at = None
        self._consecutive_failures = 0


class OPACacheInvalidationHandler:
    """Webhook callback handler for processing OPA bundle reload events and invalidating PDP cache."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize OPACacheInvalidationHandler.

        Args:
            *args: Optional positional target adapter or PDP engine.
            **kwargs: Optional keyword arguments (remote_adapter, pdp_engine).
        """
        target = kwargs.get("remote_adapter", kwargs.get("pdp_engine", args[0] if len(args) > 0 else None))
        self._remote_adapter = target

    def handle_bundle_reload_webhook(self, payload: Dict[str, Any]) -> bool:
        """Handles incoming OPA webhook notification and flushes decision cache.

        Args:
            payload: Webhook payload dictionary.

        Returns:
            bool: True upon successful processing.
        """
        if self._remote_adapter and hasattr(self._remote_adapter, "invalidate_cache"):
            self._remote_adapter.invalidate_cache()
        elif self._remote_adapter and hasattr(self._remote_adapter, "clear_cache"):
            self._remote_adapter.clear_cache()
        return True

    def on_invalidation_event(self, payload: Dict[str, Any]) -> int:
        """Handles identity or policy invalidation event and evicts subject or full PDP cache."""
        subject_id = payload.get("subject_id") or payload.get("email")
        if subject_id and self._remote_adapter and hasattr(self._remote_adapter, "evict_subject_cache"):
            return int(self._remote_adapter.evict_subject_cache(str(subject_id)))
        self.handle_bundle_reload_webhook(payload)
        return 0


