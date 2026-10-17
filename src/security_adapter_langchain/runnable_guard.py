"""
SecureRunnable wrapper guarding LangChain Runnables and agent callables prior to execution.

Enforces PDP agent access authorization checks and sets up async task SecurityContextHolder
identity context prior to invoking wrapped runnables as specified in Spec 0 and Spec 4.
"""

import inspect
from typing import Any, Dict, Optional, List, Iterator, AsyncIterator
from security_core.identity import SecurityIdentity, SecurityContextHolder, IdentityBridge, InvocationParameters
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest
from security_core.audit import AuditEvent
from security_core.constants import (
    ACTION_AGENT_INVOKE,
    EVENT_AGENT_ACCESS_DENIED,
    PEP_RUNNABLE_ENTRY,
    SEVERITY_WARNING,
    CONFIG_KEY_SECURITY_IDENTITY,
    CONFIG_KEY_INVOCATION_PARAMS,
    PII_SCOPE_FULL_IN_FLIGHT,
    PII_STAGE_INBOUND_PROMPT,
    PII_STAGE_OUTBOUND_RESPONSE,
)
from security_core.exceptions import AgentAccessDeniedException, SecurityAuthorizationError
from security_adapter_langchain.callback_handler import SecureCallbackHandler
from security_core.pii import get_pii_sanitizer, get_pii_scope, PiiContext



class SecureRunnable:
    """Wraps agent Runnables or callables with a service boundary security evaluation gate.

    Attributes:
        runnable (Any): Wrapped LangChain Runnable or callable.
        pdp_engine (PolicyDecisionEngine): PDP engine instance for evaluation.
        agent_name (str): Identifier of the agent or Runnable target.
        required_roles (List[str]): List of required role strings.
        min_clearance (int): Minimum required clearance rank.
    """

    def __init__(
        self,
        runnable: Any,
        pdp_engine: PolicyDecisionEngine,
        agent_name: str,
        required_roles: Optional[List[str]],
        min_clearance: int,
        target_tenant: Optional[str],
    ):
        """Initialize SecureRunnable.

        Args:
            runnable: Target Runnable or callable.
            pdp_engine: Policy decision engine.
            agent_name: Agent identifier.
            required_roles: List of required roles.
            min_clearance: Minimum clearance floor rank.
            target_tenant: Target tenant isolation boundary.
        """
        self._runnable = runnable
        self._pdp_engine = pdp_engine
        self._agent_name = agent_name
        self._required_roles = list(required_roles) if required_roles is not None else []
        self._min_clearance = min_clearance
        self._target_tenant = target_tenant
        self._violation_handler: Optional[Any] = None
        self._violation_fallback: Optional[Any] = None

    @classmethod
    def wrap(
        cls,
        runnable: Any,
        pdp_engine: PolicyDecisionEngine,
        agent_name: str,
        required_roles: Optional[List[str]],
        min_clearance: int,
        target_tenant: Optional[str],
    ):
        """Factory method to construct a SecureRunnable wrapper.

        Args:
            runnable: Target Runnable or callable.
            pdp_engine: PDP decision engine.
            agent_name: Target agent identifier.
            required_roles: Required role strings list.
            min_clearance: Minimum clearance level rank.
            target_tenant: Target tenant isolation boundary.

        Returns:
            SecureRunnable: Constructed wrapper instance.
        """
        return cls(
            runnable=runnable,
            pdp_engine=pdp_engine,
            agent_name=agent_name,
            required_roles=required_roles,
            min_clearance=min_clearance,
            target_tenant=target_tenant,
        )

    @property
    def agent_name(self) -> str:
        """Get target agent identifier."""
        return self._agent_name

    def with_violation_handler(
        self,
        violation_handler: Any,
        fallback_builder: Any,
    ) -> "SecureRunnable":
        """Bind a declarative ToolViolationHandler and fallback builder as an LCEL error boundary."""
        self._violation_handler = violation_handler
        self._violation_fallback = fallback_builder
        return self

    @staticmethod
    def handoff(
        target_runnable: "SecureRunnable",
        input_data: Any,
        config: Optional[Dict[str, Any]],
    ) -> Any:
        """Execute a synchronous agent-to-agent handoff preserving in-band RunnableConfig and L1 cache."""
        if isinstance(config, dict):
            configurable = config.setdefault("configurable", {})
            configurable["sec:handoff_propagated"] = True
            configurable["sec:handoff_target"] = target_runnable.agent_name
        return target_runnable.invoke(input_data, config)

    @staticmethod
    async def ahandoff(
        target_runnable: "SecureRunnable",
        input_data: Any,
        config: Optional[Dict[str, Any]],
    ) -> Any:
        """Execute an asynchronous agent-to-agent handoff preserving in-band RunnableConfig and L1 cache."""
        if isinstance(config, dict):
            configurable = config.setdefault("configurable", {})
            configurable["sec:handoff_propagated"] = True
            configurable["sec:handoff_target"] = target_runnable.agent_name
        return await target_runnable.ainvoke(input_data, config)

    def _prepare_config(self, config: Optional[Dict[str, Any]], identity: SecurityIdentity) -> Optional[Dict[str, Any]]:
        if not isinstance(config, dict):
            return config
        configurable = config.setdefault("configurable", {})
        configurable[CONFIG_KEY_SECURITY_IDENTITY] = identity
        if CONFIG_KEY_INVOCATION_PARAMS not in configurable:
            inv_params = InvocationParameters.create(
                security_identity=identity,
                metadata=dict(config.get("metadata") or {}),
            )
            configurable.update(inv_params.serialize_to_state())

        if self._pdp_engine is not None:
            configurable["sec:pdp_engine"] = self._pdp_engine
            cel_eval = getattr(self._pdp_engine, "_cel_evaluator", None)
            if cel_eval and getattr(cel_eval, "entity_resolver", None):
                configurable["sec:entity_resolver"] = cel_eval.entity_resolver
            callbacks = config.setdefault("callbacks", [])
            if isinstance(callbacks, list) and not any(isinstance(cb, SecureCallbackHandler) for cb in callbacks):
                callbacks.append(SecureCallbackHandler.create(pdp_engine=self._pdp_engine, security_identity=identity))
        return config

    def _evaluate_entry_access(self, config: Optional[Dict[str, Any]]) -> SecurityIdentity:
        """Internal helper evaluating PDP entry access and returning caller identity."""
        identity = IdentityBridge.extract_from_config(config)
        if identity is None:
            identity = IdentityBridge.resolve_identity(None)

        self._prepare_config(config, identity)

        tenant = self._target_tenant if self._target_tenant is not None else identity.tenant_id
        request = PolicyEvaluationRequest.create(
            subject=identity,
            action=ACTION_AGENT_INVOKE,
            resource={
                "target_id": self._agent_name,
                "tenant_id": tenant,
                "required_roles": self._required_roles,
                "min_clearance": self._min_clearance,
            },
            context={"config": config} if config else {},
        )

        decision = self._pdp_engine.evaluate(request)
        audit_mgr = getattr(self._pdp_engine, "audit_manager", None)
        if not decision.is_permitted:
            if audit_mgr is not None:
                audit_mgr.record_event(AuditEvent.create(
                    subject_id=identity.subject_id,
                    tenant_id=identity.tenant_id,
                    action=f"agent:invoke:{self._agent_name}",
                    resource=self._agent_name,
                    decision="DENY",
                    diagnostic_reason=decision.diagnostic_reason,
                    severity=SEVERITY_WARNING,
                    metadata={"agent_name": self._agent_name},
                    enforcement_point=PEP_RUNNABLE_ENTRY,
                    reason_code=EVENT_AGENT_ACCESS_DENIED,
                ))
            raise AgentAccessDeniedException.for_agent(
                agent_name=self._agent_name,
                message=f"Agent invocation denied for '{self._agent_name}': {decision.diagnostic_reason}",
                diagnostic_reason=decision.diagnostic_reason,
            )

        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"][f"sec:entry_verified:{self._agent_name}"] = True

        trace_id = identity.attributes.get("trace_id") if hasattr(identity, "attributes") else None
        span_id = identity.attributes.get("span_id") if hasattr(identity, "attributes") else None
        if not trace_id and isinstance(config, dict):
            meta = config.get("metadata", {})
            if isinstance(meta, dict):
                trace_id = meta.get("trace_id")
                span_id = meta.get("span_id")

        if audit_mgr is not None:
            IdentityBridge.record_auth_success(
                audit_manager=audit_mgr,
                subject_id=identity.subject_id,
                tenant_id=identity.tenant_id,
                action=f"agent:invoke:{self._agent_name}",
                resource=self._agent_name,
                department=identity.department_id,
                roles=list(identity.roles),
                clearance_level=identity.clearance_level,
                trace_id=trace_id,
                span_id=span_id,
            )
        return identity

    def _sanitize_inbound_input(self, input_data: Any, identity: SecurityIdentity) -> Any:
        """Sanitize inbound input payload if FULL_IN_FLIGHT PII redaction scope is enabled."""
        if get_pii_scope() == PII_SCOPE_FULL_IN_FLIGHT:
            sanitizer = get_pii_sanitizer()
            ctx = PiiContext.create(PII_STAGE_INBOUND_PROMPT, identity.tenant_id, identity.subject_id, self._agent_name, None)
            if isinstance(input_data, str):
                return sanitizer.sanitize_text(input_data, ctx)
            elif isinstance(input_data, dict):
                return sanitizer.sanitize_payload(input_data, ctx)
            elif isinstance(input_data, list):
                return [
                    sanitizer.sanitize_payload(item, ctx) if isinstance(item, dict)
                    else (sanitizer.sanitize_text(item, ctx) if isinstance(item, str) else item)
                    for item in input_data
                ]
        return input_data

    def _sanitize_outbound_output(self, result: Any, identity: SecurityIdentity) -> Any:
        """Sanitize outbound response payload if FULL_IN_FLIGHT PII redaction scope is enabled."""
        if get_pii_scope() == PII_SCOPE_FULL_IN_FLIGHT:
            sanitizer = get_pii_sanitizer()
            ctx = PiiContext.create(PII_STAGE_OUTBOUND_RESPONSE, identity.tenant_id, identity.subject_id, self._agent_name, None)
            if isinstance(result, str):
                return sanitizer.sanitize_text(result, ctx)
            elif isinstance(result, dict):
                return sanitizer.sanitize_payload(result, ctx)
            elif isinstance(result, list):
                return [
                    sanitizer.sanitize_payload(item, ctx) if isinstance(item, dict)
                    else (sanitizer.sanitize_text(item, ctx) if isinstance(item, str) else item)
                    for item in result
                ]
            elif hasattr(result, "content") and isinstance(result.content, str):
                result.content = sanitizer.sanitize_text(result.content, ctx)
                return result
        return result

    def invoke(self, input_data: Any, *args: Any, **kwargs: Any) -> Any:
        """Synchronously invoke protected Runnable with security context binding and LCEL violation boundary.

        Args:
            input_data: Input data payload.
            *args: Optional positional config dictionary.
            **kwargs: Optional keyword config dictionary.

        Returns:
            Any: Invocation result from wrapped Runnable or violation fallback.

        Raises:
            AgentAccessDeniedException: If PDP denies agent entry access.
        """
        config: Optional[Dict[str, Any]] = kwargs.get("config", args[0] if len(args) > 0 else None)
        identity = self._evaluate_entry_access(config)
        token = SecurityContextHolder.set_identity(identity)
        input_data = self._sanitize_inbound_input(input_data, identity)
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict) and self._violation_handler is not None:
            config["configurable"]["sec:violation_handler"] = self._violation_handler
            config["configurable"].setdefault("sec:actions", [])
        try:
            if hasattr(self._runnable, "invoke"):
                if config is not None:
                    result = self._runnable.invoke(input_data, config)
                else:
                    result = self._runnable.invoke(input_data)
            elif callable(self._runnable):
                sig = inspect.signature(self._runnable)
                if "config" in sig.parameters and config is not None:
                    result = self._runnable(input_data, config=config)
                elif len(sig.parameters) >= 2 and config is not None:
                    result = self._runnable(input_data, config)
                else:
                    result = self._runnable(input_data)
            else:
                raise ValueError("Wrapped object is neither Runnable nor callable.")

            result = self._sanitize_outbound_output(result, identity)

            if (
                self._violation_fallback is not None
                and isinstance(config, dict)
                and isinstance(config.get("configurable"), dict)
                and config["configurable"].get("sec:last_violation") is not None
            ):
                resolution = config["configurable"].pop("sec:last_violation")
                return self._violation_fallback(input_data, resolution, config)
            return result
        except AgentAccessDeniedException:
            raise
        except Exception as exc:
            if self._violation_handler is not None and self._violation_fallback is not None:
                resolution = None
                if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
                    resolution = config["configurable"].pop("sec:last_violation", None)
                if resolution is None:
                    resolution = self._violation_handler.resolve_tool_exception(exc, config)
                return self._violation_fallback(input_data, resolution, config)
            raise
        finally:
            SecurityContextHolder.reset_identity(token)


    async def ainvoke(self, input_data: Any, *args: Any, **kwargs: Any) -> Any:
        """Asynchronously invoke protected Runnable with async context binding.

        Args:
            input_data: Input data payload.
            *args: Optional positional config dictionary.
            **kwargs: Optional keyword config dictionary.

        Returns:
            Any: Invocation result.

        Raises:
            AgentAccessDeniedException: If PDP denies agent entry access.
        """
        config: Optional[Dict[str, Any]] = kwargs.get("config", args[0] if len(args) > 0 else None)
        identity = self._evaluate_entry_access(config)
        token = SecurityContextHolder.set_identity(identity)
        input_data = self._sanitize_inbound_input(input_data, identity)
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict) and self._violation_handler is not None:
            config["configurable"]["sec:violation_handler"] = self._violation_handler
            config["configurable"].setdefault("sec:actions", [])
        try:
            if hasattr(self._runnable, "ainvoke"):
                if config is not None:
                    result = await self._runnable.ainvoke(input_data, config)
                else:
                    result = await self._runnable.ainvoke(input_data)
            elif callable(self._runnable):
                sig = inspect.signature(self._runnable)
                if inspect.iscoroutinefunction(self._runnable):
                    if "config" in sig.parameters and config is not None:
                        result = await self._runnable(input_data, config=config)
                    elif len(sig.parameters) >= 2 and config is not None:
                        result = await self._runnable(input_data, config)
                    else:
                        result = await self._runnable(input_data)
                else:
                    if "config" in sig.parameters and config is not None:
                        result = self._runnable(input_data, config=config)
                    elif len(sig.parameters) >= 2 and config is not None:
                        result = self._runnable(input_data, config)
                    else:
                        result = self._runnable(input_data)
            else:
                raise ValueError("Wrapped object is neither Runnable nor callable.")

            result = self._sanitize_outbound_output(result, identity)

            if (
                self._violation_fallback is not None
                and isinstance(config, dict)
                and isinstance(config.get("configurable"), dict)
                and config["configurable"].get("sec:last_violation") is not None
            ):
                resolution = config["configurable"].pop("sec:last_violation")
                return self._violation_fallback(input_data, resolution, config)
            return result
        except AgentAccessDeniedException:
            raise
        except Exception as exc:
            if self._violation_handler is not None and self._violation_fallback is not None:
                resolution = None
                if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
                    resolution = config["configurable"].pop("sec:last_violation", None)
                if resolution is None:
                    resolution = self._violation_handler.resolve_tool_exception(exc, config)
                return self._violation_fallback(input_data, resolution, config)
            raise
        finally:
            SecurityContextHolder.reset_identity(token)

    def stream(self, input_data: Any, *args: Any, **kwargs: Any) -> Iterator[Any]:
        """Synchronously stream output chunks from protected Runnable."""
        config: Optional[Dict[str, Any]] = kwargs.get("config", args[0] if len(args) > 0 else None)
        identity = self._evaluate_entry_access(config)
        token = SecurityContextHolder.set_identity(identity)
        input_data = self._sanitize_inbound_input(input_data, identity)
        try:
            if hasattr(self._runnable, "stream"):
                if config is not None:
                    for chunk in self._runnable.stream(input_data, config):
                        yield self._sanitize_outbound_output(chunk, identity)
                else:
                    for chunk in self._runnable.stream(input_data):
                        yield self._sanitize_outbound_output(chunk, identity)
            else:
                yield self.invoke(input_data, config)
        finally:
            SecurityContextHolder.reset_identity(token)

    async def astream(self, input_data: Any, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        """Asynchronously stream output chunks from protected Runnable."""
        config: Optional[Dict[str, Any]] = kwargs.get("config", args[0] if len(args) > 0 else None)
        identity = self._evaluate_entry_access(config)
        token = SecurityContextHolder.set_identity(identity)
        input_data = self._sanitize_inbound_input(input_data, identity)
        try:
            if hasattr(self._runnable, "astream"):
                if config is not None:
                    async for chunk in self._runnable.astream(input_data, config):
                        yield self._sanitize_outbound_output(chunk, identity)
                else:
                    async for chunk in self._runnable.astream(input_data):
                        yield self._sanitize_outbound_output(chunk, identity)
            else:
                yield await self.ainvoke(input_data, config)
        finally:
            SecurityContextHolder.reset_identity(token)


    def batch(self, inputs: List[Any], *args: Any, **kwargs: Any) -> List[Any]:
        """Batch invoke protected Runnable across a list of input payloads."""
        config: Optional[Dict[str, Any]] = kwargs.get("config", args[0] if len(args) > 0 else None)
        return [self.invoke(inp, config) for inp in inputs]


