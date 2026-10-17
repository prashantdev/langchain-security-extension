"""
Function decorator for securing tool callables with pre-execution PEP guards.

Intercepts tool execution requests, evaluates caller identity against required roles,
clearance floor, and CEL parameter constraint expressions as specified in Spec 2.
"""

import functools
from typing import Callable, List, Dict, Any, Optional
from security_core.identity import SecurityIdentity, IdentityBridge, SecurityContextHolder
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest
from security_core.constants import (
    ACTION_TOOL_EXECUTE,
    STRATEGY_HARD_ABORT,
    STRATEGY_RETURN_FEEDBACK,
    HIDDEN_SECURITY_PARAMS,
    PII_SCOPE_FULL_IN_FLIGHT,
    PII_STAGE_TOOL_ARGUMENT,
    PII_STAGE_TOOL_OUTPUT,
)
from security_core.exceptions import ToolExecutionDeniedError, ToolExecutionFeedbackException
from security_core.pii import get_pii_sanitizer, get_pii_scope, PiiContext



def get_tool_schema(tool: Any) -> Dict[str, Any]:
    """Extract tool schema concealing internal security parameters from model context."""
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    description = getattr(tool, "description", None) or getattr(tool, "__doc__", "") or ""

    properties: Dict[str, Any] = {}
    required: List[str] = []

    if hasattr(tool, "args_schema") and tool.args_schema:
        raw_schema = tool.args_schema.schema() if hasattr(tool.args_schema, "schema") else tool.args_schema
        if isinstance(raw_schema, dict):
            props = dict(raw_schema.get("properties", {}))
            reqs = list(raw_schema.get("required", []))
            for hidden in HIDDEN_SECURITY_PARAMS:
                props.pop(hidden, None)
                if hidden in reqs:
                    reqs.remove(hidden)
            properties = props
            required = reqs
    else:
        func = getattr(tool, "func", tool)
        import inspect
        try:
            sig = inspect.signature(func)
            for param_name, param in sig.parameters.items():
                if param_name in ("self", "cls") or param_name in HIDDEN_SECURITY_PARAMS:
                    continue
                properties[param_name] = {"type": "string", "title": param_name}
                if param.default is inspect.Parameter.empty:
                    required.append(param_name)
        except Exception:
            pass

    return {
        "name": tool_name,
        "description": description.strip(),
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
        "schema_hiding_verified": True,
    }

class SecuredToolConfig:
    """Security configuration specification for secured tool functions.

    Attributes:
        required_roles (List[str]): List of security roles required to execute the tool.
        min_clearance (int): Minimum clearance level rank required for tool execution.
        cel_expression (str): CEL condition expression string evaluating invocation parameters.
        is_mutative (bool): Flag indicating if tool performs state mutation operations.
        pdp_engine (PolicyDecisionEngine): PDP engine instance for evaluation.
    """

    def __init__(
        self,
        required_roles: List[str],
        min_clearance: int,
        cel_expression: str,
        is_mutative: bool,
        pdp_engine: PolicyDecisionEngine,
        *args: Any,
        **kwargs: Any,
    ):
        """Initialize SecuredToolConfig.

        Args:
            required_roles: Roles list.
            min_clearance: Clearance floor.
            cel_expression: CEL condition string.
            is_mutative: Mutative action flag.
            pdp_engine: PDP decision engine instance.
            *args: Additional arguments (e.g. masked_params).
            **kwargs: Additional keyword arguments.
        """
        self._required_roles = list(required_roles)
        self._min_clearance = min_clearance
        self._cel_expression = cel_expression
        self._is_mutative = is_mutative
        self._pdp_engine = pdp_engine
        self._masked_params = list(kwargs.get("masked_params", args[0] if len(args) > 0 else []))

    @classmethod
    def create(
        cls,
        required_roles: List[str],
        min_clearance: int,
        cel_expression: str,
        is_mutative: bool,
        pdp_engine: PolicyDecisionEngine,
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method to construct SecuredToolConfig."""
        return cls(
            required_roles,
            min_clearance,
            cel_expression,
            is_mutative,
            pdp_engine,
            *args,
            **kwargs,
        )
        """Factory method to construct SecuredToolConfig.

        Args:
            required_roles: Roles list.
            min_clearance: Clearance floor.
            cel_expression: CEL expression string.
            is_mutative: Mutative boolean flag.
            pdp_engine: Policy decision engine instance.

        Returns:
            SecuredToolConfig: New configuration object.
        """
        return cls(
            required_roles=required_roles,
            min_clearance=min_clearance,
            cel_expression=cel_expression,
            is_mutative=is_mutative,
            pdp_engine=pdp_engine,
        )

    @property
    def required_roles(self) -> List[str]:
        """Get copy of required roles list."""
        return list(self._required_roles)

    @property
    def min_clearance(self) -> int:
        """Get minimum clearance level rank."""
        return self._min_clearance

    @property
    def cel_expression(self) -> str:
        """Get CEL parameter constraint expression string."""
        return self._cel_expression

    @property
    def is_mutative(self) -> bool:
        """Check if tool action is mutative."""
        return self._is_mutative

    @property
    def pdp_engine(self) -> PolicyDecisionEngine:
        """Get configured PolicyDecisionEngine instance."""
        return self._pdp_engine

    @property
    def masked_params(self) -> List[str]:
        """Get list of masked parameter names."""
        return list(self._masked_params)


def secured_tool(
    required_roles: List[str],
    min_clearance: int,
    cel_expression: str,
    is_mutative: bool,
    *args: Any,
    **kwargs: Any,
) -> Callable:
    """Decorator securing tool functions with pre-execution authorization check.

    Args:
        required_roles: List of mandatory role strings for execution.
        min_clearance: Clearance floor rank required.
        cel_expression: CEL condition evaluating caller identity and arguments.
        is_mutative: True if tool modifies system state, triggering HARD_ABORT on failure.
        *args: Optional positional arguments (pdp_engine, entity_resolver, masked_params).
        **kwargs: Optional keyword arguments (pdp_engine, entity_resolver, masked_params).

    Returns:
        Callable: Wrapped target tool function with PEP interceptor guard.
    """
    pdp_engine: Optional[PolicyDecisionEngine] = kwargs.get("pdp_engine", args[0] if len(args) > 0 else None)
    entity_resolver: Optional[Any] = kwargs.get("entity_resolver", args[1] if len(args) > 1 else None)
    masked_params: List[str] = list(kwargs.get("masked_params", args[2] if len(args) > 2 else []))

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            caller_config = kwargs.get("config") or kwargs.get("runnable_config")
            caller_identity = kwargs.pop("security_identity", None)

            if caller_identity is None and caller_config:
                caller_identity = IdentityBridge.extract_from_config(caller_config)

            if caller_identity is None and args and isinstance(args[0], SecurityIdentity):
                caller_identity = args[0]
                args = args[1:]

            caller_identity = IdentityBridge.resolve_identity(caller_identity)

            if caller_config is None and caller_identity is not None:
                caller_config = IdentityBridge.create_runnable_config(caller_identity)

            # Resolve PDP engine if None
            engine = pdp_engine
            if engine is None and args and hasattr(args[0], "pdp_engine") and getattr(args[0], "pdp_engine") is not None:
                engine = getattr(args[0], "pdp_engine")

            if engine is None and "config" in kwargs and isinstance(kwargs["config"], dict):
                cfg_conf = kwargs["config"].get("configurable", {})
                if isinstance(cfg_conf, dict):
                    engine = cfg_conf.get("sec:pdp_engine") or cfg_conf.get("pdp_engine")
                    if engine is None:
                        vh = cfg_conf.get("sec:violation_handler")
                        if vh and hasattr(vh, "pdp_engine"):
                            engine = vh.pdp_engine
                if engine is None:
                    callbacks_list = kwargs["config"].get("callbacks", [])
                    if isinstance(callbacks_list, list):
                        for cb in callbacks_list:
                            if hasattr(cb, "pdp_engine"):
                                engine = cb.pdp_engine
                                break

            if engine is None:
                from security_core.registry import SecurityRegistry
                engine = SecurityRegistry.get_pdp_engine()

            if engine is None:
                from security_core.pdp import EmbeddedPolicyEngine
                engine = EmbeddedPolicyEngine.create()

            resolved_resolver = entity_resolver
            if resolved_resolver is None and args and hasattr(args[0], "entity_resolver") and getattr(args[0], "entity_resolver") is not None:
                resolved_resolver = getattr(args[0], "entity_resolver")

            if resolved_resolver is None and "config" in kwargs and isinstance(kwargs["config"], dict):
                cfg_conf = kwargs["config"].get("configurable", {})
                if isinstance(cfg_conf, dict):
                    resolved_resolver = cfg_conf.get("sec:entity_resolver") or cfg_conf.get("entity_resolver")

            if resolved_resolver is None and engine is not None and hasattr(engine, "_cel_evaluator") and engine._cel_evaluator:
                resolved_resolver = getattr(engine._cel_evaluator, "entity_resolver", None)

            if resolved_resolver is None:
                from security_core.registry import SecurityRegistry
                resolved_resolver = SecurityRegistry.get_entity_resolver()

            if resolved_resolver and hasattr(engine, "_cel_evaluator") and engine._cel_evaluator:
                engine._cel_evaluator.entity_resolver = resolved_resolver

            import inspect

            # Bind positional and keyword arguments to parameter names
            bound_args: Dict[str, Any] = {}
            try:
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())
                if params and params[0] in ("self", "cls"):
                    if not args or not (hasattr(args[0], "__class__") and args[0].__class__.__name__ in func.__qualname__):
                        args_to_bind = (None,) + args
                    else:
                        args_to_bind = args
                else:
                    args_to_bind = args

                clean_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
                bound = sig.bind_partial(*args_to_bind, **clean_kwargs)
                bound.apply_defaults()
                bound_args = dict(bound.arguments)
            except Exception:
                bound_args = dict(kwargs)

            bound_args.pop("config", None)
            bound_args.pop("self", None)
            bound_args.pop("cls", None)

            aliases: Dict[str, Any] = {}
            for k, v in list(bound_args.items()):
                if "_" in k:
                    parts = k.split("_")
                    camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
                    aliases[camel] = v
                else:
                    import re
                    snake = re.sub(r'(?<!^)(?=[A-Z])', '_', k).lower()
                    aliases[snake] = v
            bound_args.update(aliases)

            tool_name = func.__name__
            resource_descriptor = {
                "name": tool_name,
                "target_id": tool_name,
                "tenant_id": caller_identity.tenant_id,
                "required_roles": required_roles,
                "min_clearance": min_clearance,
                "cel_expression": cel_expression,
                "is_mutative": is_mutative,
                "arguments": bound_args,
                "masked_params": masked_params,
                "tool_metadata": {
                    "name": tool_name,
                    "isMutative": is_mutative,
                },
            }

            request = PolicyEvaluationRequest.create(
                subject=caller_identity,
                action=ACTION_TOOL_EXECUTE,
                resource=resource_descriptor,
                context={"config": kwargs.get("config")},
            )

            decision = engine.evaluate(request)

            if not decision.is_permitted:
                # Retry budget tracking & parameter escalation checking in config
                cfg = kwargs.get("config")
                retries = 0
                prev_args = None
                param_escalation_detected = False

                if isinstance(cfg, dict) and isinstance(cfg.get("configurable"), dict):
                    retries = cfg["configurable"].get("sec:retry_count", 0) + 1
                    cfg["configurable"]["sec:retry_count"] = retries
                    prev_args = cfg["configurable"].get("sec:prev_args")
                    cfg["configurable"]["sec:prev_args"] = bound_args

                    if prev_args is not None and prev_args != bound_args:
                        param_escalation_detected = True

                strategy = decision.obligations.get("strategy", STRATEGY_HARD_ABORT if is_mutative else STRATEGY_RETURN_FEEDBACK)
                reason_msg = f"Policy violation: Access denied for tool '{tool_name}' ({decision.diagnostic_reason})"

                if param_escalation_detected and hasattr(engine, "audit_manager") and engine.audit_manager:
                    from security_core.audit import AuditEvent
                    from security_core.constants import (
                        EVENT_PARAMETER_PRIVILEGE_ESCALATION,
                        PEP_TOOL_INTERCEPTOR,
                        SEVERITY_SECURITY_ALERT,
                    )
                    engine.audit_manager.record_event(AuditEvent.create(
                        subject_id=caller_identity.subject_id,
                        tenant_id=caller_identity.tenant_id,
                        action=ACTION_TOOL_EXECUTE,
                        resource=tool_name,
                        decision="DENIED",
                        diagnostic_reason="Parameter privilege escalation attempt detected: arguments mutated across retries",
                        severity=SEVERITY_SECURITY_ALERT,
                        metadata={"previous_args": prev_args, "current_args": bound_args},
                        enforcement_point=PEP_TOOL_INTERCEPTOR,
                        reason_code=EVENT_PARAMETER_PRIVILEGE_ESCALATION,
                    ))

                # Record violation with registered ToolViolationHandler if present in config
                vh = None
                if isinstance(cfg, dict) and isinstance(cfg.get("configurable"), dict):
                    vh = cfg["configurable"].get("sec:violation_handler")

                resolution = None
                if vh is not None and hasattr(vh, "record_tool_violation"):
                    resolution = vh.record_tool_violation(
                        tool_name=tool_name,
                        diagnostic_reason=str(decision.diagnostic_reason or ""),
                        is_mutative=is_mutative,
                        config=cfg,
                        caller_identity=caller_identity,
                    )
                elif isinstance(cfg, dict) and isinstance(cfg.get("configurable"), dict):
                    from security_adapter_langchain.violation_handler import (
                        ViolationResolution,
                        STATUS_BLOCKED_BY_POLICY,
                        REMED_SEC_BLOCKED_POLICY,
                        REMED_EXEC_ABORTED,
                    )
                    should_abort_flag = bool(strategy == STRATEGY_HARD_ABORT or is_mutative or retries > 2)
                    resolution = ViolationResolution.create(
                        status=STATUS_BLOCKED_BY_POLICY if should_abort_flag else "ACCESS_DENIED",
                        action_entry=f"Blocked execution of tool '{tool_name}' ({decision.diagnostic_reason})",
                        root_cause=f"Policy violation: Access denied for tool '{tool_name}' ({decision.diagnostic_reason})",
                        user_message=reason_msg,
                        remediation_security=REMED_SEC_BLOCKED_POLICY if should_abort_flag else "FEEDBACK_REFUSAL",
                        remediation_execution=REMED_EXEC_ABORTED if should_abort_flag else "SYNTHETIC_PAYLOAD",
                        should_abort=should_abort_flag,
                        diagnostic_reason=decision.diagnostic_reason,
                        tool_name=tool_name,
                    )
                    cfg["configurable"]["sec:last_violation"] = resolution

                should_hard_abort = bool(
                    strategy == STRATEGY_HARD_ABORT
                    or is_mutative
                    or retries > 2
                    or (resolution and resolution.should_abort)
                )

                if should_hard_abort:
                    if retries > 2 and hasattr(engine, "audit_manager") and engine.audit_manager:
                        from security_core.audit import AuditEvent
                        from security_core.constants import (
                            EVENT_POLICY_BRUTE_FORCE_DETECTED,
                            PEP_TOOL_INTERCEPTOR,
                            SEVERITY_CRITICAL_ALERT,
                        )
                        engine.audit_manager.record_event(AuditEvent.create(
                            subject_id=caller_identity.subject_id,
                            tenant_id=caller_identity.tenant_id,
                            action=ACTION_TOOL_EXECUTE,
                            resource=tool_name,
                            decision="HARD_ABORT",
                            diagnostic_reason="Retry budget exceeded: Policy brute force probe detected",
                            severity=SEVERITY_CRITICAL_ALERT,
                            metadata={"retries": retries, "arguments": bound_args},
                            enforcement_point=PEP_TOOL_INTERCEPTOR,
                            reason_code=EVENT_POLICY_BRUTE_FORCE_DETECTED,
                        ))
                    raise ToolExecutionDeniedError.for_tool(
                        tool_name=tool_name,
                        message=reason_msg,
                        diagnostic_reason=decision.diagnostic_reason,
                    )
                else:
                    refusal_payload = {
                        "status": "ACCESS_DENIED",
                        "tool": tool_name,
                        "reason": reason_msg,
                        "diagnostic_reason": decision.diagnostic_reason,
                    }
                    return refusal_payload

            cfg = kwargs.get("config")
            if isinstance(cfg, dict) and isinstance(cfg.get("configurable"), dict):
                cfg["configurable"]["sec:last_violation"] = None

            func_kwargs = dict(kwargs)
            func_kwargs.pop("config", None)
            func_kwargs.pop("security_identity", None)
            func_kwargs.pop("runnable_config", None)

            # Re-inject caller SecurityIdentity and RunnableConfig if target function signature declares them
            try:
                sig = inspect.signature(func)
                if "security_identity" in sig.parameters:
                    func_kwargs["security_identity"] = caller_identity
                if "config" in sig.parameters:
                    func_kwargs["config"] = caller_config
                elif "runnable_config" in sig.parameters:
                    func_kwargs["runnable_config"] = caller_config
            except Exception:
                pass

            if get_pii_scope() == PII_SCOPE_FULL_IN_FLIGHT:
                sanitizer = get_pii_sanitizer()
                ctx_in = PiiContext.create(
                    PII_STAGE_TOOL_ARGUMENT,
                    caller_identity.tenant_id,
                    caller_identity.subject_id,
                    tool_name,
                    {"required_roles": required_roles, "min_clearance": min_clearance},
                )
                func_kwargs = sanitizer.sanitize_payload(func_kwargs, ctx_in)

            result = func(*args, **func_kwargs)

            if get_pii_scope() == PII_SCOPE_FULL_IN_FLIGHT:
                sanitizer = get_pii_sanitizer()
                ctx_out = PiiContext.create(
                    PII_STAGE_TOOL_OUTPUT,
                    caller_identity.tenant_id,
                    caller_identity.subject_id,
                    tool_name,
                    {"required_roles": required_roles, "min_clearance": min_clearance},
                )
                if isinstance(result, str):
                    result = sanitizer.sanitize_text(result, ctx_out)
                elif isinstance(result, dict):
                    result = sanitizer.sanitize_payload(result, ctx_out)
                elif isinstance(result, list):
                    result = [
                        sanitizer.sanitize_payload(item, ctx_out) if isinstance(item, dict)
                        else (sanitizer.sanitize_text(item, ctx_out) if isinstance(item, str) else item)
                        for item in result
                    ]

            return result

        try:
            import inspect
            orig_sig = inspect.signature(func)
            filtered_params = [
                p for p in orig_sig.parameters.values()
                if p.name not in HIDDEN_SECURITY_PARAMS
            ]
            wrapper.__signature__ = orig_sig.replace(parameters=filtered_params)
        except Exception:
            pass

        return wrapper

    return decorator


