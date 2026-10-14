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
)
from security_core.exceptions import ToolExecutionDeniedError, ToolExecutionFeedbackException

from security_core.constants import HIDDEN_SECURITY_PARAMS


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
            # Extract caller identity from kwargs, config, ContextHolder, or fallback to anonymous
            caller_identity = kwargs.pop("security_identity", None)

            if caller_identity is None and "config" in kwargs:
                caller_identity = IdentityBridge.extract_from_config(kwargs.get("config"))

            if caller_identity is None and args and isinstance(args[0], SecurityIdentity):
                caller_identity = args[0]
                args = args[1:]

            caller_identity = IdentityBridge.resolve_identity(caller_identity)

            # Resolve PDP engine if None
            engine = pdp_engine
            if engine is None:
                try:
                    from app.security.security_integration import get_pdp_engine
                    engine = get_pdp_engine()
                except Exception:
                    from security_core.pdp import EmbeddedPolicyEngine, RoleGraph
                    engine = EmbeddedPolicyEngine.create(RoleGraph())

            resolved_resolver = entity_resolver
            if resolved_resolver is None:
                try:
                    from app.security.entity_resolver import entity_resolver_instance
                    resolved_resolver = entity_resolver_instance
                except Exception:
                    pass

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

                diag_reason_str = str(decision.diagnostic_reason) if decision.diagnostic_reason else ""
                is_cel_violation = bool("CEL" in diag_reason_str or "Parameter Constraint" in diag_reason_str)
                if is_cel_violation:
                    strategy = STRATEGY_HARD_ABORT
                else:
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

                if strategy == STRATEGY_HARD_ABORT or is_mutative or retries > 2:
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

            func_kwargs = dict(kwargs)
            func_kwargs.pop("config", None)
            func_kwargs.pop("security_identity", None)
            return func(*args, **func_kwargs)

        return wrapper

    return decorator


