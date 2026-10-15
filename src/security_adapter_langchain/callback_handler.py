"""
LangChain BaseCallbackHandler integration for Agent & Tool authorization guards.

Intercepts LangChain framework callback events (`on_chain_start`, `on_tool_start`)
to perform PDP authorization evaluations as specified in Spec 0 and Spec 2.
"""

from typing import Dict, Any, List, Optional
from langchain_core.callbacks import BaseCallbackHandler
from security_core.identity import SecurityIdentity
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest
from security_core.constants import ACTION_AGENT_INVOKE, ACTION_TOOL_EXECUTE
from security_core.exceptions import SecurityAuthorizationError, ToolExecutionDeniedError


class SecureCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler performing pre-execution PEP evaluations.

    Attributes:
        pdp_engine (PolicyDecisionEngine): Configured PDP decision engine instance.
        security_identity (SecurityIdentity): Active caller security identity envelope.
    """

    def __init__(
        self,
        pdp_engine: PolicyDecisionEngine,
        security_identity: SecurityIdentity,
    ):
        """Initialize SecureCallbackHandler.

        Args:
            pdp_engine: Policy decision engine instance.
            security_identity: Caller identity envelope.
        """
        self._pdp_engine = pdp_engine
        self._security_identity = security_identity

    @classmethod
    def create(
        cls,
        pdp_engine: PolicyDecisionEngine,
        security_identity: SecurityIdentity,
    ):
        """Factory method to construct SecureCallbackHandler.

        Args:
            pdp_engine: Policy decision engine.
            security_identity: Security identity object.

        Returns:
            SecureCallbackHandler: Constructed handler instance.
        """
        return cls(pdp_engine=pdp_engine, security_identity=security_identity)

    @property
    def pdp_engine(self) -> PolicyDecisionEngine:
        """Get the configured PolicyDecisionEngine."""
        return self._pdp_engine

    @property
    def security_identity(self) -> SecurityIdentity:
        """Get the bound SecurityIdentity."""
        return self._security_identity

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        run_id: Any,
        parent_run_id: Any,
        tags: Optional[List[str]],
        metadata: Optional[Dict[str, Any]],
        **kwargs: Any,
    ) -> None:
        """Agent Invocation Guard intercepting chain entry and evaluating access permissions.

        Args:
            serialized: Serialized chain metadata mapping.
            inputs: Chain input arguments mapping.
            run_id: Execution run ID.
            parent_run_id: Parent run ID if nested.
            tags: Operational tags list.
            metadata: Additional execution metadata.

        Raises:
            SecurityAuthorizationError: If PDP denies chain entry.
        """
        chain_name = str(serialized.get("name") or serialized.get("id") or "LangChainRunnable")
        req_roles = serialized.get("required_roles") or (metadata.get("required_roles") if metadata else None)
        min_clr = serialized.get("min_clearance") or (metadata.get("min_clearance") if metadata else None)
        tenant = (metadata.get("tenant_id") if metadata else None) or serialized.get("tenant_id") or self._security_identity.tenant_id

        request = PolicyEvaluationRequest.create(
            subject=self._security_identity,
            action=ACTION_AGENT_INVOKE,
            resource={
                "target_id": chain_name,
                "tenant_id": tenant,
                "required_roles": req_roles,
                "min_clearance": min_clr,
            },
            context={"run_id": str(run_id), "metadata": metadata or {}},
        )
        decision = self._pdp_engine.evaluate(request)
        if not decision.is_permitted:
            raise SecurityAuthorizationError.create(
                message=f"Agent invocation denied for '{chain_name}': {decision.diagnostic_reason}",
                diagnostic_reason=decision.diagnostic_reason,
                obligations=decision.obligations,
            )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        run_id: Any,
        parent_run_id: Any,
        tags: Optional[List[str]],
        metadata: Optional[Dict[str, Any]],
        inputs: Optional[Dict[str, Any]],
        **kwargs: Any,
    ) -> None:
        """Tool Execution Interceptor hook evaluating tool access and CEL parameter constraints.

        Args:
            serialized: Serialized tool metadata map.
            input_str: Raw tool input string.
            run_id: Run ID.
            parent_run_id: Parent run ID.
            tags: Event tags.
            metadata: Metadata dictionary.
            inputs: Structured tool inputs map.

        Raises:
            ToolExecutionDeniedError: If PDP denies tool execution.
        """
        tool_name = str(serialized.get("name") or "LangChainTool")
        tool_args = inputs if inputs is not None else {"raw_input": input_str}
        req_roles = serialized.get("required_roles") or (metadata.get("required_roles") if metadata else None)
        min_clr = serialized.get("min_clearance") or (metadata.get("min_clearance") if metadata else None)
        cel_expr = serialized.get("cel_expression") or (metadata.get("cel_expression") if metadata else None)
        is_mutative = bool(serialized.get("is_mutative") or (metadata.get("is_mutative") if metadata else True))
        tenant = (metadata.get("tenant_id") if metadata else None) or serialized.get("tenant_id") or self._security_identity.tenant_id

        request = PolicyEvaluationRequest.create(
            subject=self._security_identity,
            action=ACTION_TOOL_EXECUTE,
            resource={
                "name": tool_name,
                "target_id": tool_name,
                "tenant_id": tenant,
                "required_roles": req_roles,
                "min_clearance": min_clr,
                "cel_expression": cel_expr,
                "is_mutative": is_mutative,
                "arguments": tool_args,
                "tool_metadata": {
                    "name": tool_name,
                    "isMutative": is_mutative,
                },
            },
            context={"run_id": str(run_id), "metadata": metadata or {}},
        )
        decision = self._pdp_engine.evaluate(request)
        if not decision.is_permitted:
            strategy = decision.obligations.get("strategy")
            if strategy == "RETURN_FEEDBACK" and not is_mutative:
                # Feedback strategy returns synthetic info
                return
            raise ToolExecutionDeniedError.for_tool(
                tool_name=tool_name,
                message=f"Tool execution denied for '{tool_name}': {decision.diagnostic_reason}",
                diagnostic_reason=decision.diagnostic_reason,
            )

