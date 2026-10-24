"""
LangGraph state schema definitions and thread-agnostic state node guards.

Provides in-band security envelope propagation across stateful graph nodes
as specified in Spec 0 and Spec 4.
"""

from typing import Dict, Any, Sequence, Annotated, Callable
from typing_extensions import TypedDict
from security_core.identity import SecurityIdentity, InvocationParameters
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest
from security_core.constants import SECURITY_INVOCATION_PARAMS_KEY, ACTION_AGENT_INVOKE
from security_core.exceptions import SecurityAuthorizationError


class SecuredAgentState(TypedDict):
    """LangGraph state schema incorporating in-band security envelope.

    Attributes:
        messages (Sequence[Any]): Sequence of chat message objects.
        sec_invocation_parameters (Dict[str, Any]): Embedded security invocation parameters state dictionary.
    """
    messages: Sequence[Any]
    sec_invocation_parameters: Dict[str, Any]


class LangGraphNodeGuard:
    """Interceptor for LangGraph graph nodes enforcing security context propagation and authorization.

    Attributes:
        node_name (str): Identifier of graph node target.
        required_roles (Sequence[str]): Sequence of required role strings.
        min_clearance (int): Minimum required clearance level rank.
        pdp_engine (PolicyDecisionEngine): PDP decision engine instance.
    """

    def __init__(
        self,
        node_name: str,
        required_roles: Sequence[str],
        min_clearance: int,
        pdp_engine: PolicyDecisionEngine,
    ):
        """Initialize LangGraphNodeGuard.

        Args:
            node_name: Target node identifier.
            required_roles: Roles sequence.
            min_clearance: Clearance level floor.
            pdp_engine: PDP decision engine instance.
        """
        self._node_name = node_name
        self._required_roles = list(required_roles)
        self._min_clearance = min_clearance
        self._pdp_engine = pdp_engine

    @classmethod
    def create(
        cls,
        node_name: str,
        required_roles: Sequence[str],
        min_clearance: int,
        pdp_engine: PolicyDecisionEngine,
    ):
        """Factory method constructing a LangGraphNodeGuard.

        Args:
            node_name: Target graph node name.
            required_roles: Required role strings sequence.
            min_clearance: Clearance floor rank.
            pdp_engine: PDP decision engine.

        Returns:
            LangGraphNodeGuard: New guard instance.
        """
        return cls(
            node_name=node_name,
            required_roles=required_roles,
            min_clearance=min_clearance,
            pdp_engine=pdp_engine,
        )

    @property
    def node_name(self) -> str:
        """Get the guarded node identifier string."""
        return self._node_name

    @property
    def required_roles(self) -> Sequence[str]:
        """Get copy of required role identifiers."""
        return list(self._required_roles)

    @property
    def min_clearance(self) -> int:
        """Get minimum clearance level rank."""
        return self._min_clearance

    @property
    def pdp_engine(self) -> PolicyDecisionEngine:
        """Get the configured PolicyDecisionEngine instance."""
        return self._pdp_engine

    def wrap_node(self, node_fn: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """Wraps a LangGraph node function with security evaluation.

        Args:
            node_fn: Target graph node callable accepting state dictionary and returning updated state.

        Returns:
            Callable[[Dict[str, Any]], Dict[str, Any]]: Guarded node function.
        """

        def guarded_node(state: Dict[str, Any]) -> Dict[str, Any]:
            inv_params = InvocationParameters.deserialize_from_state(state)
            identity = inv_params.security_identity

            request = PolicyEvaluationRequest.create(
                subject=identity,
                action=ACTION_AGENT_INVOKE,
                resource={
                    "target_id": self._node_name,
                    "tenant_id": identity.tenant_id,
                    "required_roles": self._required_roles,
                    "min_clearance": self._min_clearance,
                },
                context={"node_name": self._node_name},
            )

            decision = self._pdp_engine.evaluate(request)
            if not decision.is_permitted:
                raise SecurityAuthorizationError.create(
                    message=f"LangGraph Node '{self._node_name}' authorization failed: {decision.diagnostic_reason}",
                    diagnostic_reason=decision.diagnostic_reason,
                    obligations=decision.obligations,
                )

            # Ensure security envelope persists in returned state
            output_state = node_fn(state)
            if isinstance(output_state, dict) and SECURITY_INVOCATION_PARAMS_KEY not in output_state:
                output_state[SECURITY_INVOCATION_PARAMS_KEY] = state.get(
                    SECURITY_INVOCATION_PARAMS_KEY,
                    inv_params.serialize_to_state()[SECURITY_INVOCATION_PARAMS_KEY],
                )
            return output_state

        return guarded_node

