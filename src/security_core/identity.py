"""
Security identity envelopes and in-band invocation context propagation.

Defines caller identity envelopes, state serialization, identity resolution bridge,
and async context propagation holders as specified in Spec 4 and Spec 5.
"""

from typing import Dict, List, Any, Set, Optional
import contextvars

from security_core.constants import (
    DEFAULT_TENANT_ID,
    DEFAULT_CLEARANCE_LEVEL,
    DEFAULT_DEPARTMENT_ID,
    ANONYMOUS_SUBJECT_ID,
    SECURITY_INVOCATION_PARAMS_KEY,
)


class SecurityIdentity:
    """Immutable caller identity envelope containing authenticated attributes.

    Attributes:
        subject_id (str): Unique subject identifier for caller identity.
        tenant_id (str): Multi-tenant isolation boundary identifier.
        roles (Set[str]): Set of security roles assigned to the subject.
        clearance_level (int): Numeric clearance rank assigned to identity.
        department_id (str): Department identifier for organizational access controls.
        attributes (Dict[str, Any]): Dynamic key-value pairs associated with identity.
    """

    def __init__(
        self,
        subject_id: str,
        tenant_id: str,
        roles: Set[str],
        clearance_level: int,
        department_id: str,
        attributes: Dict[str, Any],
    ):
        """Initialize SecurityIdentity.

        Args:
            subject_id: Subject identifier.
            tenant_id: Tenant isolation identifier.
            roles: Set of granted role strings.
            clearance_level: Numeric clearance level rank.
            department_id: Organizational department ID.
            attributes: Additional attribute key-value map.
        """
        self._subject_id = subject_id
        self._tenant_id = tenant_id
        self._roles = frozenset(roles)
        self._clearance_level = clearance_level
        self._department_id = department_id
        self._attributes = dict(attributes)

    @classmethod
    def create(
        self_cls,
        subject_id: str,
        tenant_id: str,
        roles: Set[str],
        clearance_level: int,
        department_id: str,
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method to construct a new SecurityIdentity instance.

        Args:
            subject_id: Caller subject identifier.
            tenant_id: Tenant identifier.
            roles: Set of role strings.
            clearance_level: Clearance level rank.
            department_id: Department ID.
            *args: Optional positional attributes map.
            **kwargs: Optional keyword attributes map.

        Returns:
            SecurityIdentity: Constructed immutable identity object.
        """
        attributes: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("attributes")
        return self_cls(
            subject_id=subject_id,
            tenant_id=tenant_id,
            roles=roles,
            clearance_level=clearance_level,
            department_id=department_id,
            attributes=attributes if isinstance(attributes, dict) else {},
        )

    @classmethod
    def anonymous(self_cls):
        """Factory method constructing an unprivileged anonymous identity.

        Returns:
            SecurityIdentity: Default anonymous identity envelope.
        """
        return self_cls(
            subject_id=ANONYMOUS_SUBJECT_ID,
            tenant_id=DEFAULT_TENANT_ID,
            roles=set(),
            clearance_level=DEFAULT_CLEARANCE_LEVEL,
            department_id=DEFAULT_DEPARTMENT_ID,
            attributes={},
        )

    @property
    def subject_id(self) -> str:
        """Get the unique subject identifier."""
        return self._subject_id

    @property
    def tenant_id(self) -> str:
        """Get the tenant isolation boundary identifier."""
        return self._tenant_id

    @property
    def roles(self) -> Set[str]:
        """Get the set of role entitlements held by this identity."""
        return set(self._roles)

    @property
    def clearance_level(self) -> int:
        """Get the numeric clearance rank of this identity."""
        return self._clearance_level

    @property
    def department_id(self) -> str:
        """Get the department identifier of this identity."""
        return self._department_id

    @property
    def is_anonymous(self) -> bool:
        """Return True if identity represents an anonymous or unauthenticated subject."""
        return bool(self._subject_id is None or str(self._subject_id).upper() == ANONYMOUS_SUBJECT_ID)

    @property
    def attributes(self) -> Dict[str, Any]:
        """Get a copy of dynamic attributes attached to identity."""
        return dict(self._attributes)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize SecurityIdentity into a JSON-compatible dictionary.

        Returns:
            Dict[str, Any]: Serialized identity dictionary.
        """
        return {
            "subject_id": self._subject_id,
            "tenant_id": self._tenant_id,
            "roles": list(self._roles),
            "clearance_level": self._clearance_level,
            "department_id": self._department_id,
            "attributes": self._attributes,
        }

    @classmethod
    def from_dict(self_cls, data: Dict[str, Any]):
        """Deserialize dictionary into a SecurityIdentity instance.

        Args:
            data: Dictionary containing identity fields.

        Returns:
            SecurityIdentity: Constructed identity instance.
        """
        return self_cls(
            subject_id=data.get("subject_id", ANONYMOUS_SUBJECT_ID),
            tenant_id=data.get("tenant_id", DEFAULT_TENANT_ID),
            roles=set(data.get("roles", [])),
            clearance_level=int(data.get("clearance_level", DEFAULT_CLEARANCE_LEVEL)),
            department_id=data.get("department_id", DEFAULT_DEPARTMENT_ID),
            attributes=dict(data.get("attributes", {})),
        )

    def with_trace_context(
        self,
        trace_id: Optional[str],
        span_id: Optional[str],
    ) -> "SecurityIdentity":
        """Return a new SecurityIdentity with W3C OpenTelemetry trace and span identifiers attached.

        Args:
            trace_id: OpenTelemetry 32-character hexadecimal trace identifier.
            span_id: OpenTelemetry 16-character hexadecimal span identifier.

        Returns:
            SecurityIdentity: New immutable identity instance containing the trace context.
        """
        attrs = dict(self._attributes)
        if trace_id is not None:
            attrs["trace_id"] = trace_id
        if span_id is not None:
            attrs["span_id"] = span_id
        return self.__class__.create(
            subject_id=self._subject_id,
            tenant_id=self._tenant_id,
            roles=self.roles,
            clearance_level=self._clearance_level,
            department_id=self._department_id,
            attributes=attrs,
        )


class InvocationParameters:
    """In-band execution parameters envelope carried inside framework metadata/state.

    Attributes:
        security_identity (SecurityIdentity): Caller identity envelope.
        metadata (Dict[str, Any]): Framework invocation metadata dictionary.
    """

    def __init__(self, security_identity: SecurityIdentity, metadata: Dict[str, Any]):
        """Initialize InvocationParameters.

        Args:
            security_identity: Embedded caller identity.
            metadata: Associated invocation metadata dictionary.
        """
        self._security_identity = security_identity
        self._metadata = dict(metadata)

    @classmethod
    def create(self_cls, security_identity: SecurityIdentity, metadata: Dict[str, Any]):
        """Factory method constructing an InvocationParameters instance.

        Args:
            security_identity: Security identity object.
            metadata: Metadata mapping.

        Returns:
            InvocationParameters: Constructed parameters instance.
        """
        return self_cls(security_identity=security_identity, metadata=metadata)

    @property
    def security_identity(self) -> SecurityIdentity:
        """Get the embedded SecurityIdentity."""
        return self._security_identity

    @property
    def metadata(self) -> Dict[str, Any]:
        """Get copy of invocation metadata dictionary."""
        return dict(self._metadata)

    def serialize_to_state(self) -> Dict[str, Any]:
        """Serialize parameters into a state dictionary using standard security key.

        Returns:
            Dict[str, Any]: Dictionary suitable for graph state or framework config.
        """
        return {
            SECURITY_INVOCATION_PARAMS_KEY: {
                "identity": self._security_identity.to_dict(),
                "metadata": self._metadata,
            }
        }

    @classmethod
    def deserialize_from_state(self_cls, state_dict: Dict[str, Any]):
        """Extract and deserialize InvocationParameters from state dictionary.

        Args:
            state_dict: State or config dictionary.

        Returns:
            InvocationParameters: Deserialized parameters or default anonymous instance.
        """
        if SECURITY_INVOCATION_PARAMS_KEY not in state_dict:
            return self_cls(
                security_identity=SecurityIdentity.anonymous(),
                metadata={},
            )
        sec_payload = state_dict[SECURITY_INVOCATION_PARAMS_KEY]
        identity_data = sec_payload.get("identity", {})
        metadata_data = sec_payload.get("metadata", {})
        identity = SecurityIdentity.from_dict(identity_data)
        return self_cls(security_identity=identity, metadata=metadata_data)


ENFORCEMENT_POINT_IDENTITY_BRIDGE: str = "IDENTITY_BRIDGE"
"""Enforcement point identifier for identity bridge resolution."""

REASON_TENANT_BOUND_VIOLATION: str = "TENANT_BOUND_VIOLATION"
"""Reason code for cross-tenant boundary isolation violation."""

REASON_AUTHENTICATION_SUCCESS: str = "AUTHENTICATION_SUCCESS"
"""Reason code for successful identity context resolution."""

THREAT_CATEGORY_IDENTITY_SPOOFING: str = "IDENTITY_SPOOFING"
"""Threat category label for identity spoofing attempts."""

MITIGATION_BLOCKED: str = "BLOCKED"
"""Mitigation action label indicating request was blocked."""

SEVERITY_CRITICAL: str = "CRITICAL_ALERT"
"""Critical audit severity label."""

SEVERITY_INFO: str = "INFORMATIONAL"
"""Informational audit severity label."""

DECISION_DENY: str = "DENY"
"""PDP deny decision outcome."""

DECISION_PERMIT: str = "PERMIT"
"""PDP permit decision outcome."""


class IdentityBridge:
    """Interface and helper utilities for resolving SecurityIdentity from contexts, configs, or headers."""

    @staticmethod
    def resolve_identity(candidate_identity: Optional[SecurityIdentity]) -> SecurityIdentity:
        """Resolve identity from candidate, current context holder, or fall back to anonymous identity.

        Args:
            candidate_identity: Direct identity instance if available.

        Returns:
            SecurityIdentity: Resolved identity object.
        """
        if candidate_identity is not None:
            return candidate_identity
        ctx_identity = SecurityContextHolder.get_identity()
        if ctx_identity is not None:
            return ctx_identity
        return SecurityIdentity.anonymous()

    @staticmethod
    def extract_from_config(config: Optional[Dict[str, Any]]) -> Optional[SecurityIdentity]:
        """Extract SecurityIdentity from Runnable standard config dictionary.

        Args:
            config: Runnable config dictionary containing 'configurable' keys.

        Returns:
            Optional[SecurityIdentity]: Extracted identity object or None if missing.
        """
        if not config or not isinstance(config, dict):
            return None
        configurable = config.get("configurable")
        if isinstance(configurable, dict):
            sec_id = configurable.get("security_identity")
            if isinstance(sec_id, SecurityIdentity):
                return sec_id
            elif isinstance(sec_id, dict):
                return SecurityIdentity.from_dict(sec_id)
        return None

    @staticmethod
    def create_runnable_config(identity: SecurityIdentity) -> Dict[str, Any]:
        """Wrap SecurityIdentity into native LangChain RunnableConfig dictionary.

        Args:
            identity: SecurityIdentity envelope.

        Returns:
            Dict[str, Any]: RunnableConfig dictionary with 'configurable' mapping.
        """
        return {
            "configurable": {
                "security_identity": identity
            }
        }

    @classmethod
    def build_identity_from_claims(
        cls,
        claims: Dict[str, Any],
        clearance_rank_map: Optional[Dict[str, int]],
        default_clearance: int,
    ) -> SecurityIdentity:
        """Construct SecurityIdentity from verified JWT claims or caller metadata.

        Args:
            claims: Token claims or user identity mapping.
            clearance_rank_map: Optional mapping of clearance names to numeric ranks.
            default_clearance: Numeric clearance rank floor.

        Returns:
            SecurityIdentity: Immutable security envelope.
        """
        sub = str(claims.get("sub") or claims.get("email") or claims.get("user_id") or ANONYMOUS_SUBJECT_ID)
        tenant = str(claims.get("tenantId") or claims.get("tenant_id") or DEFAULT_TENANT_ID)
        dept = str(claims.get("department") or claims.get("dept") or DEFAULT_DEPARTMENT_ID)

        raw_roles = claims.get("roles") or claims.get("assignedRoles") or []
        roles_set: Set[str] = set()
        if isinstance(raw_roles, list):
            for r in raw_roles:
                if isinstance(r, str):
                    roles_set.update([role.strip() for role in r.split(",") if role.strip()])
        elif isinstance(raw_roles, str):
            roles_set.update([role.strip() for role in raw_roles.split(",") if role.strip()])

        raw_clr = claims.get("clearanceLevel") or claims.get("clearance") or claims.get("clearance_level")
        if isinstance(raw_clr, int):
            clr = raw_clr
        elif isinstance(raw_clr, str) and raw_clr.isdigit():
            clr = int(raw_clr)
        elif clearance_rank_map and isinstance(raw_clr, str):
            clr = clearance_rank_map.get(raw_clr.upper(), default_clearance)
        elif clearance_rank_map and roles_set:
            role_ranks = [clearance_rank_map.get(r, default_clearance) for r in roles_set if r != "ROLE_GUEST"]
            clr = max(role_ranks) if role_ranks else default_clearance
        else:
            clr = default_clearance

        attrs = dict(claims.get("attributes", {}))
        if claims.get("trace_id"):
            attrs["trace_id"] = claims["trace_id"]
        if claims.get("span_id"):
            attrs["span_id"] = claims["span_id"]

        return SecurityIdentity.create(
            subject_id=sub,
            tenant_id=tenant,
            roles=roles_set,
            clearance_level=clr,
            department_id=dept,
            attributes=attrs,
        )

    def resolve_identity_from_context(self, headers_or_context: Dict[str, Any]) -> SecurityIdentity:
        """Abstract method for resolving identity from raw request context or HTTP headers.

        Args:
            headers_or_context: Context or headers mapping.

        Returns:
            SecurityIdentity: Resolved identity.

        Raises:
            NotImplementedError: If subclass does not implement method.
        """
        raise NotImplementedError("Subclasses must implement resolve_identity_from_context")

    @staticmethod
    def record_tenant_violation(
        audit_manager: Any,
        subject_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        expected_tenant: str,
        trace_id: Optional[str],
        span_id: Optional[str],
    ) -> Any:
        """Record cross-tenant access violation event to audit manager.

        Args:
            audit_manager: Target audit manager instance.
            subject_id: Subject attempting access.
            tenant_id: Claimed tenant ID.
            action: Requested action.
            resource: Resource path or name.
            expected_tenant: Valid tenant boundary ID.
            trace_id: OpenTelemetry trace ID.
            span_id: OpenTelemetry span ID.

        Returns:
            AuditEvent: Constructed and published audit event object.
        """
        from security_core.audit import AuditEvent
        diagnostic_reason = f"Cross-tenant isolation violation: tenantId={tenant_id}"
        metadata = {
            "threat_category": THREAT_CATEGORY_IDENTITY_SPOOFING,
            "reason_code": REASON_TENANT_BOUND_VIOLATION,
            "mitigation_action": MITIGATION_BLOCKED,
            "claimedTenant": tenant_id,
            "expectedTenant": expected_tenant,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        event = AuditEvent.create(
            subject_id=subject_id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            decision=DECISION_DENY,
            diagnostic_reason=diagnostic_reason,
            severity=SEVERITY_CRITICAL,
            metadata=metadata,
            enforcement_point=ENFORCEMENT_POINT_IDENTITY_BRIDGE,
            reason_code=REASON_TENANT_BOUND_VIOLATION,
        )
        event.threat_category = THREAT_CATEGORY_IDENTITY_SPOOFING
        event.mitigation_action = MITIGATION_BLOCKED
        if trace_id:
            event.trace_id = trace_id
        if span_id:
            event.span_id = span_id
        if audit_manager:
            audit_manager.record_event(event)
        return event

    @staticmethod
    def record_auth_success(
        audit_manager: Any,
        subject_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        department: str,
        roles: List[str],
        clearance_level: Any,
        trace_id: Optional[str],
        span_id: Optional[str],
    ) -> Any:
        """Record successful identity authentication event to audit manager.

        Args:
            audit_manager: Target audit manager.
            subject_id: Subject identifier.
            tenant_id: Tenant identifier.
            action: Action identifier.
            resource: Resource identifier.
            department: Department ID.
            roles: List of granted roles.
            clearance_level: Clearance rank.
            trace_id: OpenTelemetry trace ID.
            span_id: OpenTelemetry span ID.

        Returns:
            AuditEvent: Constructed and logged audit event.
        """
        from security_core.audit import AuditEvent
        metadata = {
            "department": department,
            "roles": roles,
            "clearanceLevel": clearance_level,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        event = AuditEvent.create(
            subject_id=subject_id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            decision=DECISION_PERMIT,
            diagnostic_reason="AUTHENTICATED",
            severity=SEVERITY_INFO,
            metadata=metadata,
            enforcement_point=ENFORCEMENT_POINT_IDENTITY_BRIDGE,
            reason_code=REASON_AUTHENTICATION_SUCCESS,
        )
        if trace_id:
            event.trace_id = trace_id
        if span_id:
            event.span_id = span_id
        if audit_manager:
            audit_manager.record_event(event)
        return event


_SECURITY_IDENTITY_CONTEXT_VAR: contextvars.ContextVar[Optional[SecurityIdentity]] = contextvars.ContextVar(
    "security_identity_context_var", default=None
)


class SecurityContextHolder:
    """Thread-local / async ContextVar holder for propagating active SecurityIdentity context."""

    @staticmethod
    def set_identity(identity: Optional[SecurityIdentity]) -> contextvars.Token:
        """Bind SecurityIdentity to the current async task context.

        Args:
            identity: Active security identity to set.

        Returns:
            contextvars.Token: Context reset token.
        """
        return _SECURITY_IDENTITY_CONTEXT_VAR.set(identity)

    @staticmethod
    def get_identity() -> Optional[SecurityIdentity]:
        """Retrieve SecurityIdentity bound to current async task context.

        Returns:
            Optional[SecurityIdentity]: Active security identity or None if unbound.
        """
        return _SECURITY_IDENTITY_CONTEXT_VAR.get()

    @staticmethod
    def reset_identity(token: contextvars.Token) -> None:
        """Reset SecurityIdentity in current context using a previously returned Token.

        Args:
            token: ContextVar token returned from set_identity call.
        """
        _SECURITY_IDENTITY_CONTEXT_VAR.reset(token)


