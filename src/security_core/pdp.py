"""
Policy Decision Point (PDP) subsystem and Embedded Evaluation Engine.

Implements standard PDP interfaces, two-tier decision caching, role inheritance
graph traversal, and embedded ABAC/RBAC/CEL evaluation engines as specified in Spec 4.
"""

import hashlib
import json
import time
from enum import Enum
from typing import Dict, List, Set, Any, Optional
from security_core.identity import SecurityIdentity
from security_core.cel_evaluator import CELEvaluator
from security_core.audit import AuditManager, AuditEvent
from security_core.constants import (
    DECISION_PERMIT,
    DECISION_DENY,
    DECISION_NOT_APPLICABLE,
    DECISION_INDETERMINATE,
    CLASSIFICATION_TO_RANK,
    REASON_AUTHORIZED,
    REASON_TENANT_MISMATCH,
    REASON_INSUFFICIENT_CLEARANCE,
    REASON_MISSING_REQUIRED_ROLE,
    REASON_PARAMETER_CONSTRAINT_FAILED,
    REASON_QUARANTINED_CHUNK,
    REASON_UNAUTHENTICATED,
    ANONYMOUS_SUBJECT_ID,
    SEVERITY_INFORMATIONAL,
    SEVERITY_WARNING,
    SEVERITY_SECURITY_ALERT,
    SEVERITY_CRITICAL_ALERT,
    EVENT_TENANT_BOUND_VIOLATION,
    EVENT_CACHE_EVICTED,
    STRATEGY_HARD_ABORT,
    STRATEGY_RETURN_FEEDBACK,
    CONFIG_KEY_DECISION_CACHE,
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_CACHE_MAX_ENTRIES,
)


class DecisionEnum(str, Enum):
    """Standardized policy evaluation verdict status enumeration."""
    PERMIT = DECISION_PERMIT
    DENY = DECISION_DENY
    NOT_APPLICABLE = DECISION_NOT_APPLICABLE
    INDETERMINATE = DECISION_INDETERMINATE


class PolicyEvaluationRequest:
    """Four-part policy evaluation request envelope containing Subject, Action, Resource, and Context.

    Attributes:
        subject (SecurityIdentity): Caller security identity envelope.
        action (str): Target action identifier (e.g., 'tool:execute', 'agent:invoke').
        resource (Dict[str, Any]): Map of resource attributes and target metadata.
        context (Dict[str, Any]): Dynamic execution environment context dictionary.
    """

    def __init__(
        self,
        subject: SecurityIdentity,
        action: str,
        resource: Dict[str, Any],
        context: Dict[str, Any],
    ):
        """Initialize PolicyEvaluationRequest.

        Args:
            subject: Caller security identity.
            action: Action string identifier.
            resource: Resource attributes map.
            context: Execution context dictionary.
        """
        self._subject = subject
        self._action = action
        self._resource = dict(resource)
        self._context = dict(context)

    @classmethod
    def create(
        cls,
        subject: SecurityIdentity,
        action: str,
        resource: Dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method to construct a PolicyEvaluationRequest.

        Args:
            subject: Caller security identity envelope.
            action: Action identifier string.
            resource: Resource attributes dictionary.
            *args: Optional positional context dictionary.
            **kwargs: Optional keyword context dictionary.

        Returns:
            PolicyEvaluationRequest: Constructed request instance.
        """
        context: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("context")
        return cls(
            subject=subject,
            action=action,
            resource=resource,
            context=context if isinstance(context, dict) else {},
        )

    @property
    def subject(self) -> SecurityIdentity:
        """Get the caller SecurityIdentity."""
        return self._subject

    @property
    def action(self) -> str:
        """Get the requested action identifier."""
        return self._action

    @property
    def resource(self) -> Dict[str, Any]:
        """Get copy of target resource attributes dictionary."""
        return dict(self._resource)

    @property
    def context(self) -> Dict[str, Any]:
        """Get copy of execution environment context dictionary."""
        return dict(self._context)


PolicyRequest = PolicyEvaluationRequest



class PolicyDecision:
    """Standardized decision outcome object returned by PDP evaluation.

    Attributes:
        decision (str): Decision verdict string ('PERMIT', 'DENY', 'NOT_APPLICABLE', 'INDETERMINATE').
        diagnostic_reason (str): Reason code or message describing decision rationale.
        obligations (Dict[str, Any]): Dictionary of enforcement obligations required by PEP.
    """

    def __init__(
        self,
        decision: str,
        diagnostic_reason: str,
        obligations: Dict[str, Any],
    ):
        """Initialize PolicyDecision.

        Args:
            decision: Verdict status string.
            diagnostic_reason: Rationale description or reason code.
            obligations: Dictionary of obligation parameters.
        """
        self._decision = decision
        self._diagnostic_reason = diagnostic_reason
        self._obligations = dict(obligations)

    @classmethod
    def create(cls, decision: str, diagnostic_reason: str, obligations: Dict[str, Any]):
        """Factory method creating a PolicyDecision.

        Args:
            decision: Decision status string.
            diagnostic_reason: Reason code.
            obligations: Obligations dictionary.

        Returns:
            PolicyDecision: New decision instance.
        """
        return cls(decision=decision, diagnostic_reason=diagnostic_reason, obligations=obligations)

    @classmethod
    def permit(cls, diagnostic_reason: str, obligations: Dict[str, Any]):
        """Factory method creating a PERMIT decision.

        Args:
            diagnostic_reason: Authorization reason description.
            obligations: Enforcement obligations dictionary.

        Returns:
            PolicyDecision: PERMIT decision object.
        """
        return cls(decision=DECISION_PERMIT, diagnostic_reason=diagnostic_reason, obligations=obligations)

    @classmethod
    def deny(cls, diagnostic_reason: str, obligations: Dict[str, Any]):
        """Factory method creating a DENY decision.

        Args:
            diagnostic_reason: Denial reason description.
            obligations: Enforcement obligations dictionary (e.g., handling strategy).

        Returns:
            PolicyDecision: DENY decision object.
        """
        return cls(decision=DECISION_DENY, diagnostic_reason=diagnostic_reason, obligations=obligations)

    @classmethod
    def not_applicable(cls, diagnostic_reason: str):
        """Factory method creating a NOT_APPLICABLE decision.

        Args:
            diagnostic_reason: Rationale description.

        Returns:
            PolicyDecision: NOT_APPLICABLE decision object.
        """
        return cls(decision=DECISION_NOT_APPLICABLE, diagnostic_reason=diagnostic_reason, obligations={})

    @classmethod
    def indeterminate(cls, diagnostic_reason: str):
        """Factory method creating an INDETERMINATE decision.

        Args:
            diagnostic_reason: Error rationale description.

        Returns:
            PolicyDecision: INDETERMINATE decision object.
        """
        return cls(decision=DECISION_INDETERMINATE, diagnostic_reason=diagnostic_reason, obligations={})

    @property
    def decision(self) -> str:
        """Get raw decision verdict string."""
        return self._decision

    @property
    def decision_enum(self) -> DecisionEnum:
        """Get decision verdict as a typed DecisionEnum."""
        return DecisionEnum(self._decision)

    @property
    def diagnostic_reason(self) -> str:
        """Get diagnostic reason string."""
        return self._diagnostic_reason

    @property
    def obligations(self) -> Dict[str, Any]:
        """Get copy of obligations dictionary."""
        return dict(self._obligations)

    @property
    def obligations_list(self) -> List[str]:
        """Get obligations formatted as string list for legacy compatibility.

        Returns:
            List[str]: Formatted obligation string list.
        """
        res: List[str] = []
        strategy = self._obligations.get("strategy")
        if strategy:
            res.append(str(strategy))
        for k, v in self._obligations.items():
            if k != "strategy":
                res.append(f"{k}:{v}")
        return res

    @property
    def is_permitted(self) -> bool:
        """Check if decision is PERMIT.

        Returns:
            bool: True if decision is PERMIT, False otherwise.
        """
        return self._decision == DECISION_PERMIT


class RoleGraph:
    """Directed Acyclic Graph (DAG) for hierarchical role inheritance resolution."""

    def __init__(self):
        """Initialize empty RoleGraph."""
        self._inheritance: Dict[str, Set[str]] = {}

    @classmethod
    def create(cls):
        """Factory method creating a RoleGraph.

        Returns:
            RoleGraph: New RoleGraph instance.
        """
        return cls()

    def add_inheritance(self, parent_role: str, child_role: str) -> None:
        """Declares that parent_role inherits child_role permissions.

        Args:
            parent_role: Role that inherits permissions.
            child_role: Role whose permissions are inherited.

        Raises:
            ValueError: If adding inheritance creates a cyclic role graph.
        """
        if parent_role not in self._inheritance:
            self._inheritance[parent_role] = set()
        self._inheritance[parent_role].add(child_role)
        self._assert_no_cycles()

    def expand_roles(self, roles: Set[str]) -> Set[str]:
        """Transitively expands assigned roles through graph hierarchy.

        Args:
            roles: Base set of assigned caller roles.

        Returns:
            Set[str]: Expanded set including all inherited roles.
        """
        expanded: Set[str] = set()
        visited: Set[str] = set()

        def dfs(role: str) -> None:
            if role in visited:
                return
            visited.add(role)
            expanded.add(role)
            for child in self._inheritance.get(role, set()):
                dfs(child)

        for r in roles:
            dfs(r)
        return expanded

    def _assert_no_cycles(self) -> None:
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def has_cycle(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for neighbor in self._inheritance.get(node, set()):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            rec_stack.remove(node)
            return False

        for role in self._inheritance:
            if role not in visited:
                if has_cycle(role):
                    raise ValueError(f"Cyclic role inheritance detected at role: '{role}'")


class PolicyRule:
    """Declarative policy rule model for Deny-Overrides matching.

    Attributes:
        rule_id (str): Unique rule identifier.
        target_action (str): Action target pattern or wildcard.
        effect (str): Rule effect ('PERMIT' or 'DENY').
        required_roles (List[str]): List of roles required by rule.
        min_clearance (Optional[int]): Minimum required clearance level.
        cel_condition (Optional[str]): CEL expression condition.
        on_denial (str): Denial handling strategy ('HARD_ABORT' or 'RETURN_FEEDBACK').
    """

    def __init__(
        self,
        rule_id: str,
        target_action: str,
        effect: str,
        required_roles: List[str],
        min_clearance: Optional[int],
        cel_condition: Optional[str],
        on_denial: str,
    ):
        """Initialize PolicyRule.

        Args:
            rule_id: Unique rule ID.
            target_action: Action string.
            effect: Effect verdict.
            required_roles: List of required role strings.
            min_clearance: Clearance floor.
            cel_condition: CEL expression.
            on_denial: Violation strategy.
        """
        self.rule_id = rule_id
        self.target_action = target_action
        self.effect = effect
        self.required_roles = list(required_roles)
        self.min_clearance = min_clearance
        self.cel_condition = cel_condition
        self.on_denial = on_denial

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Construct PolicyRule from dictionary payload.

        Args:
            data: Rule dictionary representation.

        Returns:
            PolicyRule: Constructed PolicyRule object.
        """
        return cls(
            rule_id=str(data.get("rule_id", "rule_default")),
            target_action=str(data.get("target_action", "*")),
            effect=str(data.get("effect", DECISION_PERMIT)),
            required_roles=list(data.get("required_roles", [])),
            min_clearance=data.get("min_clearance"),
            cel_condition=data.get("cel_condition") or data.get("condition"),
            on_denial=str(data.get("on_denial", STRATEGY_HARD_ABORT)),
        )


class PolicyDecisionEngine:
    """Abstract SPI interface for Policy Decision Point engines."""

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Evaluate a policy decision request.

        Args:
            request: Evaluation request envelope.

        Returns:
            PolicyDecision: Computed policy decision outcome.

        Raises:
            NotImplementedError: Must be implemented by concrete PDP engines.
        """
        raise NotImplementedError("Subclasses must implement evaluate")


class TwoTierDecisionCache:
    """Two-tier caching engine (Tier 1 Invocation-Scoped + Tier 2 Cross-Request Static)."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize TwoTierDecisionCache.

        Args:
            *args: Optional positional arguments (ttl_seconds, max_entries, l1_enabled, l2_enabled).
            **kwargs: Optional keyword arguments.
        """
        ttl_seconds = kwargs.get("ttl_seconds", args[0] if len(args) > 0 else DEFAULT_CACHE_TTL_SECONDS)
        max_entries = kwargs.get("max_entries", args[1] if len(args) > 1 else DEFAULT_CACHE_MAX_ENTRIES)
        l1_enabled = kwargs.get("l1_enabled", args[2] if len(args) > 2 else True)
        l2_enabled = kwargs.get("l2_enabled", args[3] if len(args) > 3 else True)
        self._tier2_cache: Dict[str, tuple[PolicyDecision, float]] = {}
        self._ttl_seconds = float(ttl_seconds)
        self._max_entries = int(max_entries)
        self._l1_enabled = bool(l1_enabled)
        self._l2_enabled = bool(l2_enabled)

    @classmethod
    def create(cls, *args: Any, **kwargs: Any):
        """Factory method creating TwoTierDecisionCache.

        Args:
            *args: Optional positional arguments.
            **kwargs: Optional keyword arguments.

        Returns:
            TwoTierDecisionCache: New cache instance.
        """
        return cls(*args, **kwargs)

    @property
    def l1_enabled(self) -> bool:
        """Check if Tier 1 invocation cache is enabled."""
        return self._l1_enabled

    @property
    def l2_enabled(self) -> bool:
        """Check if Tier 2 static cache is enabled."""
        return self._l2_enabled

    def compute_request_hash(self, request: PolicyEvaluationRequest) -> str:
        """Compute SHA256 deterministic hash key prefixed by subject_id for an evaluation request.

        Args:
            request: Policy evaluation request object.

        Returns:
            str: Subject-prefixed hexadecimal SHA256 digest string.
        """
        res_str = json.dumps(request.resource, sort_keys=True, default=str)
        roles_str = ",".join(sorted(list(request.subject.roles))) if request.subject.roles else ""
        s = f"{request.subject.subject_id}:{request.subject.tenant_id}:{request.subject.clearance_level}:{request.subject.department_id}:{roles_str}:{request.action}:{res_str}"
        digest = hashlib.sha256(s.encode()).hexdigest()
        return f"{request.subject.subject_id}:{digest}"

    def get_invocation_cache(self, config: Optional[Dict[str, Any]], cache_key: str) -> Optional[PolicyDecision]:
        """Tier 1: Looks up decision in RunnableConfig['configurable']['sec:decision_cache'].

        Args:
            config: RunnableConfig dictionary.
            cache_key: Request hash key.

        Returns:
            Optional[PolicyDecision]: Cached decision or None if miss.
        """
        if not self._l1_enabled or not config or not isinstance(config, dict):
            return None
        configurable = config.get("configurable")
        if isinstance(configurable, dict):
            inv_cache = configurable.get(CONFIG_KEY_DECISION_CACHE)
            if isinstance(inv_cache, dict):
                return inv_cache.get(cache_key)
        return None

    def put_invocation_cache(self, config: Optional[Dict[str, Any]], cache_key: str, decision: PolicyDecision) -> None:
        """Tier 1: Stores decision in RunnableConfig['configurable']['sec:decision_cache'].

        Args:
            config: Target RunnableConfig dictionary.
            cache_key: Request hash key.
            decision: Computed PolicyDecision object to store.
        """
        if not self._l1_enabled or not config or not isinstance(config, dict):
            return
        configurable = config.get("configurable")
        if isinstance(configurable, dict):
            if CONFIG_KEY_DECISION_CACHE not in configurable or not isinstance(configurable[CONFIG_KEY_DECISION_CACHE], dict):
                configurable[CONFIG_KEY_DECISION_CACHE] = {}
            configurable[CONFIG_KEY_DECISION_CACHE][cache_key] = decision

    def get_static(self, cache_key: str) -> Optional[PolicyDecision]:
        """Tier 2: Looks up decision in process-wide static cache with TTL.

        Args:
            cache_key: Hash key.

        Returns:
            Optional[PolicyDecision]: Unexpired cached decision or None.
        """
        if not self._l2_enabled:
            return None
        entry = self._tier2_cache.get(cache_key)
        if entry:
            decision, ts = entry
            if time.time() - ts <= self._ttl_seconds:
                return decision
            del self._tier2_cache[cache_key]
        return None

    def put_static(self, cache_key: str, decision: PolicyDecision) -> None:
        """Tier 2: Stores decision in process-wide static cache with bounded max entries.

        Args:
            cache_key: Hash key.
            decision: PolicyDecision to cache.
        """
        if not self._l2_enabled:
            return
        if len(self._tier2_cache) >= self._max_entries and cache_key not in self._tier2_cache:
            oldest_key = min(self._tier2_cache.keys(), key=lambda k: self._tier2_cache[k][1])
            del self._tier2_cache[oldest_key]
        self._tier2_cache[cache_key] = (decision, time.time())

    def evict_subject(self, subject_id: str, *args: Any, **kwargs: Any) -> int:
        """Evict all cached policy decisions for a specific subject across L2 and optional L1 config.

        Args:
            subject_id: Subject identifier whose decisions must be evicted.
            *args: Optional positional config dict.
            **kwargs: Optional keyword config dict.

        Returns:
            int: Count of evicted cache entries.
        """
        prefix = f"{subject_id}:"
        evicted = 0
        keys_to_remove = [k for k in self._tier2_cache.keys() if k.startswith(prefix)]
        for k in keys_to_remove:
            del self._tier2_cache[k]
            evicted += 1

        config = kwargs.get("config", args[0] if len(args) > 0 else None)
        if isinstance(config, dict):
            configurable = config.get("configurable")
            if isinstance(configurable, dict):
                inv_cache = configurable.get(CONFIG_KEY_DECISION_CACHE)
                if isinstance(inv_cache, dict):
                    l1_keys = [k for k in inv_cache.keys() if k.startswith(prefix)]
                    for k in l1_keys:
                        del inv_cache[k]
                        evicted += 1
        return evicted

    def flush(self) -> None:
        """Flush all Tier 2 static cache entries."""
        self._tier2_cache.clear()


class EmbeddedPolicyEngine(PolicyDecisionEngine):
    """In-memory PDP evaluating tenant, clearance, roles, and CEL constraints with Deny-Overrides rules."""

    def __init__(
        self,
        role_graph: RoleGraph,
        cel_evaluator: CELEvaluator,
        audit_manager: AuditManager,
        *args: Any,
        **kwargs: Any,
    ):
        """Initialize EmbeddedPolicyEngine.

        Args:
            role_graph: RoleGraph instance for role inheritance expansion.
            cel_evaluator: CELEvaluator instance for parameter expression validation.
            audit_manager: AuditManager instance for security event logging.
            *args: Optional positional arguments (rules, decision_cache).
            **kwargs: Optional keyword arguments (rules, decision_cache).
        """
        rules = kwargs.get("rules", args[0] if len(args) > 0 else None)
        decision_cache = kwargs.get("decision_cache", args[1] if len(args) > 1 else None)
        self._role_graph = role_graph
        self._cel_evaluator = cel_evaluator
        self._audit_manager = audit_manager
        self._rules = list(rules) if rules is not None else []
        self._cache = decision_cache if isinstance(decision_cache, TwoTierDecisionCache) else TwoTierDecisionCache.create()
        self.enforce_strict_tenant_isolation = True
        self._invalidation_callbacks: List[Any] = []

    @classmethod
    def create(cls):
        """Factory method constructing default EmbeddedPolicyEngine.

        Returns:
            EmbeddedPolicyEngine: Engine initialized with default components.
        """
        return cls(
            role_graph=RoleGraph.create(),
            cel_evaluator=CELEvaluator.create(),
            audit_manager=AuditManager.create(publishers=[]),
        )

    @classmethod
    def with_components(
        cls,
        role_graph: RoleGraph,
        cel_evaluator: CELEvaluator,
        audit_manager: AuditManager,
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method constructing EmbeddedPolicyEngine with specified components.

        Args:
            role_graph: Custom RoleGraph.
            cel_evaluator: Custom CELEvaluator.
            audit_manager: Custom AuditManager.
            *args: Optional positional arguments (rules, decision_cache).
            **kwargs: Optional keyword arguments (rules, decision_cache).

        Returns:
            EmbeddedPolicyEngine: Engine instance.
        """
        return cls(
            role_graph,
            cel_evaluator,
            audit_manager,
            *args,
            **kwargs,
        )

    @property
    def role_graph(self) -> RoleGraph:
        """Get the configured RoleGraph."""
        return self._role_graph

    @property
    def audit_manager(self) -> AuditManager:
        """Get the configured AuditManager."""
        return self._audit_manager

    @property
    def decision_cache(self) -> TwoTierDecisionCache:
        """Get the configured TwoTierDecisionCache."""
        return self._cache

    def register_invalidation_callback(self, callback: Any) -> None:
        """Register a callback to be invoked upon cache eviction or subject invalidation."""
        self._invalidation_callbacks.append(callback)

    def clear_cache(self) -> None:
        """Flush all Tier 2 static cache entries."""
        self._cache.flush()
        for cb in list(getattr(self, "_invalidation_callbacks", [])):
            try:
                cb()
            except Exception:
                pass

    def evict_subject_cache(self, subject_id: str, *args: Any, **kwargs: Any) -> int:
        """Evict cached decisions for a subject upon role revocation and emit an audit event.

        Args:
            subject_id: Subject identifier whose cached decisions are invalidated.
            *args: Optional positional config dict.
            **kwargs: Optional keyword config dict.

        Returns:
            int: Count of evicted entries.
        """
        evicted_count = self._cache.evict_subject(subject_id, *args, **kwargs)
        for cb in list(getattr(self, "_invalidation_callbacks", [])):
            try:
                cb(subject_id)
            except Exception:
                pass
        event = AuditEvent.create(
            subject_id=subject_id,
            tenant_id=str(kwargs.get("tenant_id", "DEFAULT")),
            action="pdp:cache_evict",
            resource="TwoTierDecisionCache",
            decision=DECISION_PERMIT,
            diagnostic_reason=f"{EVENT_CACHE_EVICTED}: Evicted {evicted_count} cached decisions for {subject_id}",
            severity=SEVERITY_INFORMATIONAL,
            metadata={"evicted_count": evicted_count},
            reason_code=EVENT_CACHE_EVICTED,
        )
        self._audit_manager.record_event(event)
        return evicted_count

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a PolicyRule to engine rule store.

        Args:
            rule: PolicyRule instance.
        """
        self._rules.append(rule)

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Evaluate access request through tenant isolation, quarantine, clearance lattice, roles, and CEL constraints.

        Args:
            request: Evaluation request envelope.

        Returns:
            PolicyDecision: Evaluation decision status and obligations.
        """
        subject = request.subject
        resource = request.resource
        req_config = request.context.get("config") if isinstance(request.context, dict) else None

        # Check Tier 1 Invocation Cache and Tier 2 Static Cache
        cache_key = self._cache.compute_request_hash(request)
        tier1_decision = self._cache.get_invocation_cache(req_config, cache_key)
        if tier1_decision:
            if req_config and isinstance(req_config, dict) and isinstance(req_config.get("configurable"), dict):
                req_config["configurable"]["sec:pdp_cache_hit"] = True
                req_config["configurable"]["sec:pdp_cache_tier"] = "tier1"
            return tier1_decision
        cached_decision = self._cache.get_static(cache_key)
        if cached_decision:
            if req_config and isinstance(req_config, dict) and isinstance(req_config.get("configurable"), dict):
                req_config["configurable"]["sec:pdp_cache_hit"] = True
                req_config["configurable"]["sec:pdp_cache_tier"] = "tier2"
            return cached_decision

        # 0. Quarantine Check
        is_quarantined = bool(resource.get("sec:quarantined") or resource.get("quarantined"))
        if is_quarantined:
            expanded_roles = self._role_graph.expand_roles(subject.roles)
            if "ROLE_ADMIN" not in expanded_roles or subject.clearance_level < 3:
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=REASON_QUARANTINED_CHUNK,
                    severity=SEVERITY_WARNING,
                    obligations={},
                    reason_code=REASON_QUARANTINED_CHUNK,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 0.1 Unauthenticated Subject Check (Fail-closed for anonymous unless explicitly permitted by rule)
        is_anon = (
            subject is None
            or subject.is_anonymous
            or subject.subject_id is None
            or str(subject.subject_id).upper() == ANONYMOUS_SUBJECT_ID
        )
        if is_anon:
            anon_permitted = False
            if self._rules:
                for rule in self._rules:
                    if (rule.target_action == "*" or rule.target_action == request.action) and rule.effect == DECISION_PERMIT:
                        anon_permitted = True
                        break
            if not anon_permitted:
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=REASON_UNAUTHENTICATED,
                    severity=SEVERITY_WARNING,
                    obligations={},
                    reason_code=REASON_UNAUTHENTICATED,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 1. Multi-Tenancy Check
        required_tenant = resource.get("tenant_id")
        if required_tenant:
            tenant_mismatch = (subject.tenant_id not in required_tenant) if isinstance(required_tenant, (set, list, tuple)) else (required_tenant != subject.tenant_id)
            if tenant_mismatch:
                reason_code = EVENT_TENANT_BOUND_VIOLATION if self.enforce_strict_tenant_isolation else None
                severity = SEVERITY_CRITICAL_ALERT if self.enforce_strict_tenant_isolation else SEVERITY_WARNING
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=REASON_TENANT_MISMATCH,
                    severity=severity,
                    obligations={},
                    reason_code=reason_code,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 2. Clearance Lattice Check (Supports numeric rank or string classification level)
        req_clr_val = resource.get("min_clearance") or resource.get("clearance_floor") or resource.get("sec:clearance_level")
        if req_clr_val is not None:
            req_rank = CLASSIFICATION_TO_RANK.get(str(req_clr_val).upper(), int(req_clr_val) if str(req_clr_val).isdigit() else 0)
            subj_rank = subject.clearance_level
            if subj_rank < req_rank:
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=REASON_INSUFFICIENT_CLEARANCE,
                    severity=SEVERITY_WARNING,
                    obligations={},
                    reason_code=None,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 3. Role Inheritance Matching
        required_roles = resource.get("required_roles") or resource.get("sec:required_roles") or resource.get("sec:allowed_roles")
        if required_roles:
            expanded_roles = self._role_graph.expand_roles(subject.roles)
            if not set(required_roles).intersection(expanded_roles):
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=REASON_MISSING_REQUIRED_ROLE,
                    severity=SEVERITY_WARNING,
                    obligations={},
                    reason_code=None,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 4. CEL Parameter Expression Evaluation
        cel_expression = resource.get("cel_expression")
        if cel_expression:
            runtime_args = resource.get("arguments", {})
            tool_meta = resource.get("tool_metadata", {})
            passed = self._cel_evaluator.evaluate(
                expression=cel_expression,
                subject=subject,
                args=runtime_args,
                tool=tool_meta,
                config=req_config,
            )
            if not passed:
                strategy = STRATEGY_HARD_ABORT if resource.get("is_mutative") else STRATEGY_RETURN_FEEDBACK
                diag_reason = REASON_PARAMETER_CONSTRAINT_FAILED
                if self._cel_evaluator.last_diagnostic_reason:
                    diag_reason = self._cel_evaluator.last_diagnostic_reason
                elif "entities." in str(cel_expression):
                    diag_reason = "CEL_HYDRATION_FAILED (hydrated owner mismatch)"
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_DENY,
                    diagnostic_reason=diag_reason,
                    severity=SEVERITY_SECURITY_ALERT,
                    obligations={"strategy": strategy},
                    reason_code=None,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 5. Declarative Deny-Overrides Evaluation (if custom rules are defined)
        if self._rules:
            matched_permit = False
            for rule in self._rules:
                if rule.target_action == "*" or rule.target_action == request.action:
                    # Validate rule constraints: roles, clearance, cel_condition
                    rule_matches = True

                    if rule.required_roles:
                        expanded_roles = self._role_graph.expand_roles(subject.roles)
                        if not set(rule.required_roles).intersection(expanded_roles):
                            rule_matches = False

                    if rule_matches and rule.min_clearance is not None:
                        if subject.clearance_level < int(rule.min_clearance):
                            rule_matches = False

                    if rule_matches and rule.cel_condition:
                        runtime_args = resource.get("arguments", {})
                        tool_meta = resource.get("tool_metadata", {})
                        if not self._cel_evaluator.evaluate(
                            expression=rule.cel_condition,
                            subject=subject,
                            args=runtime_args,
                            tool=tool_meta,
                            config=req_config,
                        ):
                            rule_matches = False

                    if rule_matches:
                        if rule.effect == DECISION_DENY:
                            decision = self._record_and_return(
                                request=request,
                                decision_status=DECISION_DENY,
                                diagnostic_reason=f"Rule {rule.rule_id} DENY",
                                severity=SEVERITY_SECURITY_ALERT,
                                obligations={"strategy": rule.on_denial},
                                reason_code=None,
                            )
                            self._cache.put_static(cache_key, decision)
                            return decision
                        elif rule.effect == DECISION_PERMIT:
                            matched_permit = True

            if not matched_permit:
                decision = self._record_and_return(
                    request=request,
                    decision_status=DECISION_NOT_APPLICABLE,
                    diagnostic_reason="No matching permit policy rule found",
                    severity=SEVERITY_WARNING,
                    obligations={},
                    reason_code=None,
                )
                self._cache.put_static(cache_key, decision)
                return decision

        # 6. Permit Default
        decision = self._record_and_return(
            request=request,
            decision_status=DECISION_PERMIT,
            diagnostic_reason=REASON_AUTHORIZED,
            severity=SEVERITY_INFORMATIONAL,
            obligations={},
            reason_code=None,
        )
        self._cache.put_static(cache_key, decision)
        return decision

    def _record_and_return(
        self,
        request: PolicyEvaluationRequest,
        decision_status: str,
        diagnostic_reason: str,
        severity: str,
        obligations: Dict[str, Any],
        reason_code: Optional[str],
    ) -> PolicyDecision:
        resource_id = str(request.resource.get("name") or request.resource.get("target_id") or "UNKNOWN")
        event = AuditEvent.create(
            subject_id=request.subject.subject_id,
            tenant_id=request.subject.tenant_id,
            action=request.action,
            resource=resource_id,
            decision=decision_status,
            diagnostic_reason=diagnostic_reason,
            severity=severity,
            metadata={"obligations": obligations},
            reason_code=reason_code,
        )
        if reason_code == EVENT_TENANT_BOUND_VIOLATION:
            event.threat_category = "IDENTITY_SPOOFING"
            event.mitigation_action = "BLOCKED"
        self._audit_manager.record_event(event)

        dec = PolicyDecision.create(
            decision=decision_status,
            diagnostic_reason=diagnostic_reason,
            obligations=obligations,
        )
        req_config = request.context.get("config") if isinstance(request.context, dict) else None
        if req_config:
            cache_key = self._cache.compute_request_hash(request)
            self._cache.put_invocation_cache(req_config, cache_key, dec)
        return dec


