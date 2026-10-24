"""
Common Expression Language (CEL) evaluator for security parameter constraints.

Provides deterministic evaluation over `subject`, `args`, and `tool` namespaces
as specified in Spec 2 and Spec 4.
"""

import ast
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from security_core.identity import SecurityIdentity


class EntityAttributeResolverSPI(ABC):
    """Hydrates dynamic entity attributes for CEL parameter constraint validation."""

    @abstractmethod
    def resolve(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """Returns entity attribute dictionary for given entity type and ID.

        Args:
            entity_type: Entity type category identifier.
            entity_id: Unique entity instance ID.

        Returns:
            Dict[str, Any]: Entity attribute dictionary mapping.
        """
        pass


from security_core.constants import CONFIG_KEY_ENTITY_CACHE, REASON_FAIL_CLOSED_NULL_ENTITY

DEFAULT_ENTITY_RESOLVER: Optional[EntityAttributeResolverSPI] = None
DIAGNOSTIC_FAIL_CLOSED_NULL_ENTITY: str = f"{REASON_FAIL_CLOSED_NULL_ENTITY} (Unresolvable entity attributes)"


class _EntityAttrDict(dict):
    """Hydrated entity dictionary enforcing fail-closed resolution when attributes are missing or null."""

    def __getattr__(self, key: str) -> Any:
        if key not in self or self[key] is None:
            raise KeyError(f"Null or missing entity attribute: '{key}'")
        val = self[key]
        if isinstance(val, dict) and not isinstance(val, _EntityAttrDict):
            return _EntityAttrDict(val)
        return val


class CELEvaluator:
    """Evaluates parameter constraint expressions safely over evaluation context."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize CELEvaluator."""
        entity_resolver = kwargs.get("entity_resolver", args[0] if len(args) > 0 else DEFAULT_ENTITY_RESOLVER)
        self._entity_resolver = entity_resolver
        self._last_diagnostic_reason: Optional[str] = None
        self._last_hydrated_entities: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def create(cls, *args: Any, **kwargs: Any):
        """Factory method to construct a CELEvaluator."""
        entity_resolver = kwargs.get("entity_resolver", args[0] if len(args) > 0 else DEFAULT_ENTITY_RESOLVER)
        return cls(entity_resolver=entity_resolver)

    @property
    def entity_resolver(self) -> Optional[EntityAttributeResolverSPI]:
        """Get the configured entity resolver SPI instance."""
        return self._entity_resolver

    @entity_resolver.setter
    def entity_resolver(self, resolver: Optional[EntityAttributeResolverSPI]) -> None:
        """Set or update the entity resolver SPI instance."""
        self._entity_resolver = resolver

    @property
    def last_diagnostic_reason(self) -> Optional[str]:
        """Get the diagnostic reason code from the most recent evaluation, if any."""
        return self._last_diagnostic_reason

    @property
    def last_hydrated_entities(self) -> Dict[str, Dict[str, Any]]:
        """Get the map of entities hydrated during the most recent evaluation."""
        return dict(self._last_hydrated_entities)

    def evaluate(
        self,
        expression: str,
        subject: SecurityIdentity,
        args: Dict[str, Any],
        tool: Dict[str, Any],
        *extra_args: Any,
        **kwargs: Any,
    ) -> bool:
        """Evaluate a CEL parameter constraint expression against invocation context.

        Args:
            expression: Common Expression Language (CEL) boolean condition string.
            subject: SecurityIdentity envelope of the calling user or agent.
            args: Map of resolved runtime argument parameters passed to the tool.
            tool: Metadata attributes dictionary describing the target tool.
            *extra_args: Optional positional arguments (e.g., config dictionary).
            **kwargs: Optional keyword arguments (e.g., config dictionary).

        Returns:
            bool: True if the expression evaluates to truthy; False on failure or syntax error (fail-closed).
        """
        self._last_diagnostic_reason = None
        self._last_hydrated_entities = {}
        if not expression or not expression.strip():
            return True

        config = kwargs.get("config", extra_args[0] if len(extra_args) > 0 else None)
        normalized_expr = self._preprocess_cel_syntax(expression)
        eval_scope = self._build_evaluation_scope(subject, args, tool, config)

        try:
            tree = ast.parse(normalized_expr, mode="eval")
            result = self._eval_ast_node(tree.body, eval_scope)
            return bool(result)
        except KeyError:
            self._last_diagnostic_reason = DIAGNOSTIC_FAIL_CLOSED_NULL_ENTITY
            return False
        except Exception:
            # Fail closed to DENY (False) on evaluation errors, missing variables, or syntax failures
            return False

    def _preprocess_cel_syntax(self, expr: str) -> str:
        """Translates CEL operator syntax (&&, ||, ternary ?) into Python AST syntax."""
        result = expr.replace("&&", " and ").replace("||", " or ")
        if "?" in result and ":" in result:
            parts = result.split("?", 1)
            condition = parts[0].strip()
            rest = parts[1]
            true_false = rest.split(":", 1)
            true_val = true_false[0].strip()
            false_val = true_false[1].strip()
            result = f"({true_val}) if ({condition}) else ({false_val})"
        return result

    def _build_evaluation_scope(
        self,
        subject: SecurityIdentity,
        args: Dict[str, Any],
        tool: Dict[str, Any],
        config: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Constructs attribute dictionary scope for subject, args, tool, and hydrated entities namespaces."""
        subject_dict = {
            "id": subject.subject_id,
            "tenant_id": subject.tenant_id,
            "tenantId": subject.tenant_id,
            "roles": subject.roles,
            "clearance": subject.clearance_level,
            "clearance_level": subject.clearance_level,
            "dept": subject.department_id,
            "department_id": subject.department_id,
            "attributes": subject.attributes,
        }

        entity_cache: Dict[str, Dict[str, Any]] = {}
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            entity_cache = config["configurable"].setdefault(CONFIG_KEY_ENTITY_CACHE, {})

        entities_scope: Dict[str, Any] = {}
        if self._entity_resolver:
            evaluator_ref = self

            class _EntityProxy:
                def __init__(self, resolver: EntityAttributeResolverSPI, etype: str):
                    self._resolver = resolver
                    self._etype = etype

                def _resolve_with_cache(self, eid: str) -> _EntityAttrDict:
                    cache_key = f"{self._etype}:{eid}"
                    if cache_key in entity_cache:
                        res = entity_cache[cache_key]
                    else:
                        res = self._resolver.resolve(self._etype, str(eid))
                        if res is not None:
                            entity_cache[cache_key] = dict(res)
                    if res is None:
                        raise KeyError(f"Unresolvable entity '{eid}' of type '{self._etype}'")
                    evaluator_ref._last_hydrated_entities[cache_key] = dict(res)
                    return _EntityAttrDict(res)

                def __getitem__(self, eid: str) -> _EntityAttrDict:
                    return self._resolve_with_cache(str(eid))

                def __getattr__(self, eid: str) -> _EntityAttrDict:
                    return self._resolve_with_cache(str(eid))

            class _EntitiesDict(dict):
                def __init__(self, resolver: EntityAttributeResolverSPI):
                    self._resolver = resolver

                def __getitem__(self, etype: str) -> Any:
                    return _EntityProxy(self._resolver, etype)

                def __getattr__(self, etype: str) -> Any:
                    return _EntityProxy(self._resolver, etype)

            entities_scope = _EntitiesDict(self._entity_resolver)

        return {
            "subject": _AttrDict(subject_dict),
            "args": _AttrDict(args),
            "tool": _AttrDict(tool),
            "entities": entities_scope,
            "true": True,
            "false": False,
            "null": None,
            "None": None,
        }

    def _eval_ast_node(self, node: ast.AST, scope: Dict[str, Any]) -> Any:
        """Safe AST node recursive evaluation."""
        if isinstance(node, ast.Expression):
            return self._eval_ast_node(node.body, scope)

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id in scope:
                return scope[node.id]
            raise NameError(f"Undefined variable in expression: '{node.id}'")

        if isinstance(node, ast.Attribute):
            obj = self._eval_ast_node(node.value, scope)
            if hasattr(obj, node.attr):
                return getattr(obj, node.attr)
            if isinstance(obj, str):
                if node.attr == "startsWith":
                    return obj.startswith
                elif node.attr == "endsWith":
                    return obj.endswith
                elif node.attr == "contains":
                    return lambda sub: sub in obj
                elif node.attr in ("toLowerCase", "lower"):
                    return obj.lower
                elif node.attr in ("toUpperCase", "upper"):
                    return obj.upper
            if isinstance(obj, dict) and node.attr in obj:
                return obj[node.attr]
            return None

        if isinstance(node, ast.Subscript):
            value = self._eval_ast_node(node.value, scope)
            slice_val = self._eval_ast_node(node.slice, scope)
            return value[slice_val]

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_ast_node(node.operand, scope)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand

        if isinstance(node, ast.BinOp):
            left = self._eval_ast_node(node.left, scope)
            right = self._eval_ast_node(node.right, scope)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.Mod):
                return left % right

        if isinstance(node, ast.BoolOp):
            values = [self._eval_ast_node(val, scope) for val in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)

        if isinstance(node, ast.Compare):
            left = self._eval_ast_node(node.left, scope)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_ast_node(comparator, scope)
                if isinstance(op, ast.Eq) and not (left == right):
                    return False
                elif isinstance(op, ast.NotEq) and not (left != right):
                    return False
                elif isinstance(op, ast.Lt) and not (left < right):
                    return False
                elif isinstance(op, ast.LtE) and not (left <= right):
                    return False
                elif isinstance(op, ast.Gt) and not (left > right):
                    return False
                elif isinstance(op, ast.GtE) and not (left >= right):
                    return False
                elif isinstance(op, ast.In) and not (left in right):
                    return False
                elif isinstance(op, ast.NotIn) and not (left not in right):
                    return False
                left = right
            return True

        if isinstance(node, ast.IfExp):
            test = self._eval_ast_node(node.test, scope)
            if test:
                return self._eval_ast_node(node.body, scope)
            else:
                return self._eval_ast_node(node.orelse, scope)

        if isinstance(node, ast.Call):
            func = self._eval_ast_node(node.func, scope)
            args = [self._eval_ast_node(arg, scope) for arg in node.args]
            if callable(func):
                return func(*args)
            return None

        if isinstance(node, ast.List):
            return [self._eval_ast_node(el, scope) for el in node.elts]

        if isinstance(node, ast.Tuple):
            return tuple(self._eval_ast_node(el, scope) for el in node.elts)

        if isinstance(node, ast.Set):
            return set(self._eval_ast_node(el, scope) for el in node.elts)

        if isinstance(node, ast.Dict):
            keys = [self._eval_ast_node(k, scope) for k in node.keys]
            vals = [self._eval_ast_node(v, scope) for v in node.values]
            return dict(zip(keys, vals))

        raise TypeError(f"Unsupported AST node type: {type(node).__name__}")


class _AttrDict(dict):
    """Dictionary supporting dot-notation attribute access."""

    def __getattr__(self, key: str) -> Any:
        try:
            val = self[key]
            if isinstance(val, dict) and not isinstance(val, _AttrDict):
                return _AttrDict(val)
            return val
        except KeyError:
            return None

    def __setattr__(self, key: str, value: Any) -> None:
        self[key] = value


