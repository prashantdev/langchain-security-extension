"""
Global SPI registry for security extension components.

Enables consuming applications to register default PDP engines and Entity Attribute
Resolvers without coupling the library to host application packages.
"""

from typing import Optional
from security_core.pdp import PolicyDecisionEngine
from security_core.cel_evaluator import EntityAttributeResolverSPI


class SecurityRegistry:
    """Decoupled global SPI registry for host applications."""

    _default_pdp_engine: Optional[PolicyDecisionEngine] = None
    _default_entity_resolver: Optional[EntityAttributeResolverSPI] = None

    @classmethod
    def configure(
        cls,
        pdp_engine: Optional[PolicyDecisionEngine] = None,
        entity_resolver: Optional[EntityAttributeResolverSPI] = None,
    ) -> None:
        """Register default engine and resolver instances."""
        if pdp_engine is not None:
            cls._default_pdp_engine = pdp_engine
        if entity_resolver is not None:
            cls._default_entity_resolver = entity_resolver

    @classmethod
    def get_pdp_engine(cls) -> Optional[PolicyDecisionEngine]:
        """Retrieve globally registered default PDP engine."""
        return cls._default_pdp_engine

    @classmethod
    def get_entity_resolver(cls) -> Optional[EntityAttributeResolverSPI]:
        """Retrieve globally registered default EntityAttributeResolverSPI."""
        return cls._default_entity_resolver

    @classmethod
    def reset(cls) -> None:
        """Reset registered defaults (used in test fixtures)."""
        cls._default_pdp_engine = None
        cls._default_entity_resolver = None
