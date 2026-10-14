"""
Open Policy Agent (OPA) PDP Adapter package.

Extends Policy Decision Point (PDP) with remote REST integration, circuit breaker,
and dynamic cache invalidation as specified in Spec 4.
"""

from security_pdp_opa.opa_adapter import RemotePDPAdapter, OPACacheInvalidationHandler, CircuitBreakerState

__all__ = [
    "RemotePDPAdapter",
    "OPACacheInvalidationHandler",
    "CircuitBreakerState",
]

