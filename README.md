# LangChain & LangGraph Security Extension

A language-native Python enterprise RBAC & ABAC security framework for **LangChain** and **LangGraph** AI agent applications.

## Overview

`langchain-security-extension` provides zero-trust Policy Enforcement Points (PEPs) and an embedded Policy Decision Point (PDP) to govern:
- **Agent Execution Boundaries:** Guard agent invocations based on caller identity, roles, and clearance levels.
- **Tool Execution Boundaries:** Intercept tool calls prior to execution with CEL-like parameter expression checks, hard aborts, or model feedback refusals.
- **Retrieval Boundaries (RAG):** Contextual pre-filtering and post-retrieval clearance pruning for document chunks.
- **LangGraph State Security:** Thread-agnostic context propagation across state transitions and checkpoint reloads.

## Installation

```bash
pip install langchain-security-extension
```

To include optional LangChain and LangGraph dependencies:
```bash
pip install "langchain-security-extension[langchain]"
```

## Quick Start

```python
from security_core import SecurityIdentity, EmbeddedPolicyEngine, PolicyEvaluationRequest
from security_adapter_langchain import SecureCallbackHandler, secured_tool

# 1. Initialize PDP Engine & Security Identity
pdp = EmbeddedPolicyEngine.create()
identity = SecurityIdentity.create(
    subject_id="user_123",
    tenant_id="CORP_MAIN",
    roles=["DEVOPS_TIER2"],
    clearance_level=2,
    department_id="DEVOPS"
)

# 2. Attach Callback Handler to LangChain Runnable
handler = SecureCallbackHandler.create(
    pdp_engine=pdp,
    security_identity=identity
)

# 3. Secure a Tool Callable
@secured_tool(
    required_roles=["ADMIN"],
    min_clearance=3,
    is_mutative=True,
    pdp_engine=pdp
)
def restart_server(server_name: str) -> str:
    return f"Server {server_name} restarted successfully."
```

## License

Apache License 2.0
