# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-24

### Added

#### Core Architecture & Security Context (`security_core`)
- **`SecurityIdentity`**: Core caller representation encapsulating `subject_id`, `tenant_id`, `roles`, `clearance_level`, `department_id`, and arbitrary contextual metadata attributes.
- **In-Band Context Propagation**: Native serialization of security identity into LangChain `RunnableConfig` (`configurable["security_identity"]`), preventing thread-local leakage across async tasks and distributed agent steps.
- **Embedded Policy Decision Point (`EmbeddedPolicyEngine`)**: In-memory policy engine enforcing tenant boundaries, role hierarchies, and numeric clearance levels with sub-millisecond evaluation latency.
- **Two-Tier Decision Cache (`TwoTierDecisionCache`)**: L1 LRU memory cache paired with an L2 TTL cache to optimize PDP evaluation throughput.
- **CEL Rule Evaluator (`CELEvaluator`)**: Lightweight, AST-based expression evaluator for deterministic parameter constraint checks without external dependencies.
- **Zero-Dependency Core**: `security_core` runs purely on standard library and `typing-extensions`.

#### Safety & Content Protection
- **PII Sanitizer (`PIISanitizer`)**: Deterministic detection, masking, and redaction for emails, phone numbers, SSNs, credit cards, and API secrets.
- **Prompt Injection Scanner (`PromptInjectionScanner`)**: Pre-execution heuristic scanner detecting instruction overrides, system role usurpation, and delimiter evasion patterns.
- **Document Ingestion Pipeline (`SecureIngestionPipeline`)**: Pre-indexing pipeline enforcing classification tier validation, PII redaction, and multi-tenant metadata tagging for RAG vector stores.

#### LangChain & LangGraph Policy Enforcement Points (`security_adapter_langchain`)
- **Tool Guardrail Decorator (`@secured_tool`)**: Pre-execution interceptor enforcing role checks, minimum clearance levels, mutative action flagging, parameter masking, and CEL parameter evaluation before tool execution.
- **Agent Boundary Gate (`SecureRunnable`)**: LCEL wrapper safeguarding runnable execution against unauthorized caller identity or tenant mismatch.
- **Secure Retrieval Wrapper (`SecureRetriever`)**: RAG protection mechanism performing vector store pre-filtering and post-retrieval clearance pruning.
- **LangChain Callback Handler (`SecureCallbackHandler`)**: Native event-driven interceptor monitoring tool and model invocations.
- **LangGraph Integration (`inject_security_state`)**: Automatic propagation of security identity across LangGraph state graph nodes and checkpoint reloads.

#### Enterprise Integrations & Remote PDP (`security_pdp_opa`)
- **Open Policy Agent Remote Adapter (`RemotePDPAdapter`)**: Enterprise PDP SPI adapter connecting to OPA REST APIs.
- **Fail-Closed Resilience**: Circuit breaker pattern with configurable failure thresholds, retry recovery windows, and fail-closed denial behavior.

#### Observability & Compliance
- **Audit Engine (`AuditManager`)**: RFC 5424-compliant structured security audit event emission.
- **Async Batching Pipeline (`AsyncAuditPipeline`)**: High-throughput, non-blocking asynchronous audit emission with bounded queues and periodic flushing.
- **Parameter Masking**: Automatic masking of sensitive and credential arguments in audit logs.

#### Packaging & Typing
- **PEP 561 Compliance**: Shipped with `py.typed` markers in `security_core`, `security_adapter_langchain`, and `security_pdp_opa`.
- **Modern Packaging Standards**: Standard SPDX `Apache-2.0` license metadata, clean `pyproject.toml` configuration, and project URL links for PyPI.
