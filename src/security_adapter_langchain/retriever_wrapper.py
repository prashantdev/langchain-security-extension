"""
SecureRetriever wrapper performing pre-filtering AST generation, oversampling, fail-closed anonymous filtering, and post-retrieval pruning.

Applies AST prefiltering translation, adaptive oversampling, and post-retrieval document pruning
as specified in Spec 3.
"""

from typing import List, Dict, Any, Optional, Tuple
from security_core.identity import SecurityIdentity, IdentityBridge
from security_core.pdp import PolicyDecisionEngine, PolicyEvaluationRequest
from security_core.constants import (
    ACTION_CHUNK_RETRIEVE,
    DEFAULT_MAX_FETCH_CAP,
    DEFAULT_OVERSAMPLING_FACTOR,
    DEFAULT_MAX_SECONDARY_FETCHES,
    DEFAULT_SIMILARITY_CUTOFF,
    STORE_PROFILE_FULL_AST,
    STORE_PROFILE_CONSTRAINED,
    STORE_PROFILE_NO_FILTER,
    EVENT_RAG_UNAUTHORIZED_PRUNING,
    EVENT_RAG_RESULT_STARVATION,
    EVENT_POLICY_TAMPER_DETECTED,
    PEP_RAG_FILTER,
    SEVERITY_NOTICE,
    SEVERITY_WARNING,
    SEVERITY_CRITICAL_ALERT,
    SEC_TENANT_ID,
    SEC_CLASSIFICATION_LEVEL,
    SEC_CLEARANCE_FLOOR,
    SEC_ALLOWED_ROLES,
    SEC_REQUIRED_ROLES,
    SEC_DEPARTMENT_ID,
    SEC_ENVELOPE_HASH,
    SEC_QUARANTINED,
    ANONYMOUS_SUBJECT_ID,
    CLASSIFICATION_TO_RANK,
    PII_SCOPE_FULL_IN_FLIGHT,
    PII_STAGE_RETRIEVAL_DOCUMENT,
)
from security_core.audit import AuditEvent
from security_core.pii import get_pii_sanitizer, get_pii_scope, PiiContext


from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from langchain_core.callbacks.manager import CallbackManagerForRetrieverRun
from pydantic import ConfigDict

DEFAULT_TOP_K_CANDIDATES: int = 3


class SecureDocument(Document):
    """Document container representation for chunk metadata evaluation.

    Attributes:
        page_content (str): Text content of document chunk.
        metadata (Dict[str, Any]): Security envelope metadata dictionary.
    """

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
    score: Optional[float] = None

    def __init__(self, page_content: str, metadata: Optional[Dict[str, Any]] = None, **kwargs: Any):
        """Initialize SecureDocument.

        Args:
            page_content: Chunk page text content.
            metadata: Metadata envelope mapping.
            **kwargs: Additional keyword arguments.
        """
        super().__init__(page_content=page_content, metadata=dict(metadata or {}), **kwargs)

    @classmethod
    def create(cls, page_content: str, metadata: Dict[str, Any], **kwargs: Any):
        """Factory method to construct SecureDocument.

        Args:
            page_content: Chunk text string.
            metadata: Metadata mapping.
            **kwargs: Additional keyword arguments.

        Returns:
            SecureDocument: Constructed document instance.
        """
        return cls(page_content=page_content, metadata=metadata, **kwargs)


class PrefilterAST(dict):
    """Dictionary representing vector store prefilter AST while supporting direct key lookups."""

    def __getitem__(self, key: str) -> Any:
        """Lookup key directly or within nested $and clause filters."""
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        for clause in self.get("$and", []):
            if isinstance(clause, dict) and key in clause:
                return clause[key]
            elif isinstance(clause, dict) and key == "sec:clearance_level" and SEC_CLEARANCE_FLOOR in clause:
                return clause[SEC_CLEARANCE_FLOOR]
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        """Check key membership directly or in nested AST $and clauses."""
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            for clause in self.get("$and", []):
                if isinstance(clause, dict) and key in clause:
                    return True
                elif isinstance(clause, dict) and key == "sec:clearance_level" and SEC_CLEARANCE_FLOOR in clause:
                    return True
        return False


def _sanitize_chroma_filter(filter_dict: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sanitizes filter AST dictionary into Chroma-compatible where dictionary."""
    if not filter_dict or not isinstance(filter_dict, dict):
        return None

    clauses = filter_dict.get("$and")
    if isinstance(clauses, list):
        clean_clauses: List[Dict[str, Any]] = []
        for c in clauses:
            if isinstance(c, dict):
                has_unsupported = False
                for k, v in c.items():
                    if isinstance(v, dict) and "$exists" in v:
                        has_unsupported = True
                    elif k == "$or" and isinstance(v, list):
                        for sub in v:
                            if isinstance(sub, dict) and any(isinstance(sv, dict) and "$exists" in sv for sv in sub.values()):
                                has_unsupported = True
                if not has_unsupported:
                    clean_clauses.append(c)
        if len(clean_clauses) == 0:
            return None
        if len(clean_clauses) == 1:
            return clean_clauses[0]
        return {"$and": clean_clauses}

    for k, v in filter_dict.items():
        if isinstance(v, dict) and "$exists" in v:
            return None
    return dict(filter_dict)


class SecureRetriever(BaseRetriever):
    """Wraps document retriever components with dynamic pre-filtering, oversampling, and post-pruning PEP.

    Attributes:
        base_retriever (Any): Underlying vector retriever or search callable.
        pdp_engine (PolicyDecisionEngine): PDP decision engine instance.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _base_retriever: Any = None
    _pdp_engine: Any = None
    _oversampling_factor: float = DEFAULT_OVERSAMPLING_FACTOR
    _secret_key: Optional[str] = None
    _store_profile: str = STORE_PROFILE_FULL_AST
    _secondary_fetch_fn: Any = None
    _similarity_cutoff: float = DEFAULT_SIMILARITY_CUTOFF
    _active_config: Any = None

    def __init__(
        self,
        base_retriever: Any,
        pdp_engine: PolicyDecisionEngine,
        *args: Any,
        **kwargs: Any,
    ):
        """Initialize SecureRetriever.

        Args:
            base_retriever: Vector retriever or callable.
            pdp_engine: PDP decision engine instance.
            *args: Optional positional arguments (oversampling_factor, secret_key, store_profile, secondary_fetch_fn, similarity_cutoff).
            **kwargs: Optional keyword arguments.
        """
        super().__init__()
        oversampling_factor = kwargs.get("oversampling_factor", args[0] if len(args) > 0 else DEFAULT_OVERSAMPLING_FACTOR)
        secret_key = kwargs.get("secret_key", args[1] if len(args) > 1 else None)
        store_profile = kwargs.get("store_profile", args[2] if len(args) > 2 else STORE_PROFILE_FULL_AST)
        secondary_fetch_fn = kwargs.get("secondary_fetch_fn", args[3] if len(args) > 3 else None)
        similarity_cutoff = kwargs.get("similarity_cutoff", args[4] if len(args) > 4 else DEFAULT_SIMILARITY_CUTOFF)

        self._base_retriever = base_retriever
        self._pdp_engine = pdp_engine
        self._oversampling_factor = float(oversampling_factor)
        self._secret_key = secret_key
        self._store_profile = str(store_profile)
        self._secondary_fetch_fn = secondary_fetch_fn
        self._similarity_cutoff = float(similarity_cutoff)
        self._active_config = None

    @classmethod
    def wrap(
        cls,
        base_retriever: Any,
        pdp_engine: PolicyDecisionEngine,
        *args: Any,
        **kwargs: Any,
    ):
        """Factory method to construct a SecureRetriever.

        Args:
            base_retriever: Base vector store retriever object.
            pdp_engine: PDP decision engine.
            *args: Optional positional arguments.
            **kwargs: Optional keyword arguments.

        Returns:
            SecureRetriever: New wrapper instance.
        """
        return cls(base_retriever, pdp_engine, *args, **kwargs)

    @property
    def base_retriever(self) -> Any:
        """Get the underlying base retriever."""
        return self._base_retriever

    @property
    def pdp_engine(self) -> PolicyDecisionEngine:
        """Get the configured PolicyDecisionEngine instance."""
        return self._pdp_engine

    def build_full_ast(self, identity: Optional[SecurityIdentity]) -> PrefilterAST:
        """Constructs unconstrained full AST from SecurityIdentity.

        Args:
            identity: Caller security identity or None for anonymous.

        Returns:
            PrefilterAST: Full prefilter AST dictionary.
        """
        if identity is None or identity.is_anonymous or identity.subject_id is None or str(identity.subject_id).upper() == ANONYMOUS_SUBJECT_ID:
            return PrefilterAST({SEC_TENANT_ID: "__DENY_ALL_UNAUTHENTICATED__"})

        and_clauses: List[Dict[str, Any]] = [
            {SEC_TENANT_ID: identity.tenant_id},
            {SEC_CLEARANCE_FLOOR: {"$lte": identity.clearance_level}},
        ]

        if identity.roles:
            and_clauses.append({SEC_ALLOWED_ROLES: {"$in": list(identity.roles)}})

        if identity.department_id:
            and_clauses.append({
                "$or": [
                    {SEC_DEPARTMENT_ID: identity.department_id},
                    {SEC_DEPARTMENT_ID: {"$exists": False}},
                ]
            })

        return PrefilterAST({"$and": and_clauses})

    def split_predicates(
        self,
        full_ast: Dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Splits full AST into push-down filter and retained predicates based on store capability profile.

        Args:
            full_ast: Complete filter dictionary generated from SecurityIdentity.
            *args: Optional positional store_profile string.
            **kwargs: Optional keyword store_profile string.

        Returns:
            Tuple[Dict[str, Any], Dict[str, Any]]: (push_down_filter, retained_predicates)
        """
        store_profile = str(kwargs.get("store_profile", args[0] if len(args) > 0 else self._store_profile))

        if store_profile == STORE_PROFILE_NO_FILTER:
            return PrefilterAST({}), dict(full_ast)

        if store_profile == STORE_PROFILE_CONSTRAINED:
            clauses = full_ast.get("$and", [full_ast]) if isinstance(full_ast, dict) else []
            pushed_clauses: List[Dict[str, Any]] = []
            retained: Dict[str, Any] = {}

            for clause in clauses:
                if not isinstance(clause, dict):
                    continue
                for key, val in clause.items():
                    if key == SEC_TENANT_ID:
                        pushed_clauses.append({key: val})
                    elif key == SEC_DEPARTMENT_ID and not isinstance(val, dict):
                        pushed_clauses.append({key: val})
                    else:
                        retained[key] = val

            if len(pushed_clauses) == 1:
                push_down = pushed_clauses[0]
            elif len(pushed_clauses) > 1:
                push_down = {"$and": pushed_clauses}
            else:
                push_down = {}

            return PrefilterAST(push_down), retained

        return PrefilterAST(dict(full_ast)), {}

    def build_prefilter_ast(self, identity: Optional[SecurityIdentity], *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Translates caller identity envelope into dynamic VectorStore metadata filter AST dictionary according to store profile.

        Args:
            identity: Caller security identity or None for anonymous.
            *args: Optional positional config dict.
            **kwargs: Optional keyword config dict.

        Returns:
            Dict[str, Any]: Prefilter AST dictionary envelope.
        """
        config = kwargs.get("config", args[0] if len(args) > 0 else None)
        full_ast = self.build_full_ast(identity)
        push_down, retained = self.split_predicates(full_ast)

        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"]["sec:vector_ast_prefilter"] = dict(push_down)
            config["configurable"]["sec:retained_predicates"] = dict(retained)
            config["configurable"]["sec:store_profile"] = self._store_profile

        return PrefilterAST(push_down)

    def prune_documents(
        self,
        documents: List[SecureDocument],
        identity: Optional[SecurityIdentity],
        *args: Any,
        **kwargs: Any,
    ) -> List[SecureDocument]:
        """Post-retrieval pruning inspecting metadata on returned document chunks. Fail-closed if identity is None.

        Args:
            documents: Candidate list of SecureDocuments.
            identity: Caller identity or None.
            *args: Optional positional config dict.
            **kwargs: Optional keyword config dict.

        Returns:
            List[SecureDocument]: Filtered list of authorized SecureDocument objects.
        """
        config = kwargs.get("config", args[0] if len(args) > 0 else None)
        resolved_identity = IdentityBridge.resolve_identity(identity)
        pruned: List[SecureDocument] = []
        audit_manager = getattr(self._pdp_engine, "audit_manager", None)

        for doc in documents:
            metadata = doc.metadata

            # Optional HMAC Signature verification
            if self._secret_key and SEC_ENVELOPE_HASH in metadata:
                from security_adapter_langchain.ingestion import compute_envelope_hmac
                expected = compute_envelope_hmac(metadata, self._secret_key)
                if metadata[SEC_ENVELOPE_HASH] != expected:
                    if audit_manager:
                        audit_manager.record_event(AuditEvent.create(
                            subject_id=resolved_identity.subject_id,
                            tenant_id=resolved_identity.tenant_id,
                            action=ACTION_CHUNK_RETRIEVE,
                            resource=str(metadata.get("source", "document_chunk")),
                            decision="DENY",
                            diagnostic_reason="POLICY_TAMPER_DETECTED | HMAC_MISMATCH: Envelope HMAC signature mismatch",
                            severity=SEVERITY_CRITICAL_ALERT,
                            metadata={"doc_metadata": metadata},
                            enforcement_point=PEP_RAG_FILTER,
                            reason_code=EVENT_POLICY_TAMPER_DETECTED,
                        ))
                    continue  # Fail-closed tampering detection
                if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
                    config["configurable"]["sec:envelope_verified"] = True

            # Mandatory envelope verification: verify mandatory security envelope tags
            doc_tenant = metadata.get(SEC_TENANT_ID)
            has_tenant = bool(doc_tenant)
            has_classification = bool(
                metadata.get(SEC_CLASSIFICATION_LEVEL)
                or metadata.get(SEC_CLEARANCE_FLOOR) is not None
                or metadata.get("sec:clearance_level") is not None
            )
            if not (has_tenant and has_classification):
                if audit_manager:
                    audit_manager.record_event(AuditEvent.create(
                        subject_id=resolved_identity.subject_id,
                        tenant_id=resolved_identity.tenant_id,
                        action=ACTION_CHUNK_RETRIEVE,
                        resource=str(metadata.get("source", "document_chunk")),
                        decision="PRUNED",
                        diagnostic_reason="Missing mandatory security metadata: tenant_id or classification",
                        severity=SEVERITY_NOTICE,
                        metadata={"doc_metadata": metadata},
                        enforcement_point=PEP_RAG_FILTER,
                        reason_code=EVENT_RAG_UNAUTHORIZED_PRUNING,
                    ))
                continue

            doc_clearance = int(metadata.get(SEC_CLEARANCE_FLOOR, metadata.get("sec:clearance_level", CLASSIFICATION_TO_RANK.get(str(metadata.get(SEC_CLASSIFICATION_LEVEL, "")).upper(), 0))))
            doc_roles = metadata.get(SEC_ALLOWED_ROLES, metadata.get(SEC_REQUIRED_ROLES, []))
            if isinstance(doc_roles, str):
                doc_roles = [r.strip() for r in doc_roles.split(",") if r.strip()]
            doc_quarantined = bool(metadata.get(SEC_QUARANTINED, False))

            request = PolicyEvaluationRequest.create(
                subject=resolved_identity,
                action=ACTION_CHUNK_RETRIEVE,
                resource={
                    "target_id": str(metadata.get("source", "document_chunk")),
                    "tenant_id": doc_tenant,
                    "min_clearance": doc_clearance,
                    "required_roles": doc_roles,
                    SEC_QUARANTINED: doc_quarantined,
                },
                context={"config": config} if config else {},
            )

            decision = self._pdp_engine.evaluate(request)
            if decision.is_permitted:
                pruned.append(doc)
            else:
                if audit_manager:
                    audit_manager.record_event(AuditEvent.create(
                        subject_id=resolved_identity.subject_id,
                        tenant_id=resolved_identity.tenant_id,
                        action=ACTION_CHUNK_RETRIEVE,
                        resource=str(metadata.get("source", "document_chunk")),
                        decision="PRUNED",
                        diagnostic_reason=decision.diagnostic_reason,
                        severity=SEVERITY_NOTICE,
                        metadata={"doc_metadata": metadata},
                        enforcement_point=PEP_RAG_FILTER,
                        reason_code=EVENT_RAG_UNAUTHORIZED_PRUNING,
                    ))

        return pruned

    def prune_candidates(
        self,
        candidates: List[Any],
        identity: Optional[SecurityIdentity],
        *args: Any,
        **kwargs: Any,
    ) -> List[Any]:
        """Encapsulates candidate wrapping in SecureDocument, oversampling fetch sizing, AST evaluation, adaptive secondary paging, and returning original candidate objects.

        Args:
            candidates: Input raw candidates list.
            identity: Caller security identity.
            *args: Optional positional arguments (top_k, config).
            **kwargs: Optional keyword arguments (top_k, config).

        Returns:
            List[Any]: Filtered list of up to top_k authorized candidate objects.
        """
        top_k = int(kwargs.get("top_k", args[0] if len(args) > 0 else DEFAULT_TOP_K_CANDIDATES))
        config = kwargs.get("config", args[1] if len(args) > 1 else None)

        resolved_identity = IdentityBridge.resolve_identity(identity)
        self.build_prefilter_ast(resolved_identity, config=config)

        if not candidates:
            return []

        audit_manager = getattr(self._pdp_engine, "audit_manager", None)

        raw_k_fetch = int(top_k * self._oversampling_factor)
        k_fetch = min(max(raw_k_fetch, top_k), DEFAULT_MAX_FETCH_CAP)
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"]["sec:oversampled_fetch_k"] = k_fetch

        sec_docs: List[SecureDocument] = []
        doc_map: Dict[int, Any] = {}

        # Filter by similarity score cutoff if score is present on candidate
        filtered_candidates = []
        for cand in candidates:
            score = getattr(cand, "score", getattr(cand, "similarity_score", None))
            if score is not None and self._similarity_cutoff > 0.0 and float(score) < self._similarity_cutoff:
                continue
            filtered_candidates.append(cand)

        for cand in filtered_candidates:
            if isinstance(cand, SecureDocument):
                doc = cand
            elif hasattr(cand, "page_content") and hasattr(cand, "metadata"):
                doc = SecureDocument.create(page_content=cand.page_content, metadata=cand.metadata)
            elif hasattr(cand, "clearance_level") and hasattr(cand, "required_roles"):
                meta = {
                    SEC_TENANT_ID: getattr(cand, "tenant_id", resolved_identity.tenant_id),
                    SEC_CLEARANCE_FLOOR: getattr(cand, "clearance_level", 0),
                    SEC_ALLOWED_ROLES: getattr(cand, "required_roles", []),
                    "source": getattr(cand, "source", ""),
                }
                if hasattr(cand, "quarantined"):
                    meta[SEC_QUARANTINED] = getattr(cand, "quarantined")
                if hasattr(cand, "envelope_hash"):
                    meta[SEC_ENVELOPE_HASH] = getattr(cand, "envelope_hash")
                doc = SecureDocument.create(page_content=getattr(cand, "text", str(cand)), metadata=meta)
            else:
                meta = getattr(cand, "metadata", {})
                content = getattr(cand, "page_content", getattr(cand, "text", str(cand)))
                doc = SecureDocument.create(page_content=content, metadata=meta)

            sec_docs.append(doc)
            doc_map[id(doc)] = cand

        # First pass oversampled pruning
        first_batch = sec_docs[:k_fetch]
        pruned_sec_docs = self.prune_documents(first_batch, resolved_identity, config=config)

        # Adaptive secondary paging fallback if post-pruning count < top_k
        secondary_attempts = 0
        current_offset = k_fetch
        while len(pruned_sec_docs) < top_k and secondary_attempts < DEFAULT_MAX_SECONDARY_FETCHES:
            if self._secondary_fetch_fn:
                more_cands = self._secondary_fetch_fn(current_offset, k_fetch)
                if not more_cands:
                    break
                more_sec_docs = []
                for cand in more_cands:
                    score = getattr(cand, "score", getattr(cand, "similarity_score", None))
                    if score is not None and self._similarity_cutoff > 0.0 and float(score) < self._similarity_cutoff:
                        continue
                    if hasattr(cand, "page_content") and hasattr(cand, "metadata"):
                        doc = SecureDocument.create(page_content=cand.page_content, metadata=cand.metadata)
                    else:
                        doc = SecureDocument.create(page_content=str(cand), metadata=getattr(cand, "metadata", {}))
                    more_sec_docs.append(doc)
                    doc_map[id(doc)] = cand
                sec_pruned = self.prune_documents(more_sec_docs, resolved_identity, config=config)
                pruned_sec_docs.extend(sec_pruned)
            elif current_offset < len(sec_docs):
                next_batch = sec_docs[current_offset:current_offset + k_fetch]
                if not next_batch:
                    break
                sec_pruned = self.prune_documents(next_batch, resolved_identity, config=config)
                pruned_sec_docs.extend(sec_pruned)
            else:
                break
            current_offset += k_fetch
            secondary_attempts += 1

        permitted_candidates = [doc_map[id(doc)] for doc in pruned_sec_docs if id(doc) in doc_map]

        if len(permitted_candidates) < top_k and audit_manager:
            audit_manager.record_event(AuditEvent.create(
                subject_id=resolved_identity.subject_id,
                tenant_id=resolved_identity.tenant_id,
                action=ACTION_CHUNK_RETRIEVE,
                resource="vector_retriever",
                decision="STARVATION",
                diagnostic_reason=f"Post-pruning candidate count ({len(permitted_candidates)}) < target top_k ({top_k})",
                severity=SEVERITY_WARNING,
                metadata={"requested_k": top_k, "returned_count": len(permitted_candidates)},
                enforcement_point=PEP_RAG_FILTER,
                reason_code=EVENT_RAG_RESULT_STARVATION,
            ))

        final_candidates = permitted_candidates[:top_k]
        if get_pii_scope() == PII_SCOPE_FULL_IN_FLIGHT:
            sanitizer = get_pii_sanitizer()
            ctx = PiiContext.create(
                PII_STAGE_RETRIEVAL_DOCUMENT,
                resolved_identity.tenant_id,
                resolved_identity.subject_id,
                "vector_retriever",
                {"requested_k": top_k, "returned_count": len(final_candidates)},
            )
            for doc in final_candidates:
                if hasattr(doc, "page_content") and isinstance(doc.page_content, str):
                    doc.page_content = sanitizer.sanitize_text(doc.page_content, ctx)

        return final_candidates

    def invoke(
        self,
        input: str,
        config: Optional[Any] = None,
        **kwargs: Any,
    ) -> List[SecureDocument]:
        """Invoke the retriever synchronously capturing RunnableConfig for identity extraction and AST filtering."""
        self._active_config = config
        try:
            return super().invoke(input, config=config, **kwargs)
        finally:
            self._active_config = None

    def _get_relevant_documents(
        self,
        query: str,
        *,
        run_manager: Optional[CallbackManagerForRetrieverRun] = None,
        **kwargs: Any,
    ) -> List[SecureDocument]:
        """Retrieve relevant documents applying security AST filtering, oversampling, and post-pruning.

        1. Extract SecurityIdentity from run_manager.config / RunnableConfig.
        2. Generate AST filter dictionary according to store capability profile.
        3. Delegate fetch to self.base_retriever.get_relevant_documents(...) with search_kwargs={"filter": ast_filter}.
        4. Execute post-retrieval pruning and adaptive secondary paging.
        """
        run_config = getattr(run_manager, "config", None) or self._active_config
        identity = IdentityBridge.extract_from_config(run_config)
        resolved_identity = IdentityBridge.resolve_identity(identity)

        ast_filter = self.build_prefilter_ast(resolved_identity, config=run_config)

        top_k = int(kwargs.get("top_k", DEFAULT_TOP_K_CANDIDATES))
        raw_k_fetch = int(top_k * self._oversampling_factor)
        k_fetch = min(max(raw_k_fetch, top_k), DEFAULT_MAX_FETCH_CAP)
        if isinstance(run_config, dict) and isinstance(run_config.get("configurable"), dict):
            run_config["configurable"]["sec:oversampled_fetch_k"] = k_fetch

        candidates: List[Any] = []
        if hasattr(self._base_retriever, "get_relevant_documents"):
            candidates = self._base_retriever.get_relevant_documents(
                query,
                search_kwargs={"filter": ast_filter, "k": k_fetch},
            )
        elif hasattr(self._base_retriever, "invoke"):
            candidates = self._base_retriever.invoke(
                query,
                search_kwargs={"filter": ast_filter, "k": k_fetch},
            )
        elif hasattr(self._base_retriever, "query"):
            where_arg = _sanitize_chroma_filter(dict(ast_filter)) if ast_filter else None
            query_kwargs: Dict[str, Any] = {"n_results": k_fetch}
            if where_arg:
                query_kwargs["where"] = where_arg
            raw_res = self._base_retriever.query(query_texts=[query], **query_kwargs)
            docs = raw_res.get("documents", [[]])[0]
            metas = raw_res.get("metadatas", [[]])[0]
            ids = raw_res.get("ids", [[]])[0]
            for doc_id, doc_text, meta in zip(ids, docs, metas):
                clean_meta = dict(meta or {})
                roles_val = clean_meta.get(SEC_ALLOWED_ROLES)
                if isinstance(roles_val, str) and roles_val:
                    clean_meta[SEC_ALLOWED_ROLES] = [r.strip() for r in roles_val.split(",") if r.strip()]
                req_roles = clean_meta.get(SEC_REQUIRED_ROLES)
                if isinstance(req_roles, str) and req_roles:
                    clean_meta[SEC_REQUIRED_ROLES] = [r.strip() for r in req_roles.split(",") if r.strip()]
                candidates.append(SecureDocument.create(page_content=doc_text, metadata=clean_meta))
        elif callable(self._base_retriever):
            candidates = self._base_retriever(query, ast_filter, k_fetch)

        return self.prune_candidates(candidates, resolved_identity, top_k, config=run_config)

    def get_relevant_documents(
        self,
        query: str,
        identity: Optional[SecurityIdentity] = None,
        *args: Any,
        **kwargs: Any,
    ) -> List[SecureDocument]:
        """Executes retrieval with pre-filtering, oversampling, and post-pruning.

        Args:
            query: Vector store text query string.
            identity: Caller security identity or None.
            *args: Optional positional config dict.
            **kwargs: Optional keyword config dict.

        Returns:
            List[SecureDocument]: List of authorized SecureDocuments.
        """
        config = kwargs.get("config", args[0] if len(args) > 0 else None)
        filter_ast = self.build_prefilter_ast(identity, config=config)

        if hasattr(self._base_retriever, "get_relevant_documents"):
            raw_docs = self._base_retriever.get_relevant_documents(query, search_kwargs={"filter": filter_ast})
        elif callable(self._base_retriever):
            raw_docs = self._base_retriever(query, filter_ast)
        else:
            raw_docs = []

        converted_docs: List[SecureDocument] = []
        for raw in raw_docs:
            if isinstance(raw, SecureDocument):
                converted_docs.append(raw)
            elif hasattr(raw, "page_content") and hasattr(raw, "metadata"):
                converted_docs.append(SecureDocument.create(page_content=raw.page_content, metadata=raw.metadata))
            elif isinstance(raw, dict):
                converted_docs.append(SecureDocument.create(page_content=raw.get("page_content", ""), metadata=raw.get("metadata", {})))

        return self.prune_documents(converted_docs, identity, config=config)

    def search(
        self,
        query: str,
        identity: Optional[SecurityIdentity] = None,
        *args: Any,
        **kwargs: Any,
    ) -> List[Any]:
        """Executes vector similarity search with AST push-down, oversampling, and post-pruning.

        Args:
            query: Vector store text query string.
            identity: Caller security identity or None.
            *args: Optional positional arguments (top_k, config).
            **kwargs: Optional keyword arguments (top_k, config).

        Returns:
            List[Any]: Filtered list of authorized candidates.
        """
        top_k: int = int(args[0]) if len(args) > 0 else int(kwargs.get("top_k", DEFAULT_TOP_K_CANDIDATES))
        config: Optional[Dict[str, Any]] = args[1] if len(args) > 1 else kwargs.get("config")

        resolved_identity = IdentityBridge.resolve_identity(identity)
        push_down_filter = self.build_prefilter_ast(resolved_identity, config=config)

        raw_k_fetch = int(top_k * self._oversampling_factor)
        k_fetch = min(max(raw_k_fetch, top_k), DEFAULT_MAX_FETCH_CAP)
        if isinstance(config, dict) and isinstance(config.get("configurable"), dict):
            config["configurable"]["sec:oversampled_fetch_k"] = k_fetch

        candidates: List[Any] = []
        if hasattr(self._base_retriever, "query"):
            where_arg = _sanitize_chroma_filter(dict(push_down_filter)) if push_down_filter else None
            query_kwargs: Dict[str, Any] = {"n_results": k_fetch}
            if where_arg:
                query_kwargs["where"] = where_arg
            raw_res = self._base_retriever.query(query_texts=[query], **query_kwargs)
            docs = raw_res.get("documents", [[]])[0]
            metas = raw_res.get("metadatas", [[]])[0]
            ids = raw_res.get("ids", [[]])[0]
            for doc_id, doc_text, meta in zip(ids, docs, metas):
                clean_meta = dict(meta or {})
                roles_val = clean_meta.get(SEC_ALLOWED_ROLES)
                if isinstance(roles_val, str) and roles_val:
                    clean_meta[SEC_ALLOWED_ROLES] = [r.strip() for r in roles_val.split(",") if r.strip()]
                req_roles = clean_meta.get(SEC_REQUIRED_ROLES)
                if isinstance(req_roles, str) and req_roles:
                    clean_meta[SEC_REQUIRED_ROLES] = [r.strip() for r in req_roles.split(",") if r.strip()]
                candidates.append(SecureDocument.create(page_content=doc_text, metadata=clean_meta))
        elif hasattr(self._base_retriever, "get_relevant_documents"):
            candidates = self._base_retriever.get_relevant_documents(query, search_kwargs={"filter": push_down_filter, "k": k_fetch})
        elif callable(self._base_retriever):
            candidates = self._base_retriever(query, push_down_filter, k_fetch)

        return self.prune_candidates(candidates, resolved_identity, top_k, config=config)



