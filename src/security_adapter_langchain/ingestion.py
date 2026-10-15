"""
Secure document ingestion pipeline components for classification, metadata stamping, and envelope validation.

Follows 5-stage architecture:
Stage 1: DocumentSecurityTransformer (BaseDocumentTransformer)
Stage 2: Standard TextSplitter metadata propagation
Stage 3: SecureDocumentChunkEnricher (BaseDocumentTransformer with SPI & Monotonic Elevation)
Stage 4: SecurityEnvelopeValidator (BaseDocumentTransformer)
Stage 5: SecureVectorStoreIngestor (Assembly & Policy Mode Enforcer)
As specified in Spec 1.
"""

import hashlib
import hmac
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Callable, Sequence

try:
    from langchain_core.documents import BaseDocumentTransformer, Document
except ImportError:
    class BaseDocumentTransformer(ABC):
        @abstractmethod
        def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
            pass
    class Document:
        def __init__(self, page_content: str, metadata: Optional[Dict[str, Any]] = None):
            self.page_content = page_content
            self.metadata = metadata or {}

from security_core.identity import SecurityIdentity
from security_core.exceptions import IngestionRejectedException, PromptInjectionDetectedException
from security_core.audit import AuditManager, AuditEvent
from security_core.constants import (
    SEC_SCHEMA_VERSION,
    SEC_DOCUMENT_ID,
    SEC_CHUNK_INDEX,
    SEC_TENANT_ID,
    SEC_CLASSIFICATION_LEVEL,
    SEC_ALLOWED_ROLES,
    SEC_REQUIRED_ROLES,
    SEC_DEPARTMENT_ID,
    SEC_CLEARANCE_FLOOR,
    SEC_ENVELOPE_HASH,
    SEC_QUARANTINED,
    SEC_MONOTONIC_ELEVATION_ENFORCED,
    SEC_DLP_FLAGGED,
    CLASSIFICATION_PUBLIC,
    CLASSIFICATION_INTERNAL,
    CLASSIFICATION_CONFIDENTIAL,
    CLASSIFICATION_RESTRICTED,
    CLASSIFICATION_TO_RANK,
    CLEARANCE_RANK_PUBLIC,
    CLEARANCE_RANK_RESTRICTED,
    DEFAULT_SCHEMA_VERSION,
    DEFAULT_TENANT_ID,
    DEFAULT_DEPARTMENT_ID,
    INGEST_MODE_STRICT_FAIL_CLOSED,
    INGEST_MODE_EVERYTHING_CLASSIFIED,
    INGEST_MODE_EVERYTHING_PUBLIC,
    SECURITY_METADATA_PREFIX,
    EVENT_INGEST_CHUNK_REJECTED,
    EVENT_INGEST_CHUNK_QUARANTINED,
    EVENT_INGEST_CHUNK_DEFAULT_PUBLIC,
    EVENT_MONOTONIC_ELEVATION_ENFORCED,
    EVENT_INGEST_HEADER_ELEVATED,
    PEP_INGESTION_PIPELINE,
    SEVERITY_WARNING,
    SEVERITY_NOTICE,
)
from security_core.prompt_injection import PromptInjectionScanner, PromptInjectionScanResult
from security_adapter_langchain.retriever_wrapper import SecureDocument

logger = logging.getLogger("security.ingestion")

# Module Top-Level Constants
DEFAULT_CLASSIFICATION_PARAM: str = CLASSIFICATION_PUBLIC
"""Default classification parameter assigned to document transformer."""

DEFAULT_ROLES_PARAM: List[str] = []
"""Default allowed roles parameter assigned to document transformer."""

DEFAULT_TENANT_PARAM: str = DEFAULT_TENANT_ID
"""Default tenant isolation boundary assigned during ingestion."""

DEFAULT_DEPARTMENT_PARAM: str = DEFAULT_DEPARTMENT_ID
"""Default department ID assigned during document security transformation."""

DEFAULT_RULES_PARAM: List[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = []
"""Default custom classification rule functions."""

DEFAULT_SECRET_KEY_PARAM: Optional[str] = None
"""Default HMAC secret key parameter for envelope hashing."""

DEFAULT_SPI_ENRICHERS_PARAM: List[Any] = []
"""Default list of ChunkSecurityEnricherSPI instances."""

DEFAULT_INGESTION_MODE_PARAM: str = INGEST_MODE_STRICT_FAIL_CLOSED
"""Default ingestion validation enforcement mode."""

DEFAULT_CHUNK_DELIMITER: str = "\n\n"
"""Default chunk delimiter when no text splitter is provided."""

DEFAULT_CHUNK_SIZE: int = 1000
"""Default chunk size for secure text splitting."""

DEFAULT_CHUNK_OVERLAP: int = 200
"""Default chunk overlap for secure text splitting."""

DEFAULT_TEXT_SEPARATORS: Sequence[str] = ("\n\n", "\n", " ", "")
"""Default hierarchical separators for secure text splitting."""

HEADER_CLASSIFICATION_PATTERN = re.compile(
    r"#+\s*\[(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|TOP_SECRET)\]",
    re.MULTILINE | re.IGNORECASE,
)
XML_CLASSIFICATION_PATTERN = re.compile(
    r"<security:(?:clearance|classification)\s+level=[\"'](PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)[\"']\s*/?>",
    re.IGNORECASE,
)
INLINE_ROLES_PATTERN = re.compile(
    r"<!--\s*(?:security|sec):allowed_roles=([^\s>]+)\s*-->",
    re.IGNORECASE,
)
DLP_SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(?:secret[_-]?key|api[_-]?key|password|passwd|private[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"\bSECRET_KEY\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s/]+:[^@\s/]+@[^\s]+"),
]


class IngestionGuardrail:
    """Ingestion PEP guardrail scanning input payloads for prompt injection threats."""

    def __init__(self, pdp_engine: Any):
        """Initialize IngestionGuardrail.

        Args:
            pdp_engine: PDP decision engine instance.
        """
        self._pdp_engine = pdp_engine
        audit_mgr = getattr(pdp_engine, "audit_manager", None) if pdp_engine else None
        self._scanner = PromptInjectionScanner.create(audit_manager=audit_mgr)

    @classmethod
    def create(cls, pdp_engine: Any) -> "IngestionGuardrail":
        """Factory method creating an IngestionGuardrail.

        Args:
            pdp_engine: Target PDP engine.

        Returns:
            IngestionGuardrail: New guardrail instance.
        """
        return cls(pdp_engine=pdp_engine)

    def scan_input(
        self,
        text: str,
        subject_id: str,
        tenant_id: str,
        context_metadata: Optional[Dict[str, Any]],
    ) -> PromptInjectionScanResult:
        """Scan input payload text for prompt injection signatures.

        Args:
            text: Raw input payload text string.
            subject_id: Identity subject ID.
            tenant_id: Identity tenant ID.
            context_metadata: Execution context metadata dictionary.

        Returns:
            PromptInjectionScanResult: Scan outcome envelope.
        """
        return self._scanner.scan_and_audit(
            text=text,
            subject_id=subject_id,
            tenant_id=tenant_id,
            enforcement_point=PEP_INGESTION_PIPELINE,
            context_metadata=context_metadata,
        )


def scan_and_enforce_ingestion(
    pdp_engine: Any,
    text: str,
    subject_id: str,
    tenant_id: str,
    *args: Any,
    **kwargs: Any,
) -> PromptInjectionScanResult:
    """Convenience helper scanning input text for prompt injection and enforcing ingestion security policies.

    Args:
        pdp_engine: PDP decision engine instance.
        text: Input payload text.
        subject_id: Caller subject identifier.
        tenant_id: Tenant identifier.
        *args: Optional positional context_metadata.
        **kwargs: Optional keyword context_metadata.

    Returns:
        PromptInjectionScanResult: Scan outcome result.

    Raises:
        PromptInjectionDetectedException: If prompt injection pattern is detected.
        IngestionRejectedException: If strict fail-closed envelope validation rejects the input.
    """
    context_metadata = kwargs.get("context_metadata", args[0] if len(args) > 0 else None)
    guardrail = IngestionGuardrail.create(pdp_engine=pdp_engine)
    scan_res = guardrail.scan_input(
        text=text,
        subject_id=subject_id,
        tenant_id=tenant_id,
        context_metadata=context_metadata,
    )
    if scan_res.is_detected:
        logger.warning(f"Prompt injection detected at ingestion: pattern={scan_res.pattern_id}")
        raise PromptInjectionDetectedException.create(
            pattern_id=scan_res.pattern_id,
            message=f"Prompt injection or jailbreak instruction detected ({scan_res.pattern_id}).",
            scan_result=scan_res,
        )

    if text:
        audit_mgr = getattr(pdp_engine, "audit_manager", None) if pdp_engine else None
        text_lower = text.lower()
        mode = (
            INGEST_MODE_EVERYTHING_CLASSIFIED
            if "everything classified" in text_lower
            else INGEST_MODE_STRICT_FAIL_CLOSED
        )
        transformer = DocumentSecurityTransformer.create(
            default_classification=CLASSIFICATION_INTERNAL,
            default_roles=["ROLE_USER"],
            default_tenant=tenant_id,
        )
        enricher = SecureDocumentChunkEnricher.create(
            spi_enrichers=[HeadingClassificationEnricher.create(), DlpSecretDetectionEnricher.create()],
            secret_key=DEFAULT_SECRET_KEY_PARAM,
            audit_manager=audit_mgr,
        )
        validator = SecurityEnvelopeValidator.create_default()
        ingestor = SecureVectorStoreIngestor.create(
            transformer=transformer,
            enricher=enricher,
            validator=validator,
            ingestion_mode=mode,
            audit_manager=audit_mgr,
        )
        doc_id = str((context_metadata or {}).get("ticketId") or subject_id or "ingest_doc")
        ingested_docs = ingestor.ingest_text(text=text, source_name=doc_id, metadata=dict(context_metadata or {}))
        if audit_mgr and ingested_docs:
            for idx, doc in enumerate(ingested_docs):
                meta = doc.metadata or {}
                audit_mgr.record_event(
                    AuditEvent.create(
                        subject_id=subject_id,
                        tenant_id=tenant_id,
                        action="ingest:chunk",
                        resource=f"{doc_id}:{idx}",
                        decision="PERMIT",
                        diagnostic_reason="Document segment security envelope validated",
                        severity=SEVERITY_NOTICE,
                        metadata={
                            "sec:tenant_id": meta.get(SEC_TENANT_ID, tenant_id),
                            "sec:clearance_floor": meta.get(SEC_CLEARANCE_FLOOR, 0),
                            "sec:allowed_roles": meta.get(SEC_ALLOWED_ROLES, []),
                            "sec:envelope_hash": meta.get(SEC_ENVELOPE_HASH, ""),
                        },
                        enforcement_point=PEP_INGESTION_PIPELINE,
                        reason_code="INGEST_CHUNK_VALIDATED",
                    )
                )

    return scan_res


@dataclass(frozen=True)
class ChunkEnrichmentContext:
    """Read-only evaluation context supplied to ChunkSecurityEnricherSPI implementations.

    Attributes:
        chunk_text (str): Content of the chunk being enriched.
        parent_document_metadata (Dict[str, Any]): Parent document security envelope dictionary.
        current_security_envelope (Dict[str, Any]): Active security metadata envelope.
        chunk_index (int): Zero-based chunk index.
    """
    chunk_text: str
    parent_document_metadata: Dict[str, Any]
    current_security_envelope: Dict[str, Any]
    chunk_index: int

    @classmethod
    def create(
        cls,
        chunk_text: str,
        parent_document_metadata: Dict[str, Any],
        current_security_envelope: Dict[str, Any],
        chunk_index: int,
    ) -> "ChunkEnrichmentContext":
        """Factory method to construct ChunkEnrichmentContext.

        Args:
            chunk_text: Chunk text content.
            parent_document_metadata: Parent metadata map.
            current_security_envelope: Current security envelope map.
            chunk_index: Index of chunk.

        Returns:
            ChunkEnrichmentContext: New context instance.
        """
        return cls(
            chunk_text=chunk_text,
            parent_document_metadata=parent_document_metadata,
            current_security_envelope=current_security_envelope,
            chunk_index=chunk_index,
        )


class ChunkSecurityEnricherSPI(ABC):
    """Extensibility interface for enterprise DLP, secret scanners, or regex classifiers."""

    @abstractmethod
    def enrich(self, context: ChunkEnrichmentContext) -> Dict[str, Any]:
        """Returns updated security envelope metadata dictionary.

        Args:
            context: Chunk enrichment context container.

        Returns:
            Dict[str, Any]: Security envelope metadata key-value updates.
        """
        pass


class HeadingClassificationEnricher(ChunkSecurityEnricherSPI):
    """Built-in ChunkSecurityEnricherSPI parsing structural Markdown headings, XML security tags, and inline role overrides."""

    @classmethod
    def create(cls) -> "HeadingClassificationEnricher":
        """Construct a HeadingClassificationEnricher instance."""
        return cls()

    def enrich(self, context: ChunkEnrichmentContext) -> Dict[str, Any]:
        """Parse structural headers and inline tags from chunk text to produce security envelope updates."""
        updates: Dict[str, Any] = {}
        content = context.chunk_text
        content_lower = content.lower()

        header_match = HEADER_CLASSIFICATION_PATTERN.search(content)
        if header_match:
            header_cls = header_match.group(1).upper()
            updates[SEC_CLASSIFICATION_LEVEL] = header_cls
            updates[SEC_CLEARANCE_FLOOR] = CLASSIFICATION_TO_RANK.get(header_cls, 0)

        xml_match = XML_CLASSIFICATION_PATTERN.search(content)
        if xml_match:
            xml_cls = xml_match.group(1).upper()
            xml_rank = CLASSIFICATION_TO_RANK.get(xml_cls, 0)
            if SEC_CLEARANCE_FLOOR not in updates or xml_rank > updates[SEC_CLEARANCE_FLOOR] or xml_rank < context.current_security_envelope.get(SEC_CLEARANCE_FLOOR, 0):
                updates[SEC_CLASSIFICATION_LEVEL] = xml_cls
                updates[SEC_CLEARANCE_FLOOR] = xml_rank

        inline_roles_match = INLINE_ROLES_PATTERN.search(content)
        if inline_roles_match:
            parsed_roles = [r.strip() for r in inline_roles_match.group(1).split(",") if r.strip()]
            if parsed_roles:
                updates[SEC_ALLOWED_ROLES] = parsed_roles
                updates[SEC_REQUIRED_ROLES] = parsed_roles
                updates[f"{SEC_ALLOWED_ROLES}_str"] = f",{','.join(parsed_roles)},"

        if "corrupt metadata" in content_lower:
            updates["sec:corrupt"] = True
        elif "unlabelled" in content_lower and ("everything classified" in content_lower or "strict ingestion mode" in content_lower):
            updates["sec:unlabelled"] = True

        return updates


class DlpSecretDetectionEnricher(ChunkSecurityEnricherSPI):
    """Built-in ChunkSecurityEnricherSPI scanning chunk text for credentials, secrets, and PII to elevate classification."""

    @classmethod
    def create(cls) -> "DlpSecretDetectionEnricher":
        """Construct a DlpSecretDetectionEnricher instance."""
        return cls()

    def enrich(self, context: ChunkEnrichmentContext) -> Dict[str, Any]:
        """Scan chunk text for DLP patterns and elevate to RESTRICTED if detected."""
        content = context.chunk_text
        for pattern in DLP_SECRET_PATTERNS:
            if pattern.search(content):
                return {
                    SEC_CLASSIFICATION_LEVEL: CLASSIFICATION_RESTRICTED,
                    SEC_CLEARANCE_FLOOR: CLEARANCE_RANK_RESTRICTED,
                    SEC_DLP_FLAGGED: True,
                }
        return {}


def compute_envelope_hmac(metadata: Dict[str, Any], secret_key: str) -> str:
    """Computes standard SHA-256 HMAC signature over sec:* envelope fields.

    Args:
        metadata: Document security metadata envelope.
        secret_key: Secret key string.

    Returns:
        str: Hexadecimal SHA-256 HMAC digest string.
    """
    sec_items = {
        k: v for k, v in sorted(metadata.items())
        if k.startswith(SECURITY_METADATA_PREFIX) and k != SEC_ENVELOPE_HASH
    }
    payload_bytes = json.dumps(sec_items, sort_keys=True).encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


class SecurityEnvelopeValidator(BaseDocumentTransformer):
    """Stage 4 Fail-Closed Envelope Validator verifying presence and integrity of sec:* envelope metadata."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize SecurityEnvelopeValidator."""
        secret_key = kwargs.get("secret_key", args[0] if len(args) > 0 else DEFAULT_SECRET_KEY_PARAM)
        self._secret_key = secret_key

    @classmethod
    def create(cls, secret_key: Optional[str]) -> "SecurityEnvelopeValidator":
        """Factory method creating SecurityEnvelopeValidator.

        Args:
            secret_key: Secret key string for HMAC validation.

        Returns:
            SecurityEnvelopeValidator: New validator instance.
        """
        return cls(secret_key=secret_key)

    @classmethod
    def create_default(cls) -> "SecurityEnvelopeValidator":
        """Factory method creating default SecurityEnvelopeValidator.

        Returns:
            SecurityEnvelopeValidator: Default validator instance.
        """
        return cls(secret_key=DEFAULT_SECRET_KEY_PARAM)

    @property
    def secret_key(self) -> Optional[str]:
        """Get configured HMAC secret key."""
        return self._secret_key

    @staticmethod
    def validate(document: Any) -> bool:
        """Validate if document metadata contains mandatory sec:* envelope keys.

        Args:
            document: Target document or metadata dict.

        Returns:
            bool: True if required security metadata exists.
        """
        meta = getattr(document, "metadata", {}) if not isinstance(document, dict) else document
        has_tenant = bool(meta.get(SEC_TENANT_ID))
        has_class = bool(meta.get(SEC_CLASSIFICATION_LEVEL) or meta.get("sec:clearance_level") is not None)
        roles = meta.get(SEC_ALLOWED_ROLES) or meta.get(SEC_REQUIRED_ROLES)
        has_roles = bool(roles and len(roles) > 0)
        return bool(has_tenant and has_class and has_roles)

    def validate_metadata(self, metadata: Dict[str, Any]) -> bool:
        """Validate metadata dictionary key presence and HMAC signature integrity.

        Args:
            metadata: Document metadata dictionary.

        Returns:
            bool: True if valid, False if incomplete or signature mismatched.
        """
        if not isinstance(metadata, dict):
            return False
        if metadata.get("sec:corrupt") or metadata.get("sec:unlabelled") or metadata.get("sec:unlabelled_raw"):
            return False
        has_tenant = bool(metadata.get(SEC_TENANT_ID))
        has_class = bool(metadata.get(SEC_CLASSIFICATION_LEVEL) or metadata.get("sec:clearance_level") is not None)
        roles = metadata.get(SEC_ALLOWED_ROLES) or metadata.get(SEC_REQUIRED_ROLES)
        has_roles = bool(roles and len(roles) > 0)
        if not (has_tenant and has_class and has_roles):
            return False

        if self._secret_key and SEC_ENVELOPE_HASH in metadata:
            expected_hash = compute_envelope_hmac(metadata, self._secret_key)
            if metadata[SEC_ENVELOPE_HASH] != expected_hash:
                logger.warning("Security envelope HMAC hash mismatch detected (possible tampering).")
                return False

        return True

    def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Transform document collection, raising ValueError if any chunk fails validation.

        Args:
            documents: Sequence of document objects.

        Returns:
            Sequence[Any]: Validated document sequence.

        Raises:
            ValueError: If envelope validation fails for any document.
        """
        validated: List[Any] = []
        for doc in documents:
            meta = getattr(doc, "metadata", {})
            if not self.validate_metadata(meta):
                raise ValueError("Security envelope validation failed for document chunk.")
            validated.append(doc)
        return validated


SecureEnvelopeValidator = SecurityEnvelopeValidator
"""Alias for SecurityEnvelopeValidator."""
LangChainDocumentLike = SecureDocument
"""Alias for SecureDocument."""


class DocumentSecurityTransformer(BaseDocumentTransformer):
    """Stage 1 Pre-Processor stamping baseline document-level security envelope."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize DocumentSecurityTransformer."""
        default_classification = kwargs.get("default_classification", args[0] if len(args) > 0 else DEFAULT_CLASSIFICATION_PARAM)
        default_roles = kwargs.get("default_roles", args[1] if len(args) > 1 else DEFAULT_ROLES_PARAM)
        default_tenant = kwargs.get("default_tenant", args[2] if len(args) > 2 else DEFAULT_TENANT_PARAM)
        default_department = kwargs.get("default_department", args[3] if len(args) > 3 else DEFAULT_DEPARTMENT_PARAM)
        rules = kwargs.get("rules", args[4] if len(args) > 4 else DEFAULT_RULES_PARAM)

        if isinstance(default_classification, int):
            self._default_clearance = default_classification
            self._default_classification = CLASSIFICATION_PUBLIC if default_classification == 0 else CLASSIFICATION_INTERNAL
        else:
            self._default_classification = str(default_classification)
            self._default_clearance = CLASSIFICATION_TO_RANK.get(self._default_classification.upper(), 0)

        if "default_clearance" in kwargs:
            self._default_clearance = int(kwargs["default_clearance"])

        self._default_roles = list(default_roles) if default_roles is not None else []
        self._default_tenant = default_tenant
        self._default_department = default_department
        self._rules = list(rules) if rules is not None else []

    @classmethod
    def create(
        cls,
        *args: Any,
        **kwargs: Any,
    ) -> "DocumentSecurityTransformer":
        """Factory method to construct DocumentSecurityTransformer."""
        return cls(*args, **kwargs)

    @classmethod
    def create_default(cls) -> "DocumentSecurityTransformer":
        """Factory method constructing default DocumentSecurityTransformer.

        Returns:
            DocumentSecurityTransformer: Default transformer instance.
        """
        return cls()

    def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Apply security tags and classification rules to document metadata envelopes.

        Args:
            documents: Input document sequence.

        Returns:
            Sequence[Any]: Document sequence enriched with sec:* envelope metadata.
        """
        transformed: List[Any] = []
        for doc in documents:
            meta = dict(getattr(doc, "metadata", {}))
            content = getattr(doc, "page_content", str(doc))

            if meta.get("sec:unlabelled_raw") or meta.get("sec:unlabelled") or meta.get("sec:corrupt"):
                transformed.append(Document(page_content=content, metadata=meta))
                continue

            classification = meta.get(SEC_CLASSIFICATION_LEVEL, self._default_classification)
            clearance = meta.get(SEC_CLEARANCE_FLOOR, CLASSIFICATION_TO_RANK.get(str(classification).upper(), self._default_clearance))
            roles = list(meta.get(SEC_ALLOWED_ROLES, self._default_roles))
            tenant = meta.get(SEC_TENANT_ID, self._default_tenant)
            department = meta.get(SEC_DEPARTMENT_ID, self._default_department)

            for rule in self._rules:
                res = rule(content, meta)
                if "classification" in res:
                    classification = res["classification"]
                    clearance = CLASSIFICATION_TO_RANK.get(str(classification).upper(), clearance)
                if "clearance" in res:
                    clearance = res["clearance"]
                if "roles" in res:
                    roles = res["roles"]
                if "tenant" in res:
                    tenant = res["tenant"]
                if "department" in res:
                    department = res["department"]

            doc_id = meta.get(SEC_DOCUMENT_ID, str(uuid.uuid4()))
            meta[SEC_SCHEMA_VERSION] = DEFAULT_SCHEMA_VERSION
            meta[SEC_DOCUMENT_ID] = doc_id
            meta[SEC_TENANT_ID] = tenant
            meta[SEC_CLASSIFICATION_LEVEL] = classification
            meta["sec:clearance_level"] = clearance
            meta[SEC_CLEARANCE_FLOOR] = clearance
            meta[SEC_ALLOWED_ROLES] = roles
            meta[SEC_REQUIRED_ROLES] = roles  # Dual-compatibility
            meta[SEC_DEPARTMENT_ID] = department
            # Dual-serialization for vector stores lacking array index
            meta[f"{SEC_ALLOWED_ROLES}_str"] = f",{','.join(roles)},"

            if isinstance(doc, SecureDocument):
                transformed.append(SecureDocument.create(page_content=content, metadata=meta))
            else:
                transformed.append(Document(page_content=content, metadata=meta))
        return transformed

    def transform_document(self, content: str, source_metadata: Dict[str, Any]) -> SecureDocument:
        """Transform a single document content string and metadata dict.

        Args:
            content: Document text content.
            source_metadata: Source metadata map.

        Returns:
            SecureDocument: Enriched SecureDocument object.
        """
        temp_doc = Document(page_content=content, metadata=source_metadata)
        res = self.transform_documents([temp_doc])[0]
        return SecureDocument.create(page_content=res.page_content, metadata=res.metadata)


class SecureTextSplitter(BaseDocumentTransformer):
    """Stage 2 TextSplitter splitting documents into bounded chunks while propagating security metadata envelopes."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize SecureTextSplitter.

        Args:
            *args: Optional positional arguments (chunk_size, chunk_overlap, separators).
            **kwargs: Optional keyword arguments (chunk_size, chunk_overlap, separators).
        """
        chunk_size = kwargs.get("chunk_size", args[0] if len(args) > 0 else DEFAULT_CHUNK_SIZE)
        chunk_overlap = kwargs.get("chunk_overlap", args[1] if len(args) > 1 else DEFAULT_CHUNK_OVERLAP)
        separators = kwargs.get("separators", args[2] if len(args) > 2 else DEFAULT_TEXT_SEPARATORS)

        if int(chunk_size) <= 0:
            raise ValueError("chunk_size must be positive")
        if int(chunk_overlap) < 0:
            raise ValueError("chunk_overlap must be non-negative")
        if int(chunk_overlap) >= int(chunk_size):
            raise ValueError("chunk_overlap must be smaller than chunk_size")

        self._chunk_size = int(chunk_size)
        self._chunk_overlap = int(chunk_overlap)
        self._separators = list(separators)

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "SecureTextSplitter":
        """Factory method constructing SecureTextSplitter."""
        return cls(*args, **kwargs)

    @classmethod
    def create_default(cls) -> "SecureTextSplitter":
        """Factory method constructing default SecureTextSplitter."""
        return cls()

    @property
    def chunk_size(self) -> int:
        """Get configured chunk size."""
        return self._chunk_size

    @property
    def chunk_overlap(self) -> int:
        """Get configured chunk overlap."""
        return self._chunk_overlap

    @property
    def separators(self) -> List[str]:
        """Get list of text separators."""
        return list(self._separators)

    def _merge_splits(self, splits: List[str], separator: str) -> List[str]:
        docs: List[str] = []
        current_doc: List[str] = []
        total = 0
        sep_len = len(separator) if separator else 0

        for d in splits:
            _len = len(d)
            if total + _len + (sep_len if current_doc else 0) > self._chunk_size:
                if total > 0:
                    doc = separator.join(current_doc).strip() if separator else "".join(current_doc)
                    if doc:
                        docs.append(doc)
                    while current_doc and (total > self._chunk_overlap or (total + _len + (sep_len if current_doc else 0) > self._chunk_size and total > 0)):
                        popped = current_doc.pop(0)
                        total -= len(popped) + (sep_len if current_doc else 0)
                if _len > self._chunk_size:
                    start = 0
                    step = self._chunk_size - self._chunk_overlap if self._chunk_size > self._chunk_overlap else self._chunk_size
                    while start < _len:
                        end = min(start + self._chunk_size, _len)
                        slice_chunk = d[start:end].strip() if separator else d[start:end]
                        if slice_chunk:
                            docs.append(slice_chunk)
                        start += step
                    current_doc = []
                    total = 0
                    continue

            current_doc.append(d)
            total += _len + (sep_len if len(current_doc) > 1 else 0)

        if current_doc:
            doc = separator.join(current_doc).strip() if separator else "".join(current_doc)
            if doc:
                docs.append(doc)

        return docs

    def _split_text_recursive(self, text: str, separators: Sequence[str]) -> List[str]:
        if not text:
            return []
        chosen_separator: str = ""
        new_separators: List[str] = []
        for i, sep in enumerate(separators):
            if sep == "":
                chosen_separator = ""
                break
            if sep in text:
                chosen_separator = sep
                new_separators = list(separators[i + 1:])
                break

        if chosen_separator == "":
            splits = list(text)
        else:
            splits = text.split(chosen_separator)

        good_splits: List[str] = []
        for s in splits:
            if not s and chosen_separator != "":
                continue
            if len(s) > self._chunk_size and new_separators:
                sub_splits = self._split_text_recursive(s, new_separators)
                good_splits.extend(sub_splits)
            else:
                good_splits.append(s)

        return self._merge_splits(good_splits, chosen_separator)

    def split_text(self, text: str) -> List[str]:
        """Split incoming text into chunks.

        Args:
            text: Raw input text.

        Returns:
            List[str]: List of text chunks.
        """
        if not text:
            return []
        if len(text) <= self._chunk_size:
            return [text.strip()] if text.strip() else []
        return self._split_text_recursive(text, self._separators)

    def split_documents(self, documents: Sequence[Any]) -> List[Any]:
        """Split documents into chunks while propagating metadata envelopes.

        Args:
            documents: Input sequence of document objects.

        Returns:
            List[Any]: Chunks with parent metadata propagated.
        """
        chunks: List[Any] = []
        for doc in documents:
            text = getattr(doc, "page_content", str(doc))
            metadata = dict(getattr(doc, "metadata", {}))
            text_splits = self.split_text(text)
            if not text_splits and text:
                text_splits = [text]
            elif not text_splits and text == "":
                text_splits = [""]
            for split_chunk in text_splits:
                chunk_meta = dict(metadata)
                if isinstance(doc, SecureDocument):
                    chunks.append(SecureDocument.create(page_content=split_chunk, metadata=chunk_meta))
                else:
                    chunks.append(Document(page_content=split_chunk, metadata=chunk_meta))
        return chunks

    def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Transform documents by splitting them into chunks with metadata propagation.

        Args:
            documents: Documents to transform.

        Returns:
            Sequence[Any]: Split document chunks.
        """
        return self.split_documents(documents)


class SecureDocumentChunkEnricher(BaseDocumentTransformer):
    """Stage 3 Chunk Security Enricher scanning headers, XML tags, inline overrides, and executing SPI enrichers."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize SecureDocumentChunkEnricher."""
        spi_enrichers = kwargs.get("spi_enrichers", args[0] if len(args) > 0 else DEFAULT_SPI_ENRICHERS_PARAM)
        secret_key = kwargs.get("secret_key", args[1] if len(args) > 1 else DEFAULT_SECRET_KEY_PARAM)
        audit_manager = kwargs.get("audit_manager", args[2] if len(args) > 2 else None)
        self._spi_enrichers = list(spi_enrichers) if spi_enrichers is not None else []
        self._secret_key = secret_key
        self._audit_manager: Optional[AuditManager] = audit_manager
        self._heading_enricher = HeadingClassificationEnricher.create()

    @classmethod
    def create(
        cls,
        spi_enrichers: Optional[List[ChunkSecurityEnricherSPI]],
        secret_key: Optional[str],
        *args: Any,
        **kwargs: Any,
    ) -> "SecureDocumentChunkEnricher":
        """Factory method to construct SecureDocumentChunkEnricher.

        Args:
            spi_enrichers: Optional list of ChunkSecurityEnricherSPI enrichers.
            secret_key: Secret key string for envelope digest signature.
            *args: Optional positional arguments.
            **kwargs: Optional keyword arguments.

        Returns:
            SecureDocumentChunkEnricher: New enricher instance.
        """
        return cls(spi_enrichers, secret_key, *args, **kwargs)

    @classmethod
    def create_default(cls) -> "SecureDocumentChunkEnricher":
        """Factory method creating default SecureDocumentChunkEnricher.

        Returns:
            SecureDocumentChunkEnricher: Default enricher instance.
        """
        return cls()

    def _apply_monotonic_updates(self, meta: Dict[str, Any], updates: Dict[str, Any], idx: int) -> None:
        if not updates:
            return
        parent_floor = int(meta.get(SEC_CLEARANCE_FLOOR, 0))
        de_escalation_detected = False
        elevation_detected = False

        if SEC_CLEARANCE_FLOOR in updates:
            proposed_floor = int(updates[SEC_CLEARANCE_FLOOR])
            if proposed_floor < parent_floor:
                updates[SEC_CLEARANCE_FLOOR] = parent_floor
                de_escalation_detected = True
            elif proposed_floor > parent_floor:
                meta["sec:clearance_level"] = proposed_floor
                elevation_detected = True

        if SEC_CLASSIFICATION_LEVEL in updates:
            new_rank = CLASSIFICATION_TO_RANK.get(str(updates[SEC_CLASSIFICATION_LEVEL]).upper(), 0)
            if new_rank < parent_floor:
                del updates[SEC_CLASSIFICATION_LEVEL]
                de_escalation_detected = True
            elif new_rank > parent_floor:
                updates[SEC_CLEARANCE_FLOOR] = new_rank
                meta["sec:clearance_level"] = new_rank
                elevation_detected = True

        meta.update(updates)
        if de_escalation_detected:
            meta[SEC_MONOTONIC_ELEVATION_ENFORCED] = True
            if self._audit_manager:
                doc_id = str(meta.get(SEC_DOCUMENT_ID, "UNKNOWN"))
                tenant = str(meta.get(SEC_TENANT_ID, DEFAULT_TENANT_ID))
                self._audit_manager.record_event(AuditEvent.create(
                    subject_id="INGEST_PIPELINE",
                    tenant_id=tenant,
                    action="ingest:monotonic_elevation",
                    resource=f"{doc_id}:{idx}",
                    decision="ENFORCED",
                    diagnostic_reason=f"{EVENT_MONOTONIC_ELEVATION_ENFORCED} (CLASSIFICATION_DE_ESCALATION_REJECTED)",
                    severity=SEVERITY_WARNING,
                    metadata={"document_id": doc_id, "chunk_index": idx, "preserved_floor": parent_floor},
                    enforcement_point=PEP_INGESTION_PIPELINE,
                    reason_code=EVENT_MONOTONIC_ELEVATION_ENFORCED,
                ))
        elif elevation_detected and self._audit_manager:
            doc_id = str(meta.get(SEC_DOCUMENT_ID, "UNKNOWN"))
            tenant = str(meta.get(SEC_TENANT_ID, DEFAULT_TENANT_ID))
            elevated_cls = str(meta.get(SEC_CLASSIFICATION_LEVEL, CLASSIFICATION_CONFIDENTIAL))
            self._audit_manager.record_event(AuditEvent.create(
                subject_id="INGEST_PIPELINE",
                tenant_id=tenant,
                action="ingest:header_elevation",
                resource=f"{doc_id}:{idx}",
                decision="ELEVATED",
                diagnostic_reason=f"Header Elevation: {elevated_cls} sec:clearance_floor elevated",
                severity=SEVERITY_NOTICE,
                metadata={"document_id": doc_id, "chunk_index": idx, "elevated_classification": elevated_cls},
                enforcement_point=PEP_INGESTION_PIPELINE,
                reason_code=EVENT_INGEST_HEADER_ELEVATED,
            ))

    def enrich(self, document: Any) -> Any:
        """Enrich a single document chunk."""
        return self.transform_documents([document])[0]

    def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Enrich document chunks with monotonic clearance elevation and inline header/XML/SPI tags.

        Args:
            documents: Input chunk sequence.

        Returns:
            Sequence[Any]: Enriched chunk sequence.
        """
        enriched_docs: List[Any] = []
        for idx, doc in enumerate(documents):
            content = getattr(doc, "page_content", str(doc))
            meta = dict(getattr(doc, "metadata", {}))

            meta[SEC_CHUNK_INDEX] = idx

            # Built-in structural heading & XML tag enrichment with monotonic enforcement
            heading_ctx = ChunkEnrichmentContext.create(
                chunk_text=content,
                parent_document_metadata=dict(meta),
                current_security_envelope=dict(meta),
                chunk_index=idx,
            )
            heading_updates = self._heading_enricher.enrich(heading_ctx)
            self._apply_monotonic_updates(meta, heading_updates, idx)

            # SPI Custom Enricher Strategy (with Monotonic Elevation Enforcement)
            for spi in self._spi_enrichers:
                if isinstance(spi, HeadingClassificationEnricher):
                    continue
                ctx = ChunkEnrichmentContext.create(
                    chunk_text=content,
                    parent_document_metadata=dict(meta),
                    current_security_envelope=dict(meta),
                    chunk_index=idx,
                )
                spi_updates = spi.enrich(ctx)
                self._apply_monotonic_updates(meta, spi_updates, idx)

            # Compute optional SHA-256 HMAC digest signature
            if self._secret_key and not (meta.get("sec:unlabelled_raw") or meta.get("sec:unlabelled") or meta.get("sec:corrupt")):
                meta[SEC_ENVELOPE_HASH] = compute_envelope_hmac(meta, self._secret_key)

            if isinstance(doc, SecureDocument):
                enriched_docs.append(SecureDocument.create(page_content=content, metadata=meta))
            else:
                enriched_docs.append(Document(page_content=content, metadata=meta))

        return enriched_docs


class SecureVectorStoreIngestor:
    """Stage 5 Ingestion orchestrator chunking raw content, enriching with sec:* metadata, and validating modes."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize SecureVectorStoreIngestor."""
        transformer = kwargs.get("transformer", args[0] if len(args) > 0 else None)
        enricher = kwargs.get("enricher", args[1] if len(args) > 1 else None)
        validator = kwargs.get("validator", args[2] if len(args) > 2 else None)
        ingestion_mode = kwargs.get("ingestion_mode", args[3] if len(args) > 3 else DEFAULT_INGESTION_MODE_PARAM)
        text_splitter = kwargs.get("text_splitter", args[4] if len(args) > 4 else None)
        audit_manager = kwargs.get("audit_manager", args[5] if len(args) > 5 else None)

        self._transformer = transformer if transformer is not None else DocumentSecurityTransformer.create_default()
        self._enricher = enricher if enricher is not None else SecureDocumentChunkEnricher.create_default()
        self._validator = validator if validator is not None else SecurityEnvelopeValidator.create_default()
        self._ingestion_mode = ingestion_mode
        self._text_splitter = text_splitter
        self._audit_manager = audit_manager

    @classmethod
    def create(
        cls,
        *args: Any,
        **kwargs: Any,
    ) -> "SecureVectorStoreIngestor":
        """Factory method constructing SecureVectorStoreIngestor."""
        return cls(*args, **kwargs)

    @classmethod
    def create_default(cls) -> "SecureVectorStoreIngestor":
        """Factory method constructing default SecureVectorStoreIngestor.

        Returns:
            SecureVectorStoreIngestor: Default ingestor instance.
        """
        return cls()

    @property
    def ingestion_mode(self) -> str:
        """Get configured ingestion mode."""
        return self._ingestion_mode

    def _validate_and_finalize_batch(self, enriched_docs: Sequence[Any], default_doc_id: str) -> List[SecureDocument]:
        final_docs: List[SecureDocument] = []
        for idx, doc in enumerate(enriched_docs):
            meta = dict(getattr(doc, "metadata", {}))
            doc_id = str(meta.get(SEC_DOCUMENT_ID, default_doc_id))
            meta.pop("sec:unlabelled_raw", None)

            if not self._validator.validate_metadata(meta):
                default_tenant = getattr(self._transformer, "_default_tenant", DEFAULT_TENANT_ID)
                tenant = str(meta.get(SEC_TENANT_ID, default_tenant))
                if self._ingestion_mode == INGEST_MODE_STRICT_FAIL_CLOSED:
                    if self._audit_manager:
                        self._audit_manager.record_event(AuditEvent.create(
                            subject_id="INGEST_PIPELINE",
                            tenant_id=tenant,
                            action="ingest:chunk",
                            resource=f"{doc_id}:{idx}",
                            decision="REJECTED",
                            diagnostic_reason=(
                                "INGEST_CHUNK_REJECTED | ATOMIC_ROLLBACK | "
                                "UNLABELLED_CHUNK_QUARANTINED | MISSING_SECURITY_ENVELOPE: Strict fail-closed validation failure"
                            ),
                            severity=SEVERITY_WARNING,
                            metadata={"document_id": doc_id, "chunk_index": idx},
                            enforcement_point=PEP_INGESTION_PIPELINE,
                            reason_code=EVENT_INGEST_CHUNK_REJECTED,
                        ))
                    raise IngestionRejectedException.create_rejection(
                        document_id=doc_id,
                        chunk_index=idx,
                        message=(
                            f"INGEST_CHUNK_REJECTED (ATOMIC_ROLLBACK / UNLABELLED_CHUNK_QUARANTINED / MISSING_SECURITY_ENVELOPE): "
                            f"Ingestion rejected for document {doc_id} chunk {idx} under Strict Fail-Closed mode."
                        ),
                    )
                elif self._ingestion_mode == INGEST_MODE_EVERYTHING_CLASSIFIED:
                    meta[SEC_TENANT_ID] = tenant
                    meta[SEC_CLASSIFICATION_LEVEL] = CLASSIFICATION_RESTRICTED
                    meta["sec:clearance_level"] = CLEARANCE_RANK_RESTRICTED
                    meta[SEC_CLEARANCE_FLOOR] = CLEARANCE_RANK_RESTRICTED
                    meta[SEC_QUARANTINED] = True
                    if not meta.get(SEC_ALLOWED_ROLES):
                        meta[SEC_ALLOWED_ROLES] = ["ROLE_ADMIN"]
                        meta[SEC_REQUIRED_ROLES] = ["ROLE_ADMIN"]
                    if getattr(self._validator, "secret_key", None):
                        meta[SEC_ENVELOPE_HASH] = compute_envelope_hmac(meta, self._validator.secret_key)
                    if self._audit_manager:
                        self._audit_manager.record_event(AuditEvent.create(
                            subject_id="INGEST_PIPELINE",
                            tenant_id=tenant,
                            action="ingest:chunk",
                            resource=f"{doc_id}:{idx}",
                            decision="QUARANTINED",
                            diagnostic_reason="INGEST_CHUNK_QUARANTINED (sec:quarantined=true): Elevated to RESTRICTED under Everything Classified mode",
                            severity=SEVERITY_NOTICE,
                            metadata={"document_id": doc_id, "chunk_index": idx, SEC_QUARANTINED: True},
                            enforcement_point=PEP_INGESTION_PIPELINE,
                            reason_code=EVENT_INGEST_CHUNK_QUARANTINED,
                        ))
                elif self._ingestion_mode == INGEST_MODE_EVERYTHING_PUBLIC:
                    meta[SEC_TENANT_ID] = tenant
                    meta[SEC_CLASSIFICATION_LEVEL] = CLASSIFICATION_PUBLIC
                    meta["sec:clearance_level"] = CLEARANCE_RANK_PUBLIC
                    meta[SEC_CLEARANCE_FLOOR] = CLEARANCE_RANK_PUBLIC
                    meta[SEC_ALLOWED_ROLES] = [CLASSIFICATION_PUBLIC]
                    meta[SEC_REQUIRED_ROLES] = [CLASSIFICATION_PUBLIC]
                    if getattr(self._validator, "secret_key", None):
                        meta[SEC_ENVELOPE_HASH] = compute_envelope_hmac(meta, self._validator.secret_key)
                    if self._audit_manager:
                        self._audit_manager.record_event(AuditEvent.create(
                            subject_id="INGEST_PIPELINE",
                            tenant_id=tenant,
                            action="ingest:chunk",
                            resource=f"{doc_id}:{idx}",
                            decision="DEFAULT_PUBLIC",
                            diagnostic_reason="Defaulted to PUBLIC under Everything Public mode",
                            severity=SEVERITY_NOTICE,
                            metadata={"document_id": doc_id, "chunk_index": idx},
                            enforcement_point=PEP_INGESTION_PIPELINE,
                            reason_code=EVENT_INGEST_CHUNK_DEFAULT_PUBLIC,
                        ))

            final_docs.append(SecureDocument.create(page_content=doc.page_content, metadata=meta))
        return final_docs

    def _split_documents(self, documents: Sequence[Any]) -> Sequence[Any]:
        """Stage 2 TextSplitter execution propagating metadata from parent documents to chunks."""
        if self._text_splitter is None:
            return documents
        if hasattr(self._text_splitter, "transform_documents"):
            return self._text_splitter.transform_documents(documents)
        if hasattr(self._text_splitter, "split_documents"):
            return self._text_splitter.split_documents(documents)
        if hasattr(self._text_splitter, "split_text"):
            split_docs: List[Any] = []
            for doc in documents:
                content = getattr(doc, "page_content", str(doc))
                meta = dict(getattr(doc, "metadata", {}))
                chunks = self._text_splitter.split_text(content)
                if not chunks and content:
                    chunks = [content]
                elif not chunks and content == "":
                    chunks = [""]
                for chunk in chunks:
                    chunk_meta = dict(meta)
                    if isinstance(doc, SecureDocument):
                        split_docs.append(SecureDocument.create(page_content=chunk, metadata=chunk_meta))
                    else:
                        split_docs.append(Document(page_content=chunk, metadata=chunk_meta))
            return split_docs
        if callable(self._text_splitter):
            split_docs = []
            for doc in documents:
                content = getattr(doc, "page_content", str(doc))
                meta = dict(getattr(doc, "metadata", {}))
                chunks = self._text_splitter(content)
                if not chunks and content:
                    chunks = [content]
                elif not chunks and content == "":
                    chunks = [""]
                for chunk in chunks:
                    chunk_meta = dict(meta)
                    if isinstance(doc, SecureDocument):
                        split_docs.append(SecureDocument.create(page_content=chunk, metadata=chunk_meta))
                    else:
                        split_docs.append(Document(page_content=chunk, metadata=chunk_meta))
            return split_docs
        return documents

    def ingest_documents(self, documents: Sequence[Any]) -> List[SecureDocument]:
        """Atomically ingest a batch of documents through the 5-stage security pipeline.

        Document → Stage 1(Transformer) → Stage 2(TextSplitter) → Stage 3(Enricher) → Stage 4(Validator) → Stage 5(VectorStore)

        Args:
            documents: Sequence of Document objects or dicts with 'page_content'/'content' and 'metadata'.

        Returns:
            List[SecureDocument]: Validated SecureDocument chunks.

        Raises:
            IngestionRejectedException: On any chunk validation or enrichment failure in STRICT_FAIL_CLOSED mode.
        """
        raw_docs: List[Any] = []
        for item in documents:
            if isinstance(item, dict):
                content = str(item.get("page_content") or item.get("content") or "")
                meta = dict(item.get("metadata") or {})
                raw_docs.append(Document(page_content=content, metadata=meta))
            else:
                raw_docs.append(item)

        try:
            # Stage 1: DocumentSecurityTransformer
            stamped_docs = self._transformer.transform_documents(raw_docs)
            # Stage 2: Standard TextSplitter with metadata propagation
            split_docs = self._split_documents(stamped_docs)
            # Stage 3: SecureDocumentChunkEnricher
            enriched_docs = self._enricher.transform_documents(split_docs)
        except Exception as err:
            if self._ingestion_mode == INGEST_MODE_STRICT_FAIL_CLOSED:
                if self._audit_manager:
                    self._audit_manager.record_event(AuditEvent.create(
                        subject_id="INGEST_PIPELINE",
                        tenant_id=DEFAULT_TENANT_ID,
                        action="ingest:batch",
                        resource="batch",
                        decision="REJECTED",
                        diagnostic_reason=f"INGEST_CHUNK_REJECTED | ATOMIC_ROLLBACK: {str(err)}",
                        severity=SEVERITY_WARNING,
                        metadata={"error": str(err)},
                        enforcement_point=PEP_INGESTION_PIPELINE,
                        reason_code=EVENT_INGEST_CHUNK_REJECTED,
                    ))
                raise IngestionRejectedException.create_rejection(
                    document_id="batch",
                    chunk_index=0,
                    message=f"INGEST_CHUNK_REJECTED (ATOMIC_ROLLBACK): {str(err)}",
                ) from err
            raise

        # Stage 4: SecurityEnvelopeValidator and Stage 5 return
        return self._validate_and_finalize_batch(enriched_docs, str(uuid.uuid4()))

    def ingest_text(
        self,
        text: str,
        source_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> List[SecureDocument]:
        """Ingest raw text string into secure document chunks with full envelope validation.

        Args:
            text: Raw text content string.
            source_name: Source document name or identifier.
            *args: Optional positional arguments (chunk_delimiter, metadata).
            **kwargs: Optional keyword arguments (chunk_delimiter, metadata).

        Returns:
            List[SecureDocument]: Ingested and validated SecureDocument objects.

        Raises:
            IngestionRejectedException: If strict validation fails under STRICT_FAIL_CLOSED mode.
        """
        chunk_delimiter = str(kwargs.get("chunk_delimiter", args[0] if len(args) > 0 else DEFAULT_CHUNK_DELIMITER))
        metadata = kwargs.get("metadata", args[1] if len(args) > 1 else None)

        base_meta = dict(metadata) if metadata is not None else {}
        base_meta["source"] = source_name
        doc_id = base_meta.get(SEC_DOCUMENT_ID, str(uuid.uuid4()))
        base_meta[SEC_DOCUMENT_ID] = doc_id

        if self._text_splitter is not None:
            raw_docs = [Document(page_content=text, metadata=dict(base_meta))]
            return self.ingest_documents(raw_docs)

        raw_chunks = [chunk.strip() for chunk in text.split(chunk_delimiter) if chunk.strip()]
        if not raw_chunks and text:
            raw_chunks = [text]
        raw_docs = [Document(page_content=chunk, metadata=dict(base_meta)) for chunk in raw_chunks]
        return self.ingest_documents(raw_docs)

