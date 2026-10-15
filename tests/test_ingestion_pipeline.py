"""
Comprehensive unit tests for Secure Ingestion Pipeline (Stage 3 Enricher, SPI, HMAC, Policy Modes).
"""

import unittest
from security_adapter_langchain.ingestion import (
    DocumentSecurityTransformer,
    SecureDocumentChunkEnricher,
    SecurityEnvelopeValidator,
    SecureVectorStoreIngestor,
    SecureTextSplitter,
    ChunkSecurityEnricherSPI,
    ChunkEnrichmentContext,
    compute_envelope_hmac,
)
from security_core.exceptions import IngestionRejectedException
from security_core.constants import (
    CLASSIFICATION_PUBLIC,
    CLASSIFICATION_RESTRICTED,
    INGEST_MODE_STRICT_FAIL_CLOSED,
    INGEST_MODE_EVERYTHING_CLASSIFIED,
    INGEST_MODE_EVERYTHING_PUBLIC,
    SEC_CLASSIFICATION_LEVEL,
    SEC_ENVELOPE_HASH,
    SEC_QUARANTINED,
)


class CustomDLPEnricher(ChunkSecurityEnricherSPI):
    def enrich(self, context: ChunkEnrichmentContext):
        if "PII" in context.chunk_text or "SECRET_KEY" in context.chunk_text:
            return {SEC_CLASSIFICATION_LEVEL: CLASSIFICATION_RESTRICTED}
        return {}


class TestSecureIngestionPipeline(unittest.TestCase):

    def test_structural_header_and_xml_enrichment(self):
        transformer = DocumentSecurityTransformer(
            default_classification=CLASSIFICATION_PUBLIC,
            default_roles=["USER"],
            default_tenant="TENANT_A",
            default_department="ENG",
        )
        enricher = SecureDocumentChunkEnricher(
            spi_enrichers=[CustomDLPEnricher()],
            secret_key="my_hmac_secret",
        )

        raw_text = "## [RESTRICTED] Infrastructure Runbook\n\nContains SECRET_KEY and AWS credentials."
        docs = transformer.transform_documents([transformer.transform_document(raw_text, {})])
        enriched = enricher.transform_documents(docs)

        self.assertEqual(len(enriched), 1)
        doc = enriched[0]
        meta = doc.metadata
        self.assertEqual(meta[SEC_CLASSIFICATION_LEVEL], CLASSIFICATION_RESTRICTED)
        self.assertIn(SEC_ENVELOPE_HASH, meta)

    def test_ingestion_policy_modes(self):
        transformer = DocumentSecurityTransformer(
            default_classification=CLASSIFICATION_PUBLIC,
            default_roles=["USER"],
            default_tenant="CORP",
            default_department="FIN",
        )

        # Strict Fail-Closed Mode raises exception on invalid envelope
        invalid_validator = SecurityEnvelopeValidator(secret_key="secret")
        invalid_validator.validate_metadata = lambda meta: False

        strict_ingestor = SecureVectorStoreIngestor(
            transformer=transformer,
            validator=invalid_validator,
            ingestion_mode=INGEST_MODE_STRICT_FAIL_CLOSED,
        )
        with self.assertRaises(IngestionRejectedException):
            strict_ingestor.ingest_text("Test content", "source.txt")

        # Everything Classified Mode sets RESTRICTED + Quarantined flag
        classified_ingestor = SecureVectorStoreIngestor(
            transformer=transformer,
            validator=invalid_validator,
            ingestion_mode=INGEST_MODE_EVERYTHING_CLASSIFIED,
        )
        docs = classified_ingestor.ingest_text("Unlabelled data", "doc.txt")
        self.assertEqual(docs[0].metadata[SEC_CLASSIFICATION_LEVEL], CLASSIFICATION_RESTRICTED)
        self.assertTrue(docs[0].metadata[SEC_QUARANTINED])

        # Everything Public Mode sets PUBLIC classification while preserving tenant
        public_ingestor = SecureVectorStoreIngestor(
            transformer=transformer,
            validator=invalid_validator,
            ingestion_mode=INGEST_MODE_EVERYTHING_PUBLIC,
        )
        docs_public = public_ingestor.ingest_text("Unlabelled public data", "doc.txt")
        self.assertEqual(docs_public[0].metadata[SEC_CLASSIFICATION_LEVEL], CLASSIFICATION_PUBLIC)
        self.assertEqual(docs_public[0].metadata["sec:tenant_id"], "CORP")

    def test_hmac_digest_verification(self):
        meta = {"sec:tenant_id": "CORP", "sec:classification_level": "INTERNAL", "sec:allowed_roles": ["ADMIN"]}
        secret = "super-secret-key"
        signature = compute_envelope_hmac(meta, secret)
        meta["sec:envelope_hash"] = signature

        validator = SecurityEnvelopeValidator(secret_key=secret)
        self.assertTrue(validator.validate_metadata(meta))

        # Tamper metadata
        tampered_meta = dict(meta)
        tampered_meta["sec:classification_level"] = "PUBLIC"
        self.assertFalse(validator.validate_metadata(tampered_meta))

    def test_ingestion_audit_events(self):
        from security_core.audit import AuditManager, InMemoryAuditLogger
        from security_core.constants import EVENT_INGEST_CHUNK_REJECTED
        logger = InMemoryAuditLogger.create()
        audit_mgr = AuditManager.create(publishers=[logger])
        transformer = DocumentSecurityTransformer()
        enricher = SecureDocumentChunkEnricher()

        class FailingValidator(SecurityEnvelopeValidator):
            def validate_metadata(self, metadata):
                return False

        validator = FailingValidator()

        ingestor_strict = SecureVectorStoreIngestor(
            transformer=transformer,
            enricher=enricher,
            validator=validator,
            ingestion_mode=INGEST_MODE_STRICT_FAIL_CLOSED,
            audit_manager=audit_mgr,
        )
        with self.assertRaises(IngestionRejectedException):
            ingestor_strict.ingest_text("doc text", "source1")

        events = logger.get_events()
        self.assertGreaterEqual(len(events), 1)
        self.assertTrue(any(e.reason_code == EVENT_INGEST_CHUNK_REJECTED for e in events))

    def test_secure_text_splitter_validation(self):
        with self.assertRaises(ValueError):
            SecureTextSplitter(chunk_size=0)
        with self.assertRaises(ValueError):
            SecureTextSplitter(chunk_size=100, chunk_overlap=100)
        with self.assertRaises(ValueError):
            SecureTextSplitter(chunk_size=100, chunk_overlap=-1)

    def test_secure_text_splitter_chunking_and_metadata_propagation(self):
        from langchain_core.documents import Document
        splitter = SecureTextSplitter(chunk_size=20, chunk_overlap=5)
        text = "Alpha Bravo Charlie\n\nDelta Echo Foxtrot\n\nGolf Hotel India"
        chunks = splitter.split_text(text)
        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 20)

        # Verify metadata propagation
        doc = Document(
            page_content=text,
            metadata={"sec:tenant_id": "CORP", "author": "security-team", "sec:classification_level": "INTERNAL"},
        )
        split_docs = splitter.transform_documents([doc])
        self.assertGreater(len(split_docs), 1)
        for chunk_doc in split_docs:
            self.assertEqual(chunk_doc.metadata["sec:tenant_id"], "CORP")
            self.assertEqual(chunk_doc.metadata["author"], "security-team")
            self.assertEqual(chunk_doc.metadata["sec:classification_level"], "INTERNAL")

    def test_secure_vector_store_ingestor_executes_splitter_between_stage1_and_stage3(self):
        from security_core.constants import SEC_CHUNK_INDEX, SEC_CLASSIFICATION_LEVEL
        transformer = DocumentSecurityTransformer(
            default_classification=CLASSIFICATION_PUBLIC,
            default_roles=["ROLE_USER"],
            default_tenant="TENANT_ALPHA",
        )
        splitter = SecureTextSplitter(chunk_size=50, chunk_overlap=10)
        enricher = SecureDocumentChunkEnricher()
        validator = SecurityEnvelopeValidator.create_default()

        ingestor = SecureVectorStoreIngestor(
            transformer=transformer,
            enricher=enricher,
            validator=validator,
            text_splitter=splitter,
            ingestion_mode=INGEST_MODE_STRICT_FAIL_CLOSED,
        )

        # Raw document with multi-paragraph text, second paragraph has restricted header
        raw_text = "Standard public section content.\n\n## [RESTRICTED] Highly sensitive section content requiring clearance."
        from langchain_core.documents import Document
        input_doc = Document(page_content=raw_text, metadata={"source": "test_doc.md"})

        final_chunks = ingestor.ingest_documents([input_doc])

        # Stage 2 must have split input_doc into multiple chunks
        self.assertGreater(len(final_chunks), 1)

        # Stage 1 stamped tenant & baseline roles on both chunks via metadata propagation
        for idx, chunk in enumerate(final_chunks):
            self.assertEqual(chunk.metadata["sec:tenant_id"], "TENANT_ALPHA")
            self.assertEqual(chunk.metadata[SEC_CHUNK_INDEX], idx)

        # Stage 3 enricher executed after Stage 2 splitting, elevating the second chunk specifically
        self.assertEqual(final_chunks[0].metadata[SEC_CLASSIFICATION_LEVEL], CLASSIFICATION_PUBLIC)
        self.assertEqual(final_chunks[1].metadata[SEC_CLASSIFICATION_LEVEL], CLASSIFICATION_RESTRICTED)

