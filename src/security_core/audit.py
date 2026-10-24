"""
Structured security audit event publishing and observability subsystem.

Provides OCSF/ECS-aligned audit event models, multi-stage PII/secret sanitization,
publisher SPI implementations, and non-blocking ring buffer audit dispatch as specified in Spec 5.
"""

import os
import re
import json
import time
import uuid
import logging
import threading
from collections import deque
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from security_core.constants import (
    DEFAULT_SCHEMA_VERSION,
    DEFAULT_RING_BUFFER_CAPACITY,
    DEFAULT_PAYLOAD_MAX_CHARS,
    SEVERITY_INFORMATIONAL,
    SEVERITY_WARNING,
    SEVERITY_SECURITY_ALERT,
    SEVERITY_CRITICAL_ALERT,
    DEFAULT_SENSITIVE_FIELD_NAMES,
)
from security_core.pii import (
    PiiContext,
    PiiSanitizerSPI,
    BuiltInPiiSanitizer,
    get_pii_sanitizer,
    get_pii_scope,
    PII_STAGE_AUDIT_PAYLOAD,
    PII_SCOPE_DISABLED,
)



class AuditEvent:
    """OCSF-aligned tamper-evident structured audit evaluation record.

    Attributes:
        event_id (str): Unique UUID string for event identification.
        schema_version (str): Audit schema version specification.
        timestamp_utc (float): UTC timestamp in seconds since epoch.
        invocation_id (str): Unique trace context or invocation ID.
        trace_id (Optional[str]): OpenTelemetry trace ID.
        span_id (Optional[str]): OpenTelemetry span ID.
        subject_id (str): Caller subject identifier.
        tenant_id (str): Tenant isolation boundary identifier.
        subject_roles (List[str]): Roles assigned to caller.
        subject_clearance (int): Clearance level rank.
        enforcement_point (str): Enforcement point identifier.
        action (str): Action string requested.
        target_resource (str): Target resource path or name.
        decision (str): PDP decision outcome ('PERMIT', 'DENY', 'BLOCKED', etc.).
        reason_code (str): Standardized security event reason code.
        diagnostic_reason (str): Human-readable diagnostic description.
        severity (str): Event severity level string.
        payload_snapshot (Dict[str, Any]): Sanitized payload snapshot.
        threat_category (Optional[str]): Threat classification label.
        threat_score (Optional[float]): Threat confidence score.
        detected_pattern (Optional[str]): Injection pattern ID.
        mitigation_action (Optional[str]): Mitigation strategy applied.
        sequence_number (int): Monotonic audit sequence number.
        envelope_hmac (Optional[str]): Signature hash for tamper evidence.
    """

    def __init__(
        self,
        event_id: str,
        schema_version: str,
        timestamp_utc: float,
        invocation_id: str,
        trace_id: Optional[str],
        span_id: Optional[str],
        subject_id: str,
        tenant_id: str,
        subject_roles: List[str],
        subject_clearance: int,
        enforcement_point: str,
        action: str,
        target_resource: str,
        decision: str,
        reason_code: str,
        diagnostic_reason: str,
        severity: str,
        payload_snapshot: Dict[str, Any],
        threat_category: Optional[str] = None,
        threat_score: Optional[float] = None,
        detected_pattern: Optional[str] = None,
        mitigation_action: Optional[str] = None,
        sequence_number: int = 0,
        envelope_hmac: Optional[str] = None,
    ):
        """Initialize AuditEvent.

        Args:
            event_id: Unique UUID string for event identification.
            schema_version: Audit schema version string.
            timestamp_utc: UTC timestamp in seconds since epoch.
            invocation_id: Unique trace context or invocation ID.
            trace_id: OpenTelemetry trace ID if present.
            span_id: OpenTelemetry span ID if present.
            subject_id: Caller subject identifier.
            tenant_id: Multi-tenant boundary identifier.
            subject_roles: Roles assigned to caller.
            subject_clearance: Clearance rank assigned to caller.
            enforcement_point: Enforcement point identifier.
            action: Requested action identifier.
            target_resource: Target resource path or name.
            decision: PDP decision verdict.
            reason_code: Standardized security event reason code.
            diagnostic_reason: Human-readable diagnostic description.
            severity: Event severity level.
            payload_snapshot: Sanitized payload snapshot dictionary.
            threat_category: Optional threat classification category.
            threat_score: Optional threat confidence score.
            detected_pattern: Optional injection pattern identifier.
            mitigation_action: Optional mitigation strategy applied.
            sequence_number: Monotonic audit sequence number.
            envelope_hmac: Optional HMAC signature for tamper evidence.
        """
        self.event_id = event_id
        self.schema_version = schema_version
        self.timestamp_utc = timestamp_utc
        self.invocation_id = invocation_id
        self.trace_id = trace_id
        self.span_id = span_id
        self.subject_id = subject_id
        self.tenant_id = tenant_id
        self.subject_roles = list(subject_roles)
        self.subject_clearance = subject_clearance
        self.enforcement_point = enforcement_point
        self.action = action
        self.target_resource = target_resource
        self.decision = decision
        self.reason_code = reason_code
        self.diagnostic_reason = diagnostic_reason
        self.severity = severity
        self.payload_snapshot = dict(payload_snapshot)
        self.threat_category = threat_category
        self.threat_score = threat_score
        self.detected_pattern = detected_pattern
        self.mitigation_action = mitigation_action
        self.sequence_number = sequence_number
        self.envelope_hmac = envelope_hmac

    @classmethod
    def create(
        cls,
        subject_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        decision: str,
        diagnostic_reason: str,
        severity: str,
        metadata: Dict[str, Any],
        enforcement_point: str = "SYSTEM_BOUNDARY",
        reason_code: str = "POLICY_EVALUATION",
    ):
        """Factory method to construct an AuditEvent with OpenTelemetry trace extraction.

        Args:
            subject_id: Subject identifier.
            tenant_id: Tenant ID.
            action: Requested action.
            resource: Resource path/name.
            decision: Decision verdict.
            diagnostic_reason: Rationale description.
            severity: Severity level.
            metadata: Payload snapshot dictionary.
            enforcement_point: PEP point ID.
            reason_code: Event reason code.

        Returns:
            AuditEvent: Constructed audit event instance.
        """
        trace_id = metadata.get("trace_id")
        span_id = metadata.get("span_id")
        if trace_id is None or span_id is None:
            try:
                from opentelemetry import trace
                current_span = trace.get_current_span()
                if current_span and current_span.get_span_context().is_valid:
                    ctx = current_span.get_span_context()
                    if trace_id is None:
                        trace_id = f"{ctx.trace_id:032x}"
                    if span_id is None:
                        span_id = f"{ctx.span_id:016x}"
            except Exception:
                pass

        return cls(
            event_id=str(uuid.uuid4()),
            schema_version=DEFAULT_SCHEMA_VERSION,
            timestamp_utc=time.time(),
            invocation_id=metadata.get("invocation_id", str(uuid.uuid4())),
            trace_id=trace_id,
            span_id=span_id,
            subject_id=subject_id,
            tenant_id=tenant_id,
            subject_roles=metadata.get("subject_roles", []),
            subject_clearance=int(metadata.get("subject_clearance", 0)),
            enforcement_point=enforcement_point,
            action=action,
            target_resource=resource,
            decision=decision,
            reason_code=reason_code,
            diagnostic_reason=diagnostic_reason,
            severity=severity,
            payload_snapshot=metadata,
        )

    @property
    def resource(self) -> str:
        """Get target resource identifier."""
        return self.target_resource

    @property
    def metadata(self) -> Dict[str, Any]:
        """Get payload snapshot dictionary."""
        return self.payload_snapshot

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AuditEvent into dictionary format.

        Returns:
            Dict[str, Any]: JSON-compatible event dictionary.
        """
        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "timestamp_utc": self.timestamp_utc,
            "invocation_id": self.invocation_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "subject_roles": self.subject_roles,
            "subject_clearance": self.subject_clearance,
            "enforcement_point": self.enforcement_point,
            "action": self.action,
            "target_resource": self.target_resource,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "diagnostic_reason": self.diagnostic_reason,
            "severity": self.severity,
            "payload_snapshot": self.payload_snapshot,
            "threat_category": self.threat_category,
            "threat_score": self.threat_score,
            "detected_pattern": self.detected_pattern,
            "mitigation_action": self.mitigation_action,
            "sequence_number": self.sequence_number,
            "envelope_hmac": self.envelope_hmac,
        }


SENSITIVE_FIELD_NAMES = set(DEFAULT_SENSITIVE_FIELD_NAMES)


class AuditSanitizer:
    """3-stage in-flight PII and secret scrubber pipeline delegating to active PiiSanitizerSPI."""

    SECRET_REGEX = BuiltInPiiSanitizer.COMBINED_SECRET_REGEX

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "AuditSanitizer":
        """Construct an AuditSanitizer and register any provided masked_fields.

        Args:
            *args: Optional positional arguments (masked_fields).
            **kwargs: Optional keyword arguments (masked_fields).

        Returns:
            AuditSanitizer: New sanitizer wrapper instance.
        """
        sanitizer = get_pii_sanitizer()
        masked_fields = kwargs.get("masked_fields", args[0] if len(args) > 0 else None)
        if masked_fields and hasattr(sanitizer, "register_masked_field"):
            for field_name in masked_fields:
                sanitizer.register_masked_field(str(field_name))
        return cls()

    @classmethod
    def register_masked_field(cls, field_name: str) -> None:
        """Stage 1: Register a parameter or field name for automatic @Masked annotation redaction.

        Args:
            field_name: Parameter or field name to register for dictionary masking.
        """
        sanitizer = get_pii_sanitizer()
        if hasattr(sanitizer, "register_masked_field"):
            sanitizer.register_masked_field(field_name)

    @classmethod
    def is_masked_field(cls, field_name: str) -> bool:
        """Check if a field name is marked as sensitive/masked.

        Args:
            field_name: Parameter or field name to check.

        Returns:
            bool: True if field is registered for masking, False otherwise.
        """
        sanitizer = get_pii_sanitizer()
        if hasattr(sanitizer, "is_masked_field"):
            return sanitizer.is_masked_field(field_name)
        return False

    @classmethod
    def sanitize_string(cls, value: str, max_chars: int) -> str:
        """Apply Stage 2 regex scrubbing and Stage 3 truncation to a string value.

        Args:
            value: Input string to sanitize.
            max_chars: Character length cap before applying truncation suffix.

        Returns:
            str: Sanitized and optionally truncated string.
        """
        sanitizer = get_pii_sanitizer()
        context = PiiContext.create(PII_STAGE_AUDIT_PAYLOAD, None, None, None, None)
        return sanitizer.sanitize_text(value, context, max_chars)

    @classmethod
    def sanitize_payload(cls, payload: Dict[str, Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Scrub secrets, PII, @Masked fields, and truncate oversized strings from payload dictionary.

        Args:
            payload: Input dictionary containing audit event data or telemetry.
            *args: Optional positional arguments (max_chars, masked_fields).
            **kwargs: Optional keyword arguments (max_chars, masked_fields).

        Returns:
            Dict[str, Any]: Sanitized dictionary payload.
        """
        sanitizer = get_pii_sanitizer()
        context = PiiContext.create(PII_STAGE_AUDIT_PAYLOAD, None, None, None, None)
        return sanitizer.sanitize_payload(payload, context, *args, **kwargs)



class AuditPublisherSPI(ABC):
    """SPI interface for enterprise SIEM and audit publishers."""

    @property
    def is_immediate(self) -> bool:
        """Indicate whether events should be dispatched immediately to this publisher."""
        return False

    @abstractmethod
    def publish(self, event: AuditEvent) -> None:
        """Publish a single AuditEvent.

        Args:
            event: AuditEvent to publish.
        """
        pass

    def publish_batch(self, events: List[AuditEvent]) -> None:
        """Publish a batch of AuditEvents.

        Args:
            events: List of AuditEvents.
        """
        for event in events:
            self.publish(event)

    def flush(self) -> None:
        """Flush buffered log streams."""
        pass

    def close(self) -> None:
        """Release publisher resources."""
        pass


class ConsoleAuditLogger(AuditPublisherSPI):
    """Console logger implementation of AuditPublisherSPI."""

    def publish(self, event: AuditEvent) -> None:
        """Print audit log line to standard output.

        Args:
            event: AuditEvent to publish.
        """
        print(f"[AUDIT LOG] [{event.severity}] {event.action} by {event.subject_id} -> {event.decision} ({event.diagnostic_reason})")



class PythonLoggingAuditPublisher(AuditPublisherSPI):
    """Publishes single-line JSON log lines to Python logging logger 'audit.security.langchain'."""

    def __init__(self, logger_name: str = "audit.security.langchain"):
        """Initialize PythonLoggingAuditPublisher.

        Args:
            logger_name: Python logger name.
        """
        self.logger = logging.getLogger(logger_name)

    def publish(self, event: AuditEvent) -> None:
        """Emit sanitized JSON audit record via standard Python logger.

        Args:
            event: AuditEvent to emit.
        """
        data = AuditSanitizer.sanitize_payload(event.to_dict())
        self.logger.info(json.dumps(data))


class JsonFileAuditLogger(AuditPublisherSPI):
    """File logger writing JSON audit events to specified log path with secret masking."""

    def __init__(self, file_path: str):
        """Initialize JsonFileAuditLogger.

        Args:
            file_path: Output JSON file path.
        """
        self.file_path = file_path

    @classmethod
    def create(cls, file_path: str):
        """Factory method creating JsonFileAuditLogger.

        Args:
            file_path: Target log file path.

        Returns:
            JsonFileAuditLogger: New logger instance.
        """
        return cls(file_path=file_path)

    def publish(self, event: AuditEvent) -> None:
        """Append sanitized JSON log line to target log file.

        Args:
            event: AuditEvent to append.
        """
        sanitized_data = AuditSanitizer.sanitize_payload(event.to_dict())
        data_str = json.dumps(sanitized_data)
        dir_path = os.path.dirname(self.file_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(data_str + "\n")


class OpenTelemetryLogsPublisher(AuditPublisherSPI):
    """Emits audit events as OpenTelemetry LogRecords (optional plugin)."""

    def publish(self, event: AuditEvent) -> None:
        """Emit audit event via OpenTelemetry logging API if installed.

        Args:
            event: AuditEvent instance.
        """
        try:
            from opentelemetry._logs import get_logger
            logger = get_logger("audit.security.langchain")
            payload = AuditSanitizer.sanitize_payload(event.to_dict())
            if hasattr(logger, "emit"):
                logger.emit(payload)
            elif hasattr(logger, "log_record"):
                logger.log_record(payload)
        except Exception:
            pass


class SplunkHecPublisher(AuditPublisherSPI):
    """Batches and flushes events to Splunk HTTP Event Collector (HEC)."""

    def __init__(self, hec_url: str, token: str):
        """Initialize SplunkHecPublisher.

        Args:
            hec_url: Splunk HEC endpoint URL.
            token: Splunk HEC auth token.
        """
        self.hec_url = hec_url
        self.token = token

    def publish(self, event: AuditEvent) -> None:
        """POST audit event to Splunk HEC endpoint.

        Args:
            event: AuditEvent to transmit.
        """
        payload = {
            "event": AuditSanitizer.sanitize_payload(event.to_dict()),
            "sourcetype": "langchain:security:audit",
        }
        try:
            import urllib.request
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.hec_url,
                data=data,
                headers={"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.0):
                pass
        except Exception:
            pass


class ElasticCommonSchemaPublisher(AuditPublisherSPI):
    """Maps audit envelope directly into Elastic Common Schema (ECS) format."""

    def __init__(self, logger_name: str = "audit.security.ecs"):
        """Initialize ElasticCommonSchemaPublisher.

        Args:
            logger_name: Target Python logger name.
        """
        self.logger = logging.getLogger(logger_name)

    def publish(self, event: AuditEvent) -> None:
        """Format and emit event in ECS JSON structure.

        Args:
            event: AuditEvent to map and emit.
        """
        ecs_event = {
            "@timestamp": event.timestamp_utc,
            "event": {
                "id": event.event_id,
                "kind": "event",
                "category": ["iam", "access"],
                "action": event.action,
                "outcome": "success" if event.decision == "PERMIT" else "failure",
            },
            "user": {
                "id": event.subject_id,
                "roles": event.subject_roles,
            },
            "organization": {
                "id": event.tenant_id,
            },
            "service": {
                "name": "langchain-security",
            },
        }
        self.logger.info(json.dumps(ecs_event))


class AuditManager:
    """Central manager for non-blocking asynchronous audit event dispatch and ring buffer management."""

    def __init__(self, publishers: List[AuditPublisherSPI], *args: Any, **kwargs: Any):
        """Initialize AuditManager.

        Args:
            publishers: List of AuditPublisherSPI publisher implementations.
            *args: Optional positional arguments (capacity).
            **kwargs: Optional keyword arguments (capacity).
        """
        capacity = int(kwargs.get("capacity", args[0] if len(args) > 0 else DEFAULT_RING_BUFFER_CAPACITY))
        self._publishers = list(publishers)
        self._capacity = capacity
        self._buffer: deque = deque()
        self._dropped_count = 0
        self._async_queue: Optional[Any] = None
        self._lock = threading.Lock()
        self._queue_condition = threading.Condition(self._lock)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="AuditManagerAsyncWorker",
            daemon=True,
        )
        self._worker_thread.start()

    @classmethod
    def create(cls, publishers: List[AuditPublisherSPI], *args: Any, **kwargs: Any):
        """Factory method to construct AuditManager.

        Args:
            publishers: List of AuditPublisherSPI publisher implementations.
            *args: Optional positional arguments (capacity).
            **kwargs: Optional keyword arguments (capacity).

        Returns:
            AuditManager: Initialized manager instance with background async worker thread.
        """
        capacity = int(kwargs.get("capacity", args[0] if len(args) > 0 else DEFAULT_RING_BUFFER_CAPACITY))
        return cls(publishers=publishers, capacity=capacity)

    @property
    def publishers(self) -> List[AuditPublisherSPI]:
        """Get copy of registered audit publisher SPIs."""
        return list(self._publishers)

    @property
    def dropped_count(self) -> int:
        """Get count of audit events dropped due to buffer overflow."""
        with self._lock:
            return self._dropped_count

    def _worker_loop(self) -> None:
        """Background worker thread draining events asynchronously from the bounded queue."""
        while not self._stop_event.is_set():
            event = None
            with self._queue_condition:
                while not self._buffer and not self._stop_event.is_set():
                    self._queue_condition.wait(timeout=0.1)
                if self._buffer:
                    event = self._buffer.popleft()
            if event is not None:
                self._dispatch_to_publishers(event)

        # Drain remaining events on shutdown
        while True:
            event = None
            with self._lock:
                if self._buffer:
                    event = self._buffer.popleft()
            if event is None:
                break
            self._dispatch_to_publishers(event)

    def _dispatch_to_publishers(self, event: AuditEvent) -> None:
        """Dispatch event to registered publishers catching exceptions safely."""
        for pub in self._publishers:
            if not getattr(pub, "is_immediate", False):
                try:
                    pub.publish(event)
                except Exception:
                    pass

    def record_event(self, event: AuditEvent) -> None:
        """Execute in-flight sanitization and non-blocking dispatch to ring buffer.

        Args:
            event: AuditEvent instance to sanitize and record.
        """
        if get_pii_scope() != PII_SCOPE_DISABLED:
            ctx = PiiContext.create(
                PII_STAGE_AUDIT_PAYLOAD,
                event.tenant_id,
                event.subject_id,
                event.target_resource,
                {"action": event.action, "enforcement_point": event.enforcement_point},
            )
            sanitizer = get_pii_sanitizer()
            if isinstance(event.payload_snapshot, dict):
                event.payload_snapshot = sanitizer.sanitize_payload(event.payload_snapshot, ctx)
            if isinstance(event.diagnostic_reason, str):
                event.diagnostic_reason = sanitizer.sanitize_text(event.diagnostic_reason, ctx, DEFAULT_PAYLOAD_MAX_CHARS)

        # Immediate dispatch for synchronous publishers (e.g. test collectors)
        for pub in self._publishers:
            if getattr(pub, "is_immediate", False):
                try:
                    pub.publish(event)
                except Exception:
                    pass

        with self._queue_condition:
            if len(self._buffer) >= self._capacity:
                self._buffer.popleft()  # DROP_OLDEST_WITH_METRIC
                self._dropped_count += 1
            self._buffer.append(event)
            self._queue_condition.notify()

        if self._async_queue:
            try:
                self._async_queue.put_nowait(event)
            except Exception:
                pass

    def publish(self, event: AuditEvent) -> None:
        """Alias for record_event.

        Args:
            event: AuditEvent instance.
        """
        self.record_event(event)

    def flush(self) -> None:
        """Flush queued events and all registered audit publishers."""
        # Wait until internal bounded buffer is completely drained by worker thread
        deadline = time.time() + 2.0
        while time.time() < deadline:
            with self._lock:
                if not self._buffer:
                    break
            time.sleep(0.005)

        for pub in self._publishers:
            try:
                pub.flush()
            except Exception:
                pass

    def close(self) -> None:
        """Flush and close all registered audit publishers, stopping worker thread."""
        self._stop_event.set()
        with self._queue_condition:
            self._queue_condition.notify_all()
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)

        self.flush()
        for pub in self._publishers:
            try:
                pub.close()
            except Exception:
                pass



