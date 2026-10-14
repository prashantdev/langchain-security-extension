"""
Prompt Injection and Jailbreak Security Scanner Subsystem.

Detects direct prompt injection, system instruction overrides, and jailbreak signatures
as specified in Spec 5.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from security_core.audit import AuditManager, AuditEvent
from security_core.constants import (
    EVENT_PROMPT_INJECTION_DETECTED,
    EVENT_INSTRUCTION_OVERRIDE_ATTEMPT,
    PEP_AGENT_GUARD,
    PEP_TOOL_INTERCEPTOR,
    SEVERITY_CRITICAL_ALERT,
    SEVERITY_SECURITY_ALERT,
    STRATEGY_HARD_ABORT,
)


class PromptInjectionScanResult:
    """Scan outcome envelope indicating injection status, confidence score, and pattern ID.

    Attributes:
        is_detected (bool): True if prompt injection pattern was identified.
        pattern_id (Optional[str]): Identifier of matched rule pattern.
        threat_score (float): Confidence score of detected threat (0.0 to 1.0).
        threat_category (str): Threat classification label.
        detected_text (Optional[str]): Matched text snippet.
    """

    def __init__(
        self,
        is_detected: bool,
        pattern_id: Optional[str] = None,
        threat_score: float = 0.0,
        threat_category: str = "PROMPT_INJECTION",
        detected_text: Optional[str] = None,
    ):
        """Initialize PromptInjectionScanResult.

        Args:
            is_detected: Flag indicating threat detection.
            pattern_id: Pattern identifier.
            threat_score: Threat confidence score.
            threat_category: Threat category string.
            detected_text: Snippet of matched input text.
        """
        self.is_detected = is_detected
        self.pattern_id = pattern_id
        self.threat_score = threat_score
        self.threat_category = threat_category
        self.detected_text = detected_text


class PromptInjectionScanner:
    """Rule-based heuristic scanner for prompt injection, jailbreak, and instruction overrides."""

    INJECTION_PATTERNS = [
        (
            "JAILBREAK_SYSTEM_OVERRIDE",
            re.compile(
                r"(ignore\s+all\s+(previous|prior)\s+instructions|disregard\s+(all\s+)?previous\s+rules|system\s*:\s*you\s+are\s+now|forget\s+your\s+safety\s+guidelines)",
                re.IGNORECASE,
            ),
            0.95,
        ),
        (
            "ROLEPLAY_DAN_EVASION",
            re.compile(
                r"(do\s+anything\s+now|dan\s+mode|jailbroken|unrestricted\s+ai|act\s+as\s+an\s+unfiltered)",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            "INSTRUCTION_HIJACKING",
            re.compile(
                r"(\[system\]|###\s*instruction|override_policy\s*=\s*true|<\|im_start\|>system)",
                re.IGNORECASE,
            ),
            0.90,
        ),
    ]
    """Pre-compiled regular expression rules and confidence weights for injection scanning."""

    def __init__(self, audit_manager: Optional[AuditManager] = None):
        """Initialize PromptInjectionScanner.

        Args:
            audit_manager: Optional AuditManager for recording injection alerts.
        """
        self._audit_manager = audit_manager

    @classmethod
    def create(cls, audit_manager: Optional[AuditManager] = None):
        """Factory method to construct PromptInjectionScanner.

        Args:
            audit_manager: Optional AuditManager instance.

        Returns:
            PromptInjectionScanner: New scanner instance.
        """
        return cls(audit_manager=audit_manager)

    def scan_text(self, text: str) -> PromptInjectionScanResult:
        """Scan input text string for prompt injection and jailbreak signatures.

        Args:
            text: Input text string to scan.

        Returns:
            PromptInjectionScanResult: Scan result containing match status and threat details.
        """
        if not text or not isinstance(text, str):
            return PromptInjectionScanResult(is_detected=False)

        for pattern_id, regex, score in self.INJECTION_PATTERNS:
            match = regex.search(text)
            if match:
                snippet = match.group(0)
                category = "INSTRUCTION_OVERRIDE" if "INSTRUCTION" in pattern_id else "PROMPT_INJECTION"
                return PromptInjectionScanResult(
                    is_detected=True,
                    pattern_id=pattern_id,
                    threat_score=score,
                    threat_category=category,
                    detected_text=snippet,
                )

        return PromptInjectionScanResult(is_detected=False)

    def scan_and_audit(
        self,
        text: str,
        subject_id: str,
        tenant_id: str,
        enforcement_point: str = PEP_AGENT_GUARD,
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> PromptInjectionScanResult:
        """Scan input text and publish audit security alert event if threat is detected.

        Args:
            text: Input text string.
            subject_id: Subject attempting execution.
            tenant_id: Tenant identifier.
            enforcement_point: Target PEP identifier string.
            context_metadata: Optional additional metadata dictionary.

        Returns:
            PromptInjectionScanResult: Scan result envelope.
        """
        result = self.scan_text(text)
        if result.is_detected and self._audit_manager:
            event_type = (
                EVENT_INSTRUCTION_OVERRIDE_ATTEMPT
                if result.threat_category == "INSTRUCTION_OVERRIDE"
                else EVENT_PROMPT_INJECTION_DETECTED
            )
            severity = (
                SEVERITY_CRITICAL_ALERT
                if result.threat_score >= 0.9
                else SEVERITY_SECURITY_ALERT
            )

            meta = dict(context_metadata) if context_metadata else {}
            meta.update({
                "detected_snippet": result.detected_text,
                "threat_score": result.threat_score,
                "pattern_id": result.pattern_id,
            })

            event = AuditEvent.create(
                subject_id=subject_id,
                tenant_id=tenant_id,
                action="prompt:scan",
                resource=enforcement_point,
                decision="BLOCKED",
                diagnostic_reason=f"Prompt injection pattern detected: '{result.pattern_id}'",
                severity=severity,
                metadata=meta,
                enforcement_point=enforcement_point,
                reason_code=event_type,
            )
            event.threat_category = result.threat_category
            event.threat_score = result.threat_score
            event.detected_pattern = result.pattern_id
            event.mitigation_action = STRATEGY_HARD_ABORT

            self._audit_manager.record_event(event)

        return result

