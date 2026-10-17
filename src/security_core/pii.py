"""
PII & Sensitive Data Sanitization Module.

Provides:
- PiiSanitizerSPI: Abstract Service Provider Interface for pluggable PII & secret redactors.
- BuiltInPiiSanitizer: Default zero-dependency high-performance regex & Luhn-verified scrubber.
- PiiContext: Lifecycle context tracking execution stage and tenant/subject metadata.
- Registry functions: get_pii_sanitizer, set_pii_sanitizer, get_pii_scope, set_pii_scope.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple
import re

from security_core.constants import (
    DEFAULT_PAYLOAD_MAX_CHARS,
    DEFAULT_PII_REDACTION_SCOPE,
    DEFAULT_REDACTION_TOKEN,
    DEFAULT_SENSITIVE_FIELD_NAMES,
    PII_SCOPE_AUDIT_ONLY,
    PII_SCOPE_DISABLED,
    PII_SCOPE_FULL_IN_FLIGHT,
    PII_STAGE_AUDIT_PAYLOAD,
    PII_STAGE_INBOUND_PROMPT,
    PII_STAGE_OUTBOUND_RESPONSE,
    PII_STAGE_RETRIEVAL_DOCUMENT,
    PII_STAGE_TOOL_ARGUMENT,
    PII_STAGE_TOOL_OUTPUT,
    PHONE_CONTEXT_WINDOW_CHARS,
    DEFAULT_PHONE_HINT_PATTERN,
)

DEFAULT_MAX_CHARS: int = DEFAULT_PAYLOAD_MAX_CHARS
DEFAULT_SCOPE: str = DEFAULT_PII_REDACTION_SCOPE
REDACTED_TOKEN: str = DEFAULT_REDACTION_TOKEN
TRUNCATED_SUFFIX: str = "...[TRUNCATED]"


def is_valid_luhn(card_number_str: str) -> bool:
    """Validate candidate credit/debit card number using the Luhn checksum algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PiiContext:
    """Contextual metadata passed during PII sanitization lifecycle stages."""

    def __init__(
        self,
        stage: str,
        tenant_id: Optional[str],
        subject_id: Optional[str],
        resource_id: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ):
        self.stage = stage
        self.tenant_id = tenant_id
        self.subject_id = subject_id
        self.resource_id = resource_id
        self.metadata = dict(metadata) if metadata is not None else {}

    @classmethod
    def create(cls, stage: str, *args: Any, **kwargs: Any) -> "PiiContext":
        """Factory method to construct a PiiContext.

        Args:
            stage: Target execution lifecycle stage.
            *args: Optional positional arguments (tenant_id, subject_id, resource_id, metadata).
            **kwargs: Optional keyword arguments.

        Returns:
            PiiContext: New context instance.
        """
        tenant_id = kwargs.get("tenant_id", args[0] if len(args) > 0 else None)
        subject_id = kwargs.get("subject_id", args[1] if len(args) > 1 else None)
        resource_id = kwargs.get("resource_id", args[2] if len(args) > 2 else None)
        metadata = kwargs.get("metadata", args[3] if len(args) > 3 else None)
        return cls(stage, tenant_id, subject_id, resource_id, metadata)


class PiiSanitizerSPI(ABC):
    """Abstract Service Provider Interface for PII and Secret Redaction engines."""

    @abstractmethod
    def sanitize_text(
        self,
        text: str,
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Sanitize sensitive entities in raw text strings.

        Args:
            text: Input string to inspect and sanitize.
            context: Optional contextual information for the sanitization stage.
            *args: Optional positional arguments (e.g. max_chars).
            **kwargs: Optional keyword arguments.

        Returns:
            Sanitized string with sensitive data redacted.
        """
        pass

    @abstractmethod
    def sanitize_payload(
        self,
        payload: Dict[str, Any],
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Recursively sanitize a dictionary payload.

        Args:
            payload: Input dictionary to sanitize.
            context: Optional contextual information for the sanitization stage.
            *args: Optional positional overrides (max_chars, masked_fields).
            **kwargs: Optional keyword overrides.

        Returns:
            Sanitized dictionary with sensitive values redacted.
        """
        pass


class BuiltInPiiSanitizer(PiiSanitizerSPI):
    """Default zero-dependency high-performance PII and credential scrubber.

    Performs 3-stage sanitization:
    - Stage 1: Key-name masking for sensitive dictionary parameters.
    - Stage 2: Comprehensive regex matching for emails, phones, SSNs, credit cards (with Luhn),
               cloud credentials (AWS, Google, GitHub, Slack), JWTs, DB URIs, and private keys.
    - Stage 3: Payload size truncation to prevent log bloat.
    """

    COMBINED_SECRET_REGEX = re.compile(
        r'(?P<db_uri>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/]+:[^@\s/]+@[^\s,\'"]+)'
        r'|(?P<kv_secret>(?:bearer[\s=]+[^\s,\'"]+|password\s*[:=]\s*[^\s,\'"]+|secret\s*[:=]\s*[^\s,\'"]+|token\s*[:=]\s*[^\s,\'"]+|api[_\-]?key\s*[:=]\s*[^\s,\'"]+|aws[_\-]?key\s*[:=]\s*[^\s,\'"]+))'
        r'|(?P<jwt>eyJ[a-zA-Z0-9_\-]{5,}\.eyJ[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{5,})'
        r'|(?P<aws_key>(?:AKIA|ASIA)[0-9A-Z]{16})'
        r'|(?P<google_key>AIza[-0-9A-Za-z_]{35})'
        r'|(?P<github_token>gh[pousr]_[A-Za-z0-9_]{36,255})'
        r'|(?P<slack_token>xox[baprs]-[-0-9A-Za-z]{10,72})'
        r'|(?P<private_key>-----BEGIN [A-Z\s]+ PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END [A-Z\s]+ PRIVATE KEY-----)'
        r'|(?P<email>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b)'
        r'|(?P<ipv4>\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)'
        r'|(?P<ssn>\b\d{3}[-\s]\d{2}[-\s]\d{4}\b)'
        r'|(?P<card>\b(?:\d{4}[-\s]?){3}\d{1,7}\b|\b\d{13,19}\b)'
        r'|(?P<phone>(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\b\d{3}[-.\s])\d{3}[-.\s]\d{4}\b|\b\d{10}\b)',
        re.IGNORECASE,
    )

    PHONE_HINT_REGEX = re.compile(DEFAULT_PHONE_HINT_PATTERN, re.IGNORECASE)


    def __init__(self, *args: Any, **kwargs: Any):
        masked_fields = kwargs.get("masked_fields", args[0] if len(args) > 0 else ())
        self._registered_masked_fields: Set[str] = {
            str(f).lower().strip() for f in DEFAULT_SENSITIVE_FIELD_NAMES
        }
        if masked_fields:
            for field in masked_fields:
                self.register_masked_field(str(field))

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "BuiltInPiiSanitizer":
        """Factory method to construct a BuiltInPiiSanitizer."""
        return cls(*args, **kwargs)

    def register_masked_field(self, field_name: str) -> None:
        """Register a parameter or field name for automatic Stage 1 dictionary masking."""
        if field_name:
            self._registered_masked_fields.add(field_name.lower().strip())

    def is_masked_field(self, field_name: str) -> bool:
        """Check if a field name is marked as sensitive/masked."""
        return bool(field_name and field_name.lower().strip() in self._registered_masked_fields)

    def _redact_match(self, match: re.Match, full_text: str) -> str:
        group_dict = match.groupdict()
        text = match.group(0)

        if group_dict.get("db_uri"):
            scheme_user = text.split(":", 2)
            at_part = text.split("@", 1)[1]
            return f"{scheme_user[0]}:{scheme_user[1]}:{REDACTED_TOKEN}@{at_part}"

        if group_dict.get("kv_secret"):
            if "=" in text:
                prefix = text.split("=")[0]
                return f"{prefix}={REDACTED_TOKEN}"
            elif ":" in text:
                prefix = text.split(":")[0]
                return f"{prefix}: {REDACTED_TOKEN}"
            elif text.lower().startswith("bearer "):
                return f"bearer {REDACTED_TOKEN}"
            return REDACTED_TOKEN

        if group_dict.get("card"):
            digits = "".join(c for c in text if c.isdigit())
            if is_valid_luhn(digits):
                return REDACTED_TOKEN
            return text

        if group_dict.get("phone"):
            digits = "".join(c for c in text if c.isdigit())
            # For 10-digit numbers lacking phone formatting delimiters, require proximity to phone/fone keywords
            if len(digits) == 10 and not any(c in text for c in "-. ()+"):
                start_idx = max(0, match.start() - PHONE_CONTEXT_WINDOW_CHARS)
                end_idx = min(len(full_text), match.end() + PHONE_CONTEXT_WINDOW_CHARS)
                window = full_text[start_idx:end_idx]
                if not self.PHONE_HINT_REGEX.search(window):
                    return text
            return REDACTED_TOKEN

        return REDACTED_TOKEN

    def sanitize_text(
        self,
        text: str,
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Sanitize sensitive entities in raw text strings."""
        max_chars = int(kwargs.get("max_chars", args[0] if len(args) > 0 else DEFAULT_PAYLOAD_MAX_CHARS))
        cleaned = self.COMBINED_SECRET_REGEX.sub(lambda m: self._redact_match(m, text), text)
        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars] + TRUNCATED_SUFFIX
        return cleaned

    def sanitize_payload(
        self,
        payload: Dict[str, Any],
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Recursively sanitize a dictionary payload."""
        max_chars = int(kwargs.get("max_chars", args[0] if len(args) > 0 else DEFAULT_PAYLOAD_MAX_CHARS))
        extra_masked = set(kwargs.get("masked_fields", args[1] if len(args) > 1 else ()))
        masked_lower = {str(f).lower() for f in extra_masked} | self._registered_masked_fields

        sanitized: Dict[str, Any] = {}
        for k, v in payload.items():
            if str(k).lower() in masked_lower:
                sanitized[k] = REDACTED_TOKEN
            elif isinstance(v, str):
                sanitized[k] = self.sanitize_text(v, context, max_chars)
            elif isinstance(v, dict):
                sanitized[k] = self.sanitize_payload(v, context, max_chars, extra_masked)
            elif isinstance(v, list):
                sanitized[k] = [
                    self.sanitize_payload(item, context, max_chars, extra_masked)
                    if isinstance(item, dict)
                    else (self.sanitize_text(item, context, max_chars) if isinstance(item, str) else item)
                    for item in v
                ]
            else:
                sanitized[k] = v
        return sanitized


# Global PII Sanitizer Registry
_CURRENT_PII_SANITIZER: Optional[PiiSanitizerSPI] = None
_CURRENT_PII_SCOPE: str = DEFAULT_PII_REDACTION_SCOPE


def get_pii_sanitizer() -> PiiSanitizerSPI:
    """Retrieve the globally registered PiiSanitizerSPI instance, defaulting to BuiltInPiiSanitizer."""
    global _CURRENT_PII_SANITIZER
    if _CURRENT_PII_SANITIZER is None:
        _CURRENT_PII_SANITIZER = BuiltInPiiSanitizer()
    return _CURRENT_PII_SANITIZER


def set_pii_sanitizer(sanitizer: PiiSanitizerSPI) -> None:
    """Register a custom PiiSanitizerSPI instance globally."""
    global _CURRENT_PII_SANITIZER
    _CURRENT_PII_SANITIZER = sanitizer


def reset_pii_sanitizer() -> None:
    """Reset global PII sanitizer back to default BuiltInPiiSanitizer."""
    global _CURRENT_PII_SANITIZER
    _CURRENT_PII_SANITIZER = None


def get_pii_scope() -> str:
    """Retrieve active PII redaction scope ('audit_only', 'full_in_flight', or 'disabled')."""
    global _CURRENT_PII_SCOPE
    return _CURRENT_PII_SCOPE


def set_pii_scope(scope: str) -> None:
    """Set active PII redaction scope ('audit_only', 'full_in_flight', or 'disabled')."""
    global _CURRENT_PII_SCOPE
    _CURRENT_PII_SCOPE = scope


def reset_pii_scope() -> None:
    """Reset active PII redaction scope back to DEFAULT_PII_REDACTION_SCOPE ('audit_only')."""
    global _CURRENT_PII_SCOPE
    _CURRENT_PII_SCOPE = DEFAULT_PII_REDACTION_SCOPE
