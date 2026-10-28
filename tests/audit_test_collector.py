"""
Test-only audit collector fixture for testing audit event pipelines.
"""

from typing import List
from langchain_security_extension.security_core.audit import AuditEvent, AuditPublisherSPI


class TestAuditCollector(AuditPublisherSPI):
    """In-memory collector for audit events, strictly for unit tests."""

    __test__ = False

    def __init__(self):
        self._events: List[AuditEvent] = []

    @property
    def is_immediate(self) -> bool:
        return True

    @classmethod
    def create(cls) -> "TestAuditCollector":
        return cls()

    def publish(self, event: AuditEvent) -> None:
        self._events.append(event)

    def get_events(self) -> List[AuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()
