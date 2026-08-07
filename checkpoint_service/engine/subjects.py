"""Subject registry -- maps real identifiers to opaque token subjects.

PRD 8.6 requires opaque identifiers wherever a token crosses a trust boundary,
and salted hashing of any human-linked value that is persisted. PRD Section 5's
example payload contradicts this by embedding ``"human:jalp"`` directly. The
privacy rule wins: tokens carry ``human:<uuid>`` / ``agent:<uuid>``, and this
table holds the access-controlled mapping used for dashboard display.

The mapping is keyed on ``sha256(identifier + salt)``, so the same logical agent
always resolves to the same opaque subject id across calls -- delegation trees
stay coherent without the raw name ever entering a token.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from checkpoint_service.models.audit import SubjectMap
from checkpoint_service.utils import hash_identifier


class SubjectRegistry:
    def __init__(self, salt: str, settings=None) -> None:
        self._salt = salt
        # Optional so the registry stays usable standalone; when present, exempt
        # raw identifiers get their resolved opaque subject id registered so the
        # guardrail allowlist can match on what actually appears in tokens.
        self._settings = settings

    def hash_of(self, identifier: str) -> str:
        return hash_identifier(identifier, self._salt)

    def resolve_or_create(
        self, session: Session, identifier: str, kind: str
    ) -> SubjectMap:
        """Return the existing mapping for ``identifier`` or create one.

        Handles the concurrent-insert race by retrying the lookup once after an
        IntegrityError, so two simultaneous first-delegations to the same agent
        converge on one subject id instead of one request failing.
        """
        if kind not in {"human", "agent"}:
            raise ValueError(f"unsupported subject kind: {kind!r}")

        digest = self.hash_of(identifier)
        existing = session.scalar(
            select(SubjectMap).where(
                SubjectMap.identifier_hash == digest, SubjectMap.kind == kind
            )
        )
        if existing is not None:
            self._note_exempt(identifier, existing.subject_id)
            return existing

        record = SubjectMap(
            subject_id=f"{kind}:{uuid.uuid4()}",
            identifier_hash=digest,
            kind=kind,
            display_label=identifier,
        )
        session.add(record)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            found = session.scalar(
                select(SubjectMap).where(
                    SubjectMap.identifier_hash == digest, SubjectMap.kind == kind
                )
            )
            if found is None:  # pragma: no cover - should be unreachable
                raise
            self._note_exempt(identifier, found.subject_id)
            return found
        self._note_exempt(identifier, record.subject_id)
        return record

    def _note_exempt(self, identifier: str, subject_id: str) -> None:
        if self._settings is not None:
            self._settings.register_exempt_subject(identifier, subject_id)

    def label_for(self, session: Session, subject_id: str) -> str | None:
        """Human-readable label for an opaque subject id (dashboard only)."""
        record = session.get(SubjectMap, subject_id)
        return record.display_label if record else None

    def labels_for(self, session: Session, subject_ids: list[str]) -> dict[str, str]:
        """Bulk label lookup, one query, for rendering trees and audit tables."""
        if not subject_ids:
            return {}
        rows = session.scalars(
            select(SubjectMap).where(SubjectMap.subject_id.in_(set(subject_ids)))
        ).all()
        return {row.subject_id: row.display_label for row in rows}
