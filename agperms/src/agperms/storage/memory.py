"""In-memory storage: the zero-dependency default.

Everything lives in Python dicts behind a single reentrant lock. This is what
makes ``pip install agperms`` followed by ``Firewall()`` work with no database,
no cache, and no configuration.

What you give up
----------------
State dies with the process. A revoked token is revoked only for as long as this
object lives, so a restart resurrects it. That is acceptable for tests, notebooks,
CLI tools and single-process embedding, and unacceptable for anything where a
revocation has to outlive a deploy -- use ``SqlStorage`` there.

This is stated plainly rather than buried: the library's central promise is that
revocation is trustworthy, and the in-memory backend cannot keep that promise
across a restart.
"""

from __future__ import annotations

import datetime as _dt
import threading
import uuid
from collections import deque
from copy import deepcopy
from typing import Any

from agperms.errors import StorageError
from agperms.models import (
    ActionRecord,
    ActionReview,
    CompletionState,
    PendingApproval,
    Subject,
    TokenMetadata,
)


class MemoryStorage:
    """Process-local storage. Fast, dependency-free, and not durable."""

    #: Advertised so callers (and the Firewall's own warnings) can reason about
    #: durability without isinstance checks against a concrete class.
    durable = False

    def __init__(self) -> None:
        # Reentrant because a few operations legitimately nest (revoke_many walks
        # edges, which takes the same lock).
        self._lock = threading.RLock()
        self._tokens: dict[str, TokenMetadata] = {}
        self._edges: dict[str, list[str]] = {}
        self._revoked: dict[str, dict[str, Any]] = {}
        self._subjects: dict[str, Subject] = {}
        self._subject_by_hash: dict[tuple[str, str], str] = {}
        self._audit: list[dict[str, Any]] = []
        self._approvals: dict[str, PendingApproval] = {}
        self._actions: dict[str, ActionRecord] = {}
        self._actions_by_jti: dict[str, list[str]] = {}
        self._reviews: dict[str, ActionReview] = {}
        self._closed = False

    # ------------------------------------------------------------------
    # Token metadata
    # ------------------------------------------------------------------
    def put_token(self, metadata: TokenMetadata) -> None:
        with self._lock:
            if metadata.jti in self._tokens:
                raise StorageError(f"token {metadata.jti} already recorded")
            self._tokens[metadata.jti] = deepcopy(metadata)

    def get_token(self, jti: str) -> TokenMetadata | None:
        with self._lock:
            found = self._tokens.get(jti)
            return deepcopy(found) if found else None

    # ------------------------------------------------------------------
    # Delegation edges
    # ------------------------------------------------------------------
    def add_edge(self, parent_jti: str, child_jti: str) -> None:
        with self._lock:
            children = self._edges.setdefault(parent_jti, [])
            if child_jti not in children:  # duplicate insert is a no-op
                children.append(child_jti)

    def children_of(self, parent_jtis: list[str]) -> list[str]:
        with self._lock:
            out: list[str] = []
            for parent in parent_jtis:
                out.extend(self._edges.get(parent, ()))
            return out

    def descendants_breadth_first(self, root_jti: str) -> list[str]:
        with self._lock:
            seen = {root_jti}
            order = [root_jti]
            queue: deque[str] = deque([root_jti])
            while queue:
                level = list(queue)
                queue.clear()
                for child in self.children_of(level):
                    if child not in seen:
                        seen.add(child)
                        order.append(child)
                        queue.append(child)
            return order

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            if self._closed:
                # Fail closed: a closed store cannot answer, so it must not
                # answer "not revoked".
                raise StorageError("storage is closed; cannot answer is_revoked")
            return jti in self._revoked

    def revoked_among(self, jtis: list[str]) -> set[str]:
        with self._lock:
            return {jti for jti in jtis if jti in self._revoked}

    def revoke_many(
        self,
        jtis: list[str],
        *,
        root_of_revocation: str,
        reason: str | None,
        revoked_at: _dt.datetime,
    ) -> list[str]:
        with self._lock:
            newly: list[str] = []
            for jti in jtis:
                if jti in self._revoked:
                    continue
                self._revoked[jti] = {
                    "jti": jti,
                    "revoked_at": revoked_at,
                    "root_of_revocation": root_of_revocation,
                    "reason": reason,
                }
                newly.append(jti)
            return newly

    # ------------------------------------------------------------------
    # Subjects
    # ------------------------------------------------------------------
    def get_or_create_subject(
        self, *, identifier_hash: str, kind: str, display_label: str
    ) -> Subject:
        key = (identifier_hash, kind)
        with self._lock:
            existing_id = self._subject_by_hash.get(key)
            if existing_id is not None:
                return deepcopy(self._subjects[existing_id])
            subject = Subject(
                subject_id=f"{kind}:{uuid.uuid4()}",
                identifier_hash=identifier_hash,
                kind=kind,
                display_label=display_label,
            )
            self._subjects[subject.subject_id] = subject
            self._subject_by_hash[key] = subject.subject_id
            return deepcopy(subject)

    def get_subject(self, subject_id: str) -> Subject | None:
        with self._lock:
            found = self._subjects.get(subject_id)
            return deepcopy(found) if found else None

    def get_subjects(self, subject_ids: list[str]) -> dict[str, Subject]:
        with self._lock:
            return {
                sid: deepcopy(self._subjects[sid])
                for sid in set(subject_ids)
                if sid in self._subjects
            }

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------
    def audit_tail_hash(self) -> str | None:
        with self._lock:
            return self._audit[-1]["row_hash"] if self._audit else None

    def append_audit_batch(self, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            next_id = len(self._audit) + 1
            for offset, row in enumerate(rows):
                stored = deepcopy(row)
                stored["id"] = next_id + offset
                self._audit.append(stored)

    def iter_audit_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return [deepcopy(row) for row in self._audit]

    def find_audit_rows(
        self,
        *,
        action: str | None = None,
        jti: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            matches = [
                deepcopy(row)
                for row in self._audit
                if (action is None or row.get("action") == action)
                and (jti is None or row.get("jti") == jti)
            ]
        if limit is not None:
            return list(reversed(matches))[:limit]
        return matches

    def count_audit_rows(self) -> int:
        with self._lock:
            return len(self._audit)

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------
    def put_approval(self, approval: PendingApproval) -> None:
        with self._lock:
            self._approvals[approval.approval_id] = approval

    def get_approval(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._approvals.get(approval_id)

    def update_approval(self, approval: PendingApproval) -> None:
        with self._lock:
            if approval.approval_id not in self._approvals:
                raise StorageError(f"unknown approval {approval.approval_id}")
            self._approvals[approval.approval_id] = approval

    def list_approvals(self, *, status: str | None = None) -> list[PendingApproval]:
        with self._lock:
            found = list(self._approvals.values())
        if status is not None:
            found = [a for a in found if a.status == status]
        return sorted(found, key=lambda a: a.created_at, reverse=True)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def put_action(self, action: ActionRecord) -> None:
        with self._lock:
            if action.action_id in self._actions:
                raise StorageError(f"action {action.action_id} already recorded")
            self._actions[action.action_id] = action
            self._actions_by_jti.setdefault(action.jti, []).append(action.action_id)

    def close_action(
        self,
        action_id: str,
        *,
        state: CompletionState,
        finished_at: _dt.datetime,
        failure_reason: str | None,
    ) -> ActionRecord | None:
        with self._lock:
            existing = self._actions.get(action_id)
            if existing is None:
                return None
            # ActionRecord is frozen; replace it wholesale.
            updated = ActionRecord(
                action_id=existing.action_id,
                jti=existing.jti,
                subject_id=existing.subject_id,
                name=existing.name,
                scope=existing.scope,
                started_at=existing.started_at,
                finished_at=finished_at,
                state=state,
                failure_reason=failure_reason,
                reversibility=existing.reversibility,
            )
            self._actions[action_id] = updated
            return updated

    def get_action(self, action_id: str) -> ActionRecord | None:
        with self._lock:
            return self._actions.get(action_id)

    def actions_for_review(self, jtis: list[str]) -> list[ActionRecord]:
        with self._lock:
            out: list[ActionRecord] = []
            for jti in jtis:
                for action_id in self._actions_by_jti.get(jti, ()):
                    action = self._actions.get(action_id)
                    if action is None:
                        continue
                    # Open (fate unknown) or closed PARTIAL. A cleanly completed
                    # action has nothing to review.
                    if action.is_open or action.state is not CompletionState.CLEAN:
                        out.append(action)
            return sorted(out, key=lambda a: a.started_at)

    # ------------------------------------------------------------------
    # Reviews
    # ------------------------------------------------------------------
    def put_review(self, review: ActionReview) -> None:
        with self._lock:
            self._reviews[review.review_id] = review

    def get_review(self, review_id: str) -> ActionReview | None:
        with self._lock:
            return self._reviews.get(review_id)

    def update_review(self, review: ActionReview) -> None:
        with self._lock:
            if review.review_id not in self._reviews:
                raise StorageError(f"unknown review {review.review_id}")
            self._reviews[review.review_id] = review

    def list_reviews(self, *, reviewed: bool | None = None) -> list[ActionReview]:
        with self._lock:
            found = list(self._reviews.values())
        if reviewed is not None:
            found = [r for r in found if r.reviewed is reviewed]
        return sorted(found, key=lambda r: r.revoked_at, reverse=True)

    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            self._closed = True


__all__ = ["MemoryStorage"]
