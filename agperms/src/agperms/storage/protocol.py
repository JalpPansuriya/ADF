"""The storage contract every backend must satisfy.

Design notes
------------
**One lifecycle pattern, not two.** Every method here is unit-atomic: the caller
hands over a complete operation and the backend is responsible for making it
durable before returning. There is no ``begin()``/``commit()`` in this protocol.
That is a deliberate narrowing versus the service this library was extracted
from, where some engines received a session per call and one owned its own
transaction -- two lifecycles that an in-memory backend cannot implement
coherently. The cost is that a few multi-row operations get their own dedicated
method (:meth:`revoke_many`, :meth:`append_audit_batch`) so the backend can still
make them atomic internally.

**Fail closed is part of the contract, not the implementation.**
:meth:`is_revoked` must never answer ``False`` because it could not reach its
data. If a backend cannot determine the answer it must raise
:class:`~agperms.errors.StorageError`. Returning "probably fine" at exactly the
moment the store is broken is the failure mode this whole library exists to
prevent.

**Ordering is observable.** :meth:`descendants_breadth_first` returns
root-first, level-order, and callers surface that order to users. A backend that
returns the same set in a different order is not conforming.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Protocol, runtime_checkable

from agperms.models import (
    ActionRecord,
    ActionReview,
    CompletionState,
    PendingApproval,
    Subject,
    TokenMetadata,
)


@runtime_checkable
class Storage(Protocol):
    """Persistence operations required by :class:`agperms.Firewall`."""

    # ------------------------------------------------------------------
    # Token metadata
    # ------------------------------------------------------------------
    def put_token(self, metadata: TokenMetadata) -> None:
        """Record a freshly minted token.

        ``jti`` is unique. Re-inserting the same ``jti`` is a programming error
        and should raise :class:`~agperms.errors.StorageError`.
        """
        ...

    def get_token(self, jti: str) -> TokenMetadata | None:
        """Look up token metadata, or ``None`` if unknown."""
        ...

    # ------------------------------------------------------------------
    # Delegation edges
    # ------------------------------------------------------------------
    def add_edge(self, parent_jti: str, child_jti: str) -> None:
        """Record a parent -> child delegation.

        Inserting a duplicate pair must be a safe no-op, not an error: the mint
        path may retry, and a duplicate carries no new information.
        """
        ...

    def children_of(self, parent_jtis: list[str]) -> list[str]:
        """Direct children of every jti in ``parent_jtis``, one call.

        Batched per level so a deep tree costs one call per level rather than one
        per node.
        """
        ...

    def descendants_breadth_first(self, root_jti: str) -> list[str]:
        """``root_jti`` followed by every descendant, in level order.

        Must be cycle-safe. The ordering is user-visible, so it is part of the
        contract rather than an implementation detail.
        """
        ...

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def is_revoked(self, jti: str) -> bool:
        """Whether ``jti`` has been revoked.

        Must raise :class:`~agperms.errors.StorageError` rather than returning
        ``False`` if the answer cannot be determined. Fail closed.
        """
        ...

    def revoked_among(self, jtis: list[str]) -> set[str]:
        """Which of ``jtis`` are already revoked. Bulk form of :meth:`is_revoked`."""
        ...

    def revoke_many(
        self,
        jtis: list[str],
        *,
        root_of_revocation: str,
        reason: str | None,
        revoked_at: _dt.datetime,
    ) -> list[str]:
        """Revoke every jti in ``jtis`` atomically.

        Returns the subset that was not already revoked. Partially revoking a
        subtree would leave live tokens an operator believes are dead, so this
        must be all-or-nothing.
        """
        ...

    # ------------------------------------------------------------------
    # Subjects (opaque id <-> salted hash)
    # ------------------------------------------------------------------
    def get_or_create_subject(
        self, *, identifier_hash: str, kind: str, display_label: str
    ) -> Subject:
        """Resolve a subject, creating it on first sight.

        Must be atomic get-or-create: two concurrent first-time resolutions of
        the same identifier converge on one ``subject_id`` rather than creating
        duplicates or raising.
        """
        ...

    def get_subject(self, subject_id: str) -> Subject | None:
        ...

    def get_subjects(self, subject_ids: list[str]) -> dict[str, Subject]:
        """Bulk subject lookup, one call."""
        ...

    # ------------------------------------------------------------------
    # Audit log (hash chain)
    # ------------------------------------------------------------------
    def audit_tail_hash(self) -> str | None:
        """``row_hash`` of the most recently appended row, or ``None`` if empty.

        Must reflect true insertion order, not any external timestamp.
        """
        ...

    def append_audit_batch(self, rows: list[dict[str, Any]]) -> None:
        """Append pre-hashed rows in order, atomically.

        Each row already carries ``prev_hash`` and ``row_hash``; the backend must
        not recompute them. Appending must preserve the given order.
        """
        ...

    def iter_audit_rows(self) -> list[dict[str, Any]]:
        """Every audit row in insertion order, for integrity verification."""
        ...

    def find_audit_rows(
        self,
        *,
        action: str | None = None,
        jti: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Filtered audit query, newest first when ``limit`` is applied."""
        ...

    def count_audit_rows(self) -> int:
        ...

    # ------------------------------------------------------------------
    # Pending approvals
    # ------------------------------------------------------------------
    def put_approval(self, approval: PendingApproval) -> None:
        ...

    def get_approval(self, approval_id: str) -> PendingApproval | None:
        ...

    def update_approval(self, approval: PendingApproval) -> None:
        """Replace an existing approval record wholesale (update-by-id)."""
        ...

    def list_approvals(self, *, status: str | None = None) -> list[PendingApproval]:
        ...

    # ------------------------------------------------------------------
    # In-flight actions
    # ------------------------------------------------------------------
    def put_action(self, action: ActionRecord) -> None:
        """Record that an action has opened."""
        ...

    def close_action(
        self,
        action_id: str,
        *,
        state: CompletionState,
        finished_at: _dt.datetime,
        failure_reason: str | None,
    ) -> ActionRecord | None:
        """Mark an action finished. Returns the updated record, or ``None``."""
        ...

    def get_action(self, action_id: str) -> ActionRecord | None:
        ...

    def actions_for_review(self, jtis: list[str]) -> list[ActionRecord]:
        """Actions on ``jtis`` that a human should look at.

        That means anything not cleanly completed: still open (its fate is
        unknown) or closed as PARTIAL (it started, then raised). Cleanly
        completed actions are excluded -- there is nothing to review.

        Deliberately broader than "still open": when you pull an agent's
        capability you want everything questionable it did, not only whatever
        happened to be executing in that exact microsecond.
        """
        ...

    # ------------------------------------------------------------------
    # Review queue
    # ------------------------------------------------------------------
    def put_review(self, review: ActionReview) -> None:
        ...

    def get_review(self, review_id: str) -> ActionReview | None:
        ...

    def update_review(self, review: ActionReview) -> None:
        ...

    def list_reviews(self, *, reviewed: bool | None = None) -> list[ActionReview]:
        ...

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        """Release any resources. Must be idempotent."""
        ...


__all__ = ["Storage"]
