"""Eval item 6: audit log tamper detection.

Corrupts rows directly in the database and asserts the integrity walker names the
first broken link. This is the "tamper evidence" proof for the demo, so each test
attacks the chain a different way: field mutation, row deletion, reordering, and
hash forgery.
"""

from __future__ import annotations

from sqlalchemy import delete, select, update

from checkpoint_service.db.session import session_scope
from checkpoint_service.engine.audit_logger import GENESIS_HASH, compute_row_hash
from checkpoint_service.models.audit import AuditLog


def _rows() -> list[AuditLog]:
    with session_scope() as session:
        return list(session.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all())


class TestChainIntactWhenUntampered:
    def test_fresh_log_is_intact(self, adf):
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "agent-a", ["read_calendar"])
        adf.verify(root["token"], "read_calendar")

        result = adf.integrity()
        assert result["intact"] is True, result
        assert result["rows_checked"] >= 3
        assert result["first_broken_row_id"] is None

    def test_chain_links_are_contiguous(self, adf):
        root = adf.mint_root(["read_calendar"])
        for i in range(3):
            adf.delegate_ok(root["token"], f"agent-{i}", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        prev = GENESIS_HASH
        for row in rows:
            assert row.prev_hash == prev
            prev = row.row_hash

    def test_empty_log_is_intact(self, client, adf):
        result = adf.integrity()
        assert result["intact"] is True
        assert result["rows_checked"] == 0


class TestTamperDetection:
    """Eval item 6 -- each variant must be caught and localised."""

    def test_detects_field_mutation(self, adf):
        """Change a scope list in place: the content hash no longer matches."""
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "agent-a", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        target = rows[1]
        with session_scope() as session:
            session.execute(
                update(AuditLog)
                .where(AuditLog.id == target.id)
                .values(scopes=["read_calendar", "send_email", "spend_money"])
            )

        result = adf.integrity()
        assert result["intact"] is False
        assert result["first_broken_row_id"] == target.id
        assert "content hash mismatch" in result["detail"]

    def test_detects_decision_flip(self, adf):
        """The highest-value tamper: turning a recorded denial into an allow."""
        root = adf.mint_root(["read_calendar"])
        adf.delegate(root["token"], "greedy", ["web_search"])
        adf.flush_audit()

        rows = _rows()
        denial = [r for r in rows if r.action == "scope_escalation_denied"][0]
        with session_scope() as session:
            session.execute(
                update(AuditLog)
                .where(AuditLog.id == denial.id)
                .values(decision="allow", denied_scopes=[])
            )

        result = adf.integrity()
        assert result["intact"] is False
        assert result["first_broken_row_id"] == denial.id

    def test_detects_row_deletion(self, adf):
        """Deleting a row breaks the successor's prev_hash link."""
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "agent-a", ["read_calendar"])
        adf.delegate_ok(root["token"], "agent-b", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        victim, successor = rows[1], rows[2]
        with session_scope() as session:
            session.execute(delete(AuditLog).where(AuditLog.id == victim.id))

        result = adf.integrity()
        assert result["intact"] is False
        assert result["first_broken_row_id"] == successor.id
        assert "prev_hash" in result["detail"]

    def test_detects_forged_row_hash(self, adf):
        """Recomputing the victim's own hash is not enough.

        An attacker who edits a field and recomputes that row's row_hash still
        breaks every following row, because each prev_hash pins the old value.
        This is what makes the structure a chain rather than per-row checksums.
        """
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "agent-a", ["read_calendar"])
        adf.delegate_ok(root["token"], "agent-b", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        target = rows[1]
        tampered_payload = {
            "action": target.action,
            "actor_id": target.actor_id,
            "actor_hash": target.actor_hash,
            "jti": target.jti,
            "parent_jti": target.parent_jti,
            "root_jti": target.root_jti,
            "scopes": ["spend_money"],
            "denied_scopes": target.denied_scopes,
            "required_scope": target.required_scope,
            "decision": target.decision,
            "reason": target.reason,
            "depth": target.depth,
            "detail": target.detail,
            "event_ts": target.event_ts,
        }
        forged_hash = compute_row_hash(target.prev_hash, tampered_payload)
        with session_scope() as session:
            session.execute(
                update(AuditLog)
                .where(AuditLog.id == target.id)
                .values(scopes=["spend_money"], row_hash=forged_hash)
            )

        result = adf.integrity()
        assert result["intact"] is False
        # The forged row itself now self-verifies, so the break surfaces at the
        # NEXT row whose prev_hash still points at the original hash.
        assert result["first_broken_row_id"] == rows[2].id

    def test_detects_timestamp_backdating(self, adf):
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "agent-a", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        target = rows[1]
        with session_scope() as session:
            session.execute(
                update(AuditLog)
                .where(AuditLog.id == target.id)
                .values(event_ts="1999-01-01T00:00:00+00:00")
            )

        result = adf.integrity()
        assert result["intact"] is False
        assert result["first_broken_row_id"] == target.id

    def test_reports_first_break_not_last(self, adf):
        """With two corrupted rows, the earliest must be reported."""
        root = adf.mint_root(["read_calendar"])
        for i in range(4):
            adf.delegate_ok(root["token"], f"agent-{i}", ["read_calendar"])
        adf.flush_audit()

        rows = _rows()
        with session_scope() as session:
            session.execute(
                update(AuditLog).where(AuditLog.id == rows[3].id).values(reason="tampered-b")
            )
            session.execute(
                update(AuditLog).where(AuditLog.id == rows[1].id).values(reason="tampered-a")
            )

        result = adf.integrity()
        assert result["first_broken_row_id"] == rows[1].id


class TestAppendOnlyDiscipline:
    def test_hash_chain_survives_buffered_and_sync_interleaving(self, adf):
        """Buffered verify events and synchronous mints must not fork the chain.

        This is the risk the single-writer design exists to eliminate: two
        writers computing prev_hash from the same tail would create siblings.
        """
        root = adf.mint_root(["read_calendar"])
        for i in range(5):
            adf.verify(root["token"], "read_calendar")
            adf.delegate_ok(root["token"], f"agent-{i}", ["read_calendar"])
        adf.flush_audit()

        result = adf.integrity()
        assert result["intact"] is True, result

        rows = _rows()
        hashes = [r.row_hash for r in rows]
        assert len(hashes) == len(set(hashes)), "duplicate row_hash: the chain forked"

    def test_integrity_endpoint_flushes_before_checking(self, adf):
        """A pending buffered row must not be mistaken for a gap."""
        root = adf.mint_root(["read_calendar"])
        adf.verify(root["token"], "read_calendar")
        result = adf.integrity()  # no explicit flush
        assert result["intact"] is True
        assert any(r.action == "verify_success" for r in _rows())
