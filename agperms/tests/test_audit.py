"""Audit chain integrity: tamper must be detectable and localisable."""

from __future__ import annotations

import pytest

from agperms import Firewall
from agperms._audit import GENESIS_HASH, compute_row_hash


class TestIntactChain:
    def test_fresh_log_is_intact(self, fw: Firewall, root):
        fw.delegate(root.token, to="agent", scopes=["read_calendar"])
        fw.verify(root.token, "read_calendar")
        report = fw.verify_audit_integrity()
        assert report.intact
        assert report.rows_checked >= 3
        assert report.first_broken_row_id is None
        assert bool(report) is True

    def test_empty_log_is_intact(self, fw: Firewall):
        report = fw.verify_audit_integrity()
        assert report.intact
        assert report.rows_checked == 0

    def test_links_are_contiguous(self, fw: Firewall, root):
        for i in range(5):
            fw.delegate(root.token, to=f"agent{i}", scopes=["read_calendar"])
        rows = fw.storage.iter_audit_rows()
        prev = GENESIS_HASH
        for row in rows:
            assert row["prev_hash"] == prev
            prev = row["row_hash"]


class TestTamperDetection:
    """Each variant attacks the chain differently; all must be caught."""

    def _rows(self, fw: Firewall) -> list[dict]:
        return fw.storage._audit  # type: ignore[attr-defined]

    def test_detects_field_mutation(self, fw: Firewall, root):
        fw.delegate(root.token, to="agent", scopes=["read_calendar"])
        rows = self._rows(fw)
        target = rows[1]
        target["scopes"] = ["read_calendar", "spend_money"]
        report = fw.verify_audit_integrity()
        assert not report.intact
        assert report.first_broken_row_id == target["id"]
        assert "content hash mismatch" in report.detail

    def test_detects_decision_flip(self, fw: Firewall, root):
        """The highest-value tamper: turning a recorded denial into an allow."""
        from agperms import ScopeEscalationDenied

        with pytest.raises(ScopeEscalationDenied):
            fw.delegate(root.token, to="greedy", scopes=["send_email"])
        rows = self._rows(fw)
        denial = next(r for r in rows if r["action"] == "escalation_denied")
        denial["decision"] = "allow"
        denial["denied_scopes"] = []
        report = fw.verify_audit_integrity()
        assert not report.intact
        assert report.first_broken_row_id == denial["id"]

    def test_detects_row_deletion(self, fw: Firewall, root):
        fw.delegate(root.token, to="a", scopes=["read_calendar"])
        fw.delegate(root.token, to="b", scopes=["read_calendar"])
        rows = self._rows(fw)
        successor_id = rows[2]["id"]
        del rows[1]
        report = fw.verify_audit_integrity()
        assert not report.intact
        assert report.first_broken_row_id == successor_id
        assert "prev_hash" in report.detail

    def test_detects_reordering(self, fw: Firewall, root):
        fw.delegate(root.token, to="a", scopes=["read_calendar"])
        fw.delegate(root.token, to="b", scopes=["read_calendar"])
        rows = self._rows(fw)
        rows[1], rows[2] = rows[2], rows[1]
        assert not fw.verify_audit_integrity().intact

    def test_recomputing_one_hash_still_breaks_the_chain(self, fw: Firewall, root):
        """Editing a row and fixing its own hash breaks every row after it.

        This is what makes the structure a chain rather than per-row checksums.
        """
        fw.delegate(root.token, to="a", scopes=["read_calendar"])
        fw.delegate(root.token, to="b", scopes=["read_calendar"])
        rows = self._rows(fw)
        target = rows[1]
        target["scopes"] = ["spend_money"]
        target["row_hash"] = compute_row_hash(target["prev_hash"], target)
        report = fw.verify_audit_integrity()
        assert not report.intact
        # The forged row self-verifies, so the break surfaces at its successor.
        assert report.first_broken_row_id == rows[2]["id"]

    def test_detects_timestamp_backdating(self, fw: Firewall, root):
        fw.delegate(root.token, to="a", scopes=["read_calendar"])
        rows = self._rows(fw)
        rows[1]["event_ts"] = "1999-01-01T00:00:00+00:00"
        report = fw.verify_audit_integrity()
        assert not report.intact
        assert report.first_broken_row_id == rows[1]["id"]

    def test_reports_first_break_not_last(self, fw: Firewall, root):
        for i in range(5):
            fw.delegate(root.token, to=f"a{i}", scopes=["read_calendar"])
        rows = self._rows(fw)
        rows[4]["reason"] = "tampered-late"
        rows[2]["reason"] = "tampered-early"
        report = fw.verify_audit_integrity()
        assert report.first_broken_row_id == rows[2]["id"]


class TestChainReconstruction:
    def test_lineage_is_rebuilt_from_records(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
        mid = fw.delegate(root.token, to="assistant", scopes=["read_calendar"])
        leaf = fw.delegate(mid.token, to="calendar", scopes=["read_calendar"])

        hops = fw.chain(leaf.jti)
        assert [h.jti for h in hops] == [root.jti, mid.jti, leaf.jti]
        assert [h.depth for h in hops] == [0, 1, 2]
        assert hops[0].display_label == "alice"
        assert hops[-1].display_label == "calendar"

    def test_scopes_narrow_monotonically_down_the_chain(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["a", "b", "c"])
        one = fw.delegate(root.token, to="one", scopes=["a", "b"])
        two = fw.delegate(one.token, to="two", scopes=["a"])
        sets = [set(h.scopes) for h in fw.chain(two.jti)]
        for parent, child in zip(sets, sets[1:]):
            assert child.issubset(parent)

    def test_rebuild_matches_the_signed_claim(self, fw: Firewall):
        """Two independent representations of the same fact must agree."""
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        mid = fw.delegate(root.token, to="mid", scopes=["read_calendar"])
        leaf = fw.delegate(mid.token, to="leaf", scopes=["read_calendar"])
        rebuilt = [h.jti for h in fw.chain(leaf.jti)]
        assert rebuilt == list(leaf.claims.ancestor_jtis) + [leaf.jti]

    def test_revoked_ancestors_are_flagged(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        mid = fw.delegate(root.token, to="mid", scopes=["read_calendar"])
        fw.revoke(root.jti)
        hops = fw.chain(mid.jti)
        assert all(h.revoked for h in hops)

    def test_unknown_jti_raises(self, fw: Firewall):
        with pytest.raises(KeyError):
            fw.chain("does-not-exist")
