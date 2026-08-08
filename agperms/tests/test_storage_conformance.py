"""Backend conformance: MemoryStorage and SqlStorage must behave identically.

Every test here runs twice, once per backend. Without this, the SQL backend could
drift from the in-memory one and only the deployed path would break -- exactly the
class of bug that is hardest to catch.
"""

from __future__ import annotations

import pytest

from agperms import (
    ActionRecord,
    CompletionState,
    Config,
    Firewall,
    MemoryStorage,
    ScopeEscalationDenied,
    StorageError,
)
from agperms._time import utcnow
from agperms.storage.sql import SqlStorage


@pytest.fixture(params=["memory", "sql"])
def backend(request):
    if request.param == "memory":
        storage = MemoryStorage()
    else:
        # Shared in-memory SQLite: a real engine and real SQL, no file on disk.
        storage = SqlStorage("sqlite://", create_tables=True)
    yield storage
    storage.close()


@pytest.fixture
def fw(backend) -> Firewall:
    config = Config(
        jwt_secret="test-secret-not-for-production-0123456789abcdef",
        pii_salt="test-salt",
        rate_limit_verify_per_min=100_000,
        rate_limit_delegate_per_min=100_000,
        rate_limit_action_per_min=100_000,
    )
    return Firewall(config=config, storage=backend)


class TestCoreFlowsOnBothBackends:
    def test_mint_delegate_verify(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
        child = fw.delegate(root.token, to="agent", scopes=["read_calendar"])
        assert fw.verify(child.token, "read_calendar").valid
        assert not fw.verify(child.token, "read_email").valid

    def test_escalation_blocked(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        with pytest.raises(ScopeEscalationDenied):
            fw.delegate(root.token, to="greedy", scopes=["web_search"])

    def test_subtree_revocation(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        a = fw.delegate(root.token, to="a", scopes=["s"])
        b = fw.delegate(a.token, to="b", scopes=["s"])
        result = fw.revoke(root.jti)
        assert result.subtree_count == 3
        # Order is part of the contract, not an implementation detail.
        assert result.revoked_jtis[0] == root.jti
        for cap in (root, a, b):
            assert fw.verify(cap.token, "s").reason == "revoked"

    def test_duplicate_edge_is_a_noop(self, fw: Firewall, backend):
        root = fw.mint_root(subject="alice", scopes=["s"])
        child = fw.delegate(root.token, to="c", scopes=["s"])
        backend.add_edge(root.jti, child.jti)  # again
        backend.add_edge(root.jti, child.jti)  # and again
        assert backend.descendants_breadth_first(root.jti) == [root.jti, child.jti]

    def test_duplicate_token_raises(self, fw: Firewall, backend):
        from agperms.models import TokenMetadata

        root = fw.mint_root(subject="alice", scopes=["s"])
        meta = backend.get_token(root.jti)
        assert meta is not None
        with pytest.raises(StorageError):
            backend.put_token(meta)

    def test_subject_get_or_create_is_stable(self, fw: Firewall, backend):
        first = backend.get_or_create_subject(
            identifier_hash="abc", kind="agent", display_label="worker"
        )
        second = backend.get_or_create_subject(
            identifier_hash="abc", kind="agent", display_label="worker"
        )
        assert first.subject_id == second.subject_id
        assert backend.get_subject(first.subject_id) is not None
        assert backend.get_subjects([first.subject_id])[first.subject_id].display_label == "worker"

    def test_audit_chain_intact(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        for i in range(5):
            fw.delegate(root.token, to=f"a{i}", scopes=["s"])
        report = fw.verify_audit_integrity()
        assert report.intact, report.detail
        assert report.rows_checked == fw.storage.count_audit_rows()

    def test_chain_reconstruction(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        mid = fw.delegate(root.token, to="mid", scopes=["s"])
        leaf = fw.delegate(mid.token, to="leaf", scopes=["s"])
        hops = fw.chain(leaf.jti)
        assert [h.jti for h in hops] == [root.jti, mid.jti, leaf.jti]
        assert hops[0].display_label == "alice"


class TestApprovalOnBothBackends:
    def test_approval_round_trip(self, fw: Firewall):
        from agperms import ApprovalRequired

        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        approval_id = exc.value.approval_id

        assert len(fw.pending_approvals()) == 1
        assert fw.collect(approval_id) is None

        cap = fw.approve(approval_id, approver="human:alice")
        assert fw.verify(cap.token, "send_email").valid
        assert fw.pending_approvals() == []

    def test_denial_round_trip(self, fw: Firewall):
        from agperms import ApprovalRequired, Denied

        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        fw.deny(exc.value.approval_id, approver="human:alice")
        with pytest.raises(Denied):
            fw.collect(exc.value.approval_id)


class TestActionsOnBothBackends:
    def test_clean_action_leaves_no_review(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        with fw.action(root.token, scope="s", name="clean"):
            pass
        assert fw.revoke(root.jti).reviews == ()

    def test_partial_action_is_reviewed(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="s", name="boom"):
                raise RuntimeError("x")
        reviews = fw.revoke(root.jti).reviews
        assert len(reviews) == 1
        assert reviews[0].classification is CompletionState.PARTIAL

    def test_open_action_is_unknown(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        fw.storage.put_action(
            ActionRecord(
                action_id="crashed",
                jti=root.jti,
                subject_id=root.claims.sub,
                name="charge_card",
                scope="s",
                started_at=utcnow(),
            )
        )
        reviews = fw.revoke(root.jti).reviews
        assert len(reviews) == 1
        assert reviews[0].classification is CompletionState.UNKNOWN

    def test_review_resolution_round_trip(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="s", name="boom"):
                raise RuntimeError("x")
        review = fw.revoke(root.jti).reviews[0]

        fw.resolve_review(review.review_id, note="checked, safe", reviewed_by="human:alice")
        assert fw.pending_reviews() == []
        assert len(fw.pending_reviews(include_resolved=True)) == 1
        rows = fw.audit_events(action="review_resolved")
        assert rows[0]["detail"]["note"] == "checked, safe"
        assert fw.verify_audit_integrity().intact


class TestSqlSpecifics:
    def test_pooler_detection(self):
        from agperms.storage.sql import _is_transaction_pooler

        assert _is_transaction_pooler(
            "postgresql+psycopg://u:p@aws-0-x.pooler.supabase.com:6543/postgres"
        )
        assert _is_transaction_pooler("postgresql://u:p@h:6543/db")
        assert _is_transaction_pooler("postgresql://u:p@h:5432/db?pgbouncer=true")
        assert not _is_transaction_pooler("postgresql://u:p@h:5432/db")
        assert not _is_transaction_pooler("sqlite://")

    def test_sql_storage_is_durable_across_instances(self, tmp_path):
        """The property MemoryStorage cannot offer: revocation outlives the object."""
        db = f"sqlite:///{tmp_path / 'agperms.db'}"
        config = Config(
            jwt_secret="test-secret-not-for-production-0123456789abcdef",
            pii_salt="test-salt",
        )

        first = SqlStorage(db)
        fw1 = Firewall(config=config, storage=first)
        root = fw1.mint_root(subject="alice", scopes=["s"])
        fw1.revoke(root.jti)
        first.close()

        # A brand-new storage object over the same database.
        second = SqlStorage(db)
        fw2 = Firewall(config=config, storage=second)
        assert fw2.verify(root.token, "s").reason == "revoked"
        second.close()

    def test_closed_storage_fails_closed(self):
        storage = SqlStorage("sqlite://")
        storage.close()
        with pytest.raises(StorageError):
            storage.is_revoked("any")

    def test_sql_storage_advertises_durability(self):
        storage = SqlStorage("sqlite://")
        try:
            assert storage.durable is True
        finally:
            storage.close()


class TestSingleProcessLimitation:
    """The library is single-process. This pins that, rather than leaving it to prose.

    The audit chain needs one writer computing each row's hash from the current tail.
    ``agperms`` enforces that with a ``threading.Lock``, which cannot serialise across
    processes. Two instances over one store therefore fork the chain -- and if a future
    change ever makes that safe, this test fails and the docs get corrected with it.
    """

    def test_two_instances_sharing_a_store_fork_the_chain(self):
        config = Config(
            jwt_secret="test-secret-not-for-production-0123456789abcdef",
            pii_salt="test-salt",
        )
        store = SqlStorage("sqlite://")
        try:
            a = Firewall(config=config, storage=store)
            b = Firewall(config=config, storage=store)

            root_a = a.mint_root(subject="alice", scopes=["s"])
            root_b = b.mint_root(subject="bob", scopes=["s"])
            # Interleave so each instance's cached tail goes stale.
            for i in range(5):
                a.delegate(root_a.token, to=f"a{i}", scopes=["s"])
                b.delegate(root_b.token, to=f"b{i}", scopes=["s"])

            report = a.verify_audit_integrity()
            assert not report.intact, (
                "two instances no longer fork the chain -- if this is a deliberate "
                "fix, update agperms/README.md 'One process only' and the "
                "DECISIONS.md entry that cites this failure"
            )
            assert report.first_broken_row_id is not None
        finally:
            store.close()

    def test_one_instance_over_the_same_store_is_intact(self):
        """The contrast: a single writer keeps the chain sound."""
        config = Config(
            jwt_secret="test-secret-not-for-production-0123456789abcdef",
            pii_salt="test-salt",
        )
        store = SqlStorage("sqlite://")
        try:
            fw = Firewall(config=config, storage=store)
            root = fw.mint_root(subject="alice", scopes=["s"])
            for i in range(10):
                fw.delegate(root.token, to=f"a{i}", scopes=["s"])
            assert fw.verify_audit_integrity().intact
        finally:
            store.close()
