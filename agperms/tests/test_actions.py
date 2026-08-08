"""In-flight action checkpointing: CLEAN / PARTIAL / UNKNOWN.

This is the feature that distinguishes agperms from a plain permission check.
Every other tool answers "can this agent still act?" after a revoke. These tests
pin down the answer to "what was it in the middle of doing?"
"""

from __future__ import annotations

import datetime as _dt

import pytest

from agperms import (
    ActionRecord,
    CompletionState,
    Denied,
    Firewall,
    classify_action,
)
from agperms._time import utcnow


class TestCleanCompletion:
    def test_clean_action_queues_no_review(self, fw: Firewall, root):
        with fw.action(root.token, scope="read_calendar", name="read_agenda"):
            pass
        result = fw.revoke(root.jti)
        assert result.reviews == ()
        assert fw.pending_reviews() == []

    def test_clean_action_writes_both_events(self, fw: Firewall, root):
        with fw.action(root.token, scope="read_calendar", name="read_agenda") as act:
            action_id = act.action_id
        started = fw.audit_events(action="action_started")
        completed = fw.audit_events(action="action_completed")
        assert len(started) == 1 and len(completed) == 1
        assert started[0]["detail"]["action_id"] == action_id
        assert completed[0]["detail"]["completion_state"] == "CLEAN"

    def test_handle_exposes_correlation_ids(self, fw: Firewall, root):
        with fw.action(root.token, scope="read_calendar", name="named") as act:
            assert act.name == "named"
            assert act.scope == "read_calendar"
            assert act.jti == root.jti
            assert act.action_id

    def test_notes_are_recorded_on_close(self, fw: Firewall, root):
        with fw.action(root.token, scope="read_calendar", name="noted") as act:
            act.note("read 3 events")
        completed = fw.audit_events(action="action_completed")[0]
        assert completed["detail"]["notes"] == ["read 3 events"]


class TestPartialCompletion:
    def test_exception_is_reraised_unchanged(self, fw: Firewall, root):
        sentinel = RuntimeError("kaboom")
        with pytest.raises(RuntimeError) as exc:
            with fw.action(root.token, scope="read_calendar", name="boom"):
                raise sentinel
        assert exc.value is sentinel

    def test_failed_action_is_classified_partial(self, fw: Firewall, root):
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="read_calendar", name="boom"):
                raise RuntimeError("kaboom")
        result = fw.revoke(root.jti)
        assert len(result.reviews) == 1
        review = result.reviews[0]
        assert review.classification is CompletionState.PARTIAL
        assert review.action_name == "boom"

    def test_failure_reason_is_truncated(self, fw: Firewall, root):
        long_message = "x" * 5_000
        with pytest.raises(ValueError):
            with fw.action(root.token, scope="read_calendar", name="verbose"):
                raise ValueError(long_message)
        failed = fw.audit_events(action="action_failed")[0]
        # Bounded so an immutable log cannot be flooded by one exception.
        assert len(failed["reason"]) <= 200
        assert failed["reason"].startswith("ValueError:")

    def test_partial_and_clean_are_distinguished(self, fw: Firewall, root):
        with fw.action(root.token, scope="read_calendar", name="ok"):
            pass
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="read_calendar", name="bad"):
                raise RuntimeError("nope")
        result = fw.revoke(root.jti)
        names = {r.action_name for r in result.reviews}
        assert names == {"bad"}, "only the failed action should need review"


class TestUnknownCompletion:
    """A crash leaves an action open. Its fate is UNKNOWN, never assumed CLEAN."""

    def test_open_action_classified_unknown(self, fw: Firewall, root):
        # Simulating a crash by recording a start with no close -- the only way
        # to test this deterministically, since a real SIGKILL cannot be scripted.
        fw.storage.put_action(
            ActionRecord(
                action_id="crashed-action",
                jti=root.jti,
                subject_id=root.claims.sub,
                name="charge_card",
                scope="read_calendar",
                started_at=utcnow(),
            )
        )
        result = fw.revoke(root.jti)
        assert len(result.reviews) == 1
        assert result.reviews[0].classification is CompletionState.UNKNOWN
        assert result.reviews[0].action_name == "charge_card"

    def test_inv15_unknown_is_never_clean(self):
        """The rule the whole feature rests on, tested as a pure function.

        An action with no closing record might have finished, or might have taken
        an irreversible step and died. Those are different facts, so the classifier
        must not resolve the ambiguity in the convenient direction.
        """
        open_action = ActionRecord(
            action_id="a",
            jti="j",
            subject_id="agent:x",
            name="n",
            scope="s",
            started_at=utcnow(),
        )
        assert open_action.finished_at is None
        assert classify_action(open_action) is CompletionState.UNKNOWN
        assert classify_action(open_action) is not CompletionState.CLEAN

    def test_half_closed_record_is_still_unknown(self):
        """A finish time with no state is not evidence of success."""
        weird = ActionRecord(
            action_id="a",
            jti="j",
            subject_id="agent:x",
            name="n",
            scope="s",
            started_at=utcnow(),
            finished_at=utcnow(),
            state=None,
        )
        assert classify_action(weird) is CompletionState.UNKNOWN

    def test_classifier_passes_through_recorded_state(self):
        for state in (CompletionState.CLEAN, CompletionState.PARTIAL):
            record = ActionRecord(
                action_id="a",
                jti="j",
                subject_id="agent:x",
                name="n",
                scope="s",
                started_at=utcnow(),
                finished_at=utcnow(),
                state=state,
            )
            assert classify_action(record) is state

    def test_needs_review_only_for_non_clean(self):
        assert CompletionState.CLEAN.needs_human_review() is False
        assert CompletionState.PARTIAL.needs_human_review() is True
        assert CompletionState.UNKNOWN.needs_human_review() is True


class TestActionGating:
    def test_revoked_token_cannot_open_an_action(self, fw: Firewall, root):
        fw.revoke(root.jti)
        with pytest.raises(Denied) as exc:
            with fw.action(root.token, scope="read_calendar", name="too_late"):
                pytest.fail("body must not run")
        assert exc.value.reason == "revoked"

    def test_missing_scope_cannot_open_an_action(self, fw: Firewall, root):
        with pytest.raises(Denied) as exc:
            with fw.action(root.token, scope="send_email", name="nope"):
                pytest.fail("body must not run")
        assert exc.value.reason == "scope_not_granted"

    def test_denied_action_records_no_start(self, fw: Firewall, root):
        with pytest.raises(Denied):
            with fw.action(root.token, scope="send_email", name="nope"):
                pass
        assert fw.audit_events(action="action_started") == []


class TestSubtreeReviews:
    def test_revoking_root_reviews_descendant_actions(self, fw: Firewall, root):
        child = fw.delegate(root.token, to="cal-agent", scopes=["read_calendar"])
        with pytest.raises(RuntimeError):
            with fw.action(child.token, scope="read_calendar", name="child_work"):
                raise RuntimeError("failed downstream")
        # Revoking the *root* must surface the child's in-flight finding.
        result = fw.revoke(root.jti)
        assert child.jti in result.revoked_jtis
        assert [r.action_name for r in result.reviews] == ["child_work"]

    def test_repeat_revoke_does_not_duplicate_reviews(self, fw: Firewall, root):
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="read_calendar", name="boom"):
                raise RuntimeError("x")
        first = fw.revoke(root.jti)
        second = fw.revoke(root.jti)
        assert len(first.reviews) == 1
        assert second.reviews == ()
        assert len(fw.pending_reviews()) == 1

    def test_revocation_result_reports_needs_review(self, fw: Firewall, root):
        clean = fw.revoke(root.jti)
        assert clean.needs_review is False


class TestReviewResolution:
    @pytest.fixture
    def queued_review(self, fw: Firewall, root):
        with pytest.raises(RuntimeError):
            with fw.action(root.token, scope="read_calendar", name="boom"):
                raise RuntimeError("x")
        return fw.revoke(root.jti).reviews[0]

    def test_resolve_marks_reviewed(self, fw: Firewall, queued_review):
        updated = fw.resolve_review(
            queued_review.review_id,
            note="confirmed no email left the building",
            reviewed_by="human:alice",
        )
        assert updated.reviewed is True
        assert updated.reviewed_by == "human:alice"
        assert fw.pending_reviews() == []

    def test_note_lands_in_the_hash_chain(self, fw: Firewall, queued_review):
        fw.resolve_review(
            queued_review.review_id,
            note="verified via provider dashboard",
            reviewed_by="human:alice",
        )
        rows = fw.audit_events(action="review_resolved")
        assert len(rows) == 1
        assert rows[0]["detail"]["note"] == "verified via provider dashboard"
        assert rows[0]["detail"]["review_id"] == queued_review.review_id
        # The evidence must survive an integrity walk.
        assert fw.verify_audit_integrity().intact

    def test_note_is_required(self, fw: Firewall, queued_review):
        with pytest.raises(ValueError, match="note is required"):
            fw.resolve_review(
                queued_review.review_id, note="   ", reviewed_by="human:alice"
            )

    def test_double_resolve_is_rejected(self, fw: Firewall, queued_review):
        fw.resolve_review(
            queued_review.review_id, note="done", reviewed_by="human:alice"
        )
        with pytest.raises(ValueError, match="already resolved"):
            fw.resolve_review(
                queued_review.review_id, note="again", reviewed_by="human:alice"
            )

    def test_unknown_review_raises(self, fw: Firewall):
        with pytest.raises(KeyError):
            fw.resolve_review("nope", note="x", reviewed_by="human:alice")

    def test_resolving_does_not_unrevoke(self, fw: Firewall, root, queued_review):
        fw.resolve_review(
            queued_review.review_id, note="closed", reviewed_by="human:alice"
        )
        # Closure is forensic, not a permission action.
        assert fw.verify(root.token, "read_calendar").reason == "revoked"

    def test_include_resolved_listing(self, fw: Firewall, queued_review):
        fw.resolve_review(
            queued_review.review_id, note="closed", reviewed_by="human:alice"
        )
        assert fw.pending_reviews() == []
        assert len(fw.pending_reviews(include_resolved=True)) == 1


class TestStorageBounds:
    """The cost of checkpointing must be predictable, not just claimed to be."""

    def test_clean_actions_cost_two_rows_and_no_reviews(self, fw: Firewall, root):
        baseline = fw.storage.count_audit_rows()
        iterations = 250
        for _ in range(iterations):
            with fw.action(root.token, scope="read_calendar", name="tick"):
                pass
        added = fw.storage.count_audit_rows() - baseline
        # 2 action rows + 1 verify row per iteration; nothing else accumulates.
        assert added == iterations * 3
        assert fw.pending_reviews() == []

    def test_review_queue_tracks_incidents_not_activity(self, fw: Firewall, root):
        """1,000 clean actions then one revoke must leave the queue empty."""
        for _ in range(1_000):
            with fw.action(root.token, scope="read_calendar", name="tick"):
                pass
        result = fw.revoke(root.jti)
        assert result.reviews == ()
        assert fw.pending_reviews() == []

    def test_chain_survives_heavy_action_traffic(self, fw: Firewall, root):
        for i in range(100):
            if i % 10 == 0:
                with pytest.raises(RuntimeError):
                    with fw.action(root.token, scope="read_calendar", name=f"bad{i}"):
                        raise RuntimeError("x")
            else:
                with fw.action(root.token, scope="read_calendar", name=f"ok{i}"):
                    pass
        report = fw.verify_audit_integrity()
        assert report.intact, report.detail
        result = fw.revoke(root.jti)
        assert len(result.reviews) == 10  # exactly the failures
