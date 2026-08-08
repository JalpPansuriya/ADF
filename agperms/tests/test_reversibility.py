"""Reversibility typing: the recoverability class of an action's effect.

Taxonomy from *Revisable by Design* (arXiv:2604.23283). These tests pin the two
properties that make it useful rather than decorative: an unclassified scope is
treated as unrecoverable, and completion state still dominates recoverability
when a human is deciding what to look at first.
"""

from __future__ import annotations

import pytest

from agperms import (
    ActionRecord,
    CompletionState,
    Config,
    Firewall,
    MemoryStorage,
    Reversibility,
    review_priority,
)
from agperms._time import utcnow
from agperms.models import worst_of


def _record(
    *,
    state: CompletionState | None,
    reversibility: Reversibility,
    finished: bool = True,
) -> ActionRecord:
    now = utcnow()
    return ActionRecord(
        action_id="a",
        jti="j",
        subject_id="s",
        name="n",
        scope="sc",
        started_at=now,
        finished_at=now if finished else None,
        state=state,
        reversibility=reversibility,
    )


class TestReversibilityOrdering:
    def test_rank_is_severity_not_alphabetical(self):
        assert Reversibility.IDEMPOTENT.rank == 0
        assert Reversibility.REVERSIBLE.rank == 1
        assert Reversibility.COMPENSABLE.rank == 2
        assert Reversibility.IRREVERSIBLE.rank == 3

    def test_worst_of_returns_worst_case(self):
        # Alphabetically COMPENSABLE < IDEMPOTENT < IRREVERSIBLE < REVERSIBLE,
        # so a bare max() over these str-enum members answers REVERSIBLE. That
        # is exactly why worst_of exists.
        members = [
            Reversibility.REVERSIBLE,
            Reversibility.IRREVERSIBLE,
            Reversibility.IDEMPOTENT,
        ]
        assert worst_of(members) is Reversibility.IRREVERSIBLE
        assert max(members) is Reversibility.REVERSIBLE  # the trap, pinned

    def test_worst_of_empty_is_none(self):
        assert worst_of([]) is None


class TestConfigDefaults:
    def test_unknown_scope_is_irreversible(self):
        """Fail closed: nobody classified it, so assume the worst."""
        assert (
            Config().reversibility_of("some_brand_new_scope")
            is Reversibility.IRREVERSIBLE
        )

    def test_spend_money_is_compensable_not_irreversible(self):
        """A charge can be refunded; that is the point of the distinction."""
        assert Config().reversibility_of("spend_money") is Reversibility.COMPENSABLE

    def test_transfer_funds_has_no_clawback(self):
        assert (
            Config().reversibility_of("transfer_funds") is Reversibility.IRREVERSIBLE
        )

    def test_sensitive_and_reversibility_are_independent_maps(self):
        """Merging them would force spend_money to be IRREVERSIBLE to stay gated."""
        cfg = Config()
        assert cfg.is_sensitive("spend_money")
        assert cfg.reversibility_of("spend_money") is not Reversibility.IRREVERSIBLE

    def test_caller_overrides_are_honoured(self):
        cfg = Config(scope_reversibility={"read_calendar": Reversibility.IDEMPOTENT})
        assert cfg.reversibility_of("read_calendar") is Reversibility.IDEMPOTENT
        # Overriding replaces the map wholesale, so a default is no longer known.
        assert cfg.reversibility_of("send_email") is Reversibility.IRREVERSIBLE

    def test_string_values_are_coerced(self):
        """Config files hand over strings, not enum members."""
        cfg = Config(scope_reversibility={"read_calendar": "IDEMPOTENT"})
        assert cfg.reversibility_of("read_calendar") is Reversibility.IDEMPOTENT

    def test_mutating_the_passed_dict_cannot_change_policy(self):
        mutable = {"read_calendar": Reversibility.IDEMPOTENT}
        cfg = Config(scope_reversibility=mutable)
        mutable["read_calendar"] = Reversibility.IRREVERSIBLE
        assert cfg.reversibility_of("read_calendar") is Reversibility.IDEMPOTENT

    def test_worst_reversibility_of_empty_is_none(self):
        assert Config().worst_reversibility([]) is None

    def test_worst_reversibility_picks_the_least_recoverable(self):
        cfg = Config(
            scope_reversibility={
                "a": Reversibility.IDEMPOTENT,
                "b": Reversibility.COMPENSABLE,
                "c": Reversibility.REVERSIBLE,
            }
        )
        assert cfg.worst_reversibility(["a", "b", "c"]) is Reversibility.COMPENSABLE


class TestActionRecordsCarryReversibility:
    def test_default_is_irreversible(self):
        rec = _record(state=CompletionState.CLEAN, reversibility=Reversibility.IDEMPOTENT)
        bare = ActionRecord(
            action_id="x",
            jti="j",
            subject_id="s",
            name="n",
            scope="sc",
            started_at=rec.started_at,
        )
        assert bare.reversibility is Reversibility.IRREVERSIBLE

    def test_action_resolves_from_config(self, config: Config):
        cfg = config.with_overrides(
            scope_reversibility={"read_calendar": Reversibility.IDEMPOTENT}
        )
        fw = Firewall(config=cfg, storage=MemoryStorage())
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        with fw.action(root.token, scope="read_calendar", name="r") as act:
            assert act.reversibility is Reversibility.IDEMPOTENT
            stored = fw.storage.get_action(act.action_id)
            assert stored is not None
            assert stored.reversibility is Reversibility.IDEMPOTENT

    def test_call_site_override_wins(self, fw: Firewall, root):
        """One scope can cover a soft-delete and a hard-delete path."""
        with fw.action(
            root.token,
            scope="read_calendar",
            name="soft",
            reversibility=Reversibility.REVERSIBLE,
        ) as act:
            assert act.reversibility is Reversibility.REVERSIBLE
        stored = fw.storage.get_action(act.action_id)
        assert stored is not None
        assert stored.reversibility is Reversibility.REVERSIBLE

    def test_reversibility_survives_close(self, fw: Firewall, root):
        with fw.action(
            root.token,
            scope="read_calendar",
            name="r",
            reversibility=Reversibility.COMPENSABLE,
        ) as act:
            pass
        stored = fw.storage.get_action(act.action_id)
        assert stored is not None
        assert stored.state is CompletionState.CLEAN
        assert stored.reversibility is Reversibility.COMPENSABLE

    def test_reversibility_appears_in_audit_events(self, fw: Firewall, root):
        with fw.action(
            root.token,
            scope="read_calendar",
            name="r",
            reversibility=Reversibility.COMPENSABLE,
        ):
            pass
        started = fw.audit_events(action="action_started")[0]
        completed = fw.audit_events(action="action_completed")[0]
        assert started["detail"]["reversibility"] == "COMPENSABLE"
        assert completed["detail"]["reversibility"] == "COMPENSABLE"


class TestReviewPriority:
    def test_unknown_outranks_partial_regardless_of_reversibility(self):
        """"We do not know" is worse than "we know it failed", whatever it was."""
        unknown_idempotent = _record(
            state=None, reversibility=Reversibility.IDEMPOTENT, finished=False
        )
        partial_irreversible = _record(
            state=CompletionState.PARTIAL, reversibility=Reversibility.IRREVERSIBLE
        )
        assert review_priority(unknown_idempotent) > review_priority(
            partial_irreversible
        )

    def test_within_a_state_less_recoverable_ranks_higher(self):
        a = _record(state=CompletionState.PARTIAL, reversibility=Reversibility.IDEMPOTENT)
        b = _record(
            state=CompletionState.PARTIAL, reversibility=Reversibility.IRREVERSIBLE
        )
        assert review_priority(b) > review_priority(a)

    def test_clean_ranks_below_every_questionable_action(self):
        clean = _record(
            state=CompletionState.CLEAN, reversibility=Reversibility.IRREVERSIBLE
        )
        partial = _record(
            state=CompletionState.PARTIAL, reversibility=Reversibility.IDEMPOTENT
        )
        assert review_priority(partial) > review_priority(clean)

    def test_is_pure(self):
        """No firewall, no store, no clock -- it is a policy rule."""
        rec = _record(
            state=CompletionState.PARTIAL, reversibility=Reversibility.COMPENSABLE
        )
        assert review_priority(rec) == review_priority(rec)


class TestPendingReviewOrdering:
    def test_unknown_irreversible_surfaces_first(self, config: Config):
        """An UNKNOWN funds transfer must not sit under a page of UNKNOWN reads."""
        cfg = config.with_overrides(
            scope_reversibility={
                "read_calendar": Reversibility.IDEMPOTENT,
                "write_calendar": Reversibility.IRREVERSIBLE,
            }
        )
        fw = Firewall(config=cfg, storage=MemoryStorage())
        root = fw.mint_root(
            subject="alice", scopes=["read_calendar", "write_calendar"]
        )

        # Two actions left open, so both classify UNKNOWN; they differ only in
        # how recoverable they are.
        harmless = fw.action(root.token, scope="read_calendar", name="reads")
        harmless.__enter__()
        severe = fw.action(root.token, scope="write_calendar", name="writes")
        severe.__enter__()

        fw.revoke(root.jti)
        ordered = fw.pending_reviews(order_by_priority=True)
        assert [r.action_name for r in ordered] == ["writes", "reads"]

    def test_default_ordering_is_unchanged(self, fw: Firewall, root):
        """order_by_priority is opt-in; existing callers see the old order."""
        handle = fw.action(root.token, scope="read_calendar", name="open")
        handle.__enter__()
        fw.revoke(root.jti)
        assert [r.action_name for r in fw.pending_reviews()] == ["open"]
