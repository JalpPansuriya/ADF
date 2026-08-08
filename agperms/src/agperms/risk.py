"""Insurance-style risk-state vector for a delegated agent.

Implements the risk state ``s = (alpha, beta, eta, g, v)`` from *AI-Native
Insurance for Agentic AI: Pricing, Underwriting, and End-to-End Automation*
(Zhu, NYU, arXiv:2607.13230), which represents each agentic deployment by its
autonomy category, operational authority, external-state permissions, governance
maturity, and dependency concentration, and maps that state onto event
probabilities and premiums.

Why this lives here
-------------------
The paper's components are meant to be *observable* -- from permission
inventories, approval policy, audit evidence and telemetry. agperms already owns
three of those things for the agents it governs: the scope grants, the approval
gate, and a hash-chained audit log of every action. So three of the five
components can be computed rather than surveyed, from data the library already
has, with no new storage and no new protocol methods.

What this does NOT do
---------------------
This is deliberately not a full implementation of the paper, and the gaps are
not incidental:

* **Dependency concentration (v) cannot be computed here at all.** agperms has
  no concept of a model provider, cloud region or connector vendor. The caller
  must supply ``dependency_shares``; omitted, it stays ``None`` rather than
  being invented.
* **Autonomy category (alpha) is a heuristic**, inferred from delegation depth
  and the reversibility mix of the granted scopes. The paper's alpha(4)
  (cyber-physical) is unreachable: agperms cannot know whether a scope actuates
  a robot.
* **Governance tier (g) scores only what agperms can verify about itself** --
  durable storage, a fixed signing key, an intact audit chain, an empty review
  queue. It is not an organisational governance audit, and a high tier here is
  not evidence of red-teaming, incident response or vendor management, all of
  which the paper's tier includes.
* **None of this is a premium.** It is the input vector an underwriter would
  ask for, computed honestly from one library's view. Pricing needs the paper's
  calibration maps, which need claims data nobody has yet.

Stated plainly rather than buried, on the same principle as the in-memory
backend's durability warning: the number is only worth what its inputs are.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agperms._time import as_utc
from agperms.models import Reversibility

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agperms.firewall import Firewall

#: Relative risk weight per permission class, following the paper's Table 4
#: (external email 1, scheduling 2, record modification 4, payments 8,
#: physical-device control 15). These are the paper's own illustrative weights,
#: not empirical estimates -- override them for your own domain.
PERMISSION_WEIGHTS: dict[str, float] = {
    "read": 0.5,
    "email": 1.0,
    "scheduling": 2.0,
    "record_modification": 4.0,
    "payments": 8.0,
    "code_execution": 8.0,
    "physical_control": 15.0,
}

#: Which permission class each default scope belongs to. Unmapped scopes fall
#: back to ``record_modification``: a scope nobody classified is assumed to
#: change external state, for the same fail-closed reason an unclassified scope
#: is IRREVERSIBLE.
DEFAULT_SCOPE_PERMISSION_CLASS: dict[str, str] = {
    "read_calendar": "read",
    "read_email": "read",
    "send_email": "email",
    "post_public_content": "email",
    "schedule_meeting": "scheduling",
    "delete_data": "record_modification",
    "spend_money": "payments",
    "transfer_funds": "payments",
    "execute_code": "code_execution",
}

_FALLBACK_PERMISSION_CLASS = "record_modification"


@dataclass(frozen=True, slots=True)
class RiskState:
    """The paper's ``s = (alpha, beta, eta, g, v)`` for one subject.

    Every field carries the honesty of its source: see the module docstring for
    which components are measured, which are heuristic, and which are supplied
    by the caller.
    """

    subject_id: str

    #: Autonomy category, 0-3 on the paper's 0-4 ordinal scale. Heuristic.
    #: 4 (cyber-physical) is unreachable from scope names alone.
    alpha: int
    #: Operational authority: the fraction of this subject's observed actions
    #: that executed without passing the human-approval gate. ``None`` when no
    #: actions have been observed -- 0/0 is not "fully governed", it is unknown,
    #: and the same refusal-to-guess that makes an unclosed action UNKNOWN
    #: applies here.
    beta: float | None
    #: Permission classes this subject holds, mapped from its granted scopes.
    eta: frozenset[str]
    #: Weighted permission exposure: the paper's ``psi_eta(eta)``.
    eta_exposure: float
    #: Governance tier 0-4, counting the safeguards agperms can itself verify.
    governance_tier: int
    #: Which governance checks passed, so a tier is auditable rather than a
    #: bare number.
    governance_evidence: dict[str, bool] = field(default_factory=dict)
    #: Caller-supplied vendor mix. ``None`` means not supplied; agperms cannot
    #: observe this.
    dependency_shares: dict[str, float] | None = None
    #: Herfindahl concentration of ``dependency_shares``, or ``None``.
    dependency_concentration: float | None = None

    #: Counts behind ``beta``, exposed so the ratio can be checked rather than
    #: trusted.
    actions_observed: int = 0
    actions_autonomous: int = 0
    #: The least recoverable class among the granted scopes, or ``None`` if the
    #: subject holds no scopes.
    worst_reversibility: Reversibility | None = None

    @property
    def beta_is_measured(self) -> bool:
        """False when no actions were observed, so ``beta`` is unknown."""
        return self.beta is not None

    def to_dict(self) -> dict[str, object]:
        """Flat form, for handing to an underwriter or logging as evidence."""
        return {
            "subject_id": self.subject_id,
            "alpha": self.alpha,
            "beta": self.beta,
            "eta": sorted(self.eta),
            "eta_exposure": self.eta_exposure,
            "governance_tier": self.governance_tier,
            "governance_evidence": dict(self.governance_evidence),
            "dependency_shares": self.dependency_shares,
            "dependency_concentration": self.dependency_concentration,
            "actions_observed": self.actions_observed,
            "actions_autonomous": self.actions_autonomous,
            "worst_reversibility": (
                self.worst_reversibility.value if self.worst_reversibility else None
            ),
        }


def permission_class_of(
    scope: str, *, overrides: dict[str, str] | None = None
) -> str:
    """Which permission class ``scope`` falls into. Unknown scopes are treated
    as external-state modification rather than as reads."""
    if overrides and scope in overrides:
        return overrides[scope]
    return DEFAULT_SCOPE_PERMISSION_CLASS.get(scope, _FALLBACK_PERMISSION_CLASS)


def permission_exposure(
    scopes: list[str],
    *,
    weights: dict[str, float] | None = None,
    class_overrides: dict[str, str] | None = None,
) -> tuple[frozenset[str], float]:
    """The paper's ``eta`` and ``psi_eta(eta)`` for a set of granted scopes.

    Exposure sums over distinct permission *classes*, not scopes: holding three
    scopes that all send email is one email permission, not three.
    """
    table = weights or PERMISSION_WEIGHTS
    classes = {
        permission_class_of(scope, overrides=class_overrides) for scope in scopes
    }
    exposure = sum(table.get(cls, table.get(_FALLBACK_PERMISSION_CLASS, 1.0)) for cls in classes)
    return frozenset(classes), exposure


def autonomy_category(
    *, depth: int, worst: Reversibility | None, delegates_further: bool
) -> int:
    """Heuristic ``alpha`` on the paper's ordinal 0-4 scale.

    Mapping, and its justification:

    * 0 (assistive) -- nothing but idempotent scopes: it can read, not act.
    * 1 (tool-enabled copilot) -- can change state, but only recoverably.
    * 2 (digital agent) -- holds an unrecoverable or only-compensable scope, so
      an error becomes an external fact.
    * 3 (multi-agent workflow) -- the above *and* it delegates onward, which is
      the paper's cascading-action case.

    4 (cyber-physical) is never returned. A scope string cannot tell us whether
    it drives a robot arm, and inferring that would be a guess dressed as a
    measurement.
    """
    if worst is None or worst is Reversibility.IDEMPOTENT:
        return 0
    if worst is Reversibility.REVERSIBLE:
        return 1
    # COMPENSABLE or IRREVERSIBLE: real external consequence.
    if delegates_further or depth > 1:
        return 3
    return 2


def governance_tier(fw: "Firewall") -> tuple[int, dict[str, bool]]:
    """Score the safeguards agperms can verify about its own deployment.

    Returns the tier and the evidence behind it. Each check is something the
    library can actually establish, which is why the list is short: an
    organisational governance audit covers red-teaming, incident response and
    vendor risk, none of which a permission library can see.
    """
    integrity = fw.verify_audit_integrity()
    evidence = {
        # A revocation that dies with the process is not a control.
        "durable_storage": bool(getattr(fw.storage, "durable", False)),
        # An ephemeral key means tokens cannot be verified after a restart.
        "persistent_signing_key": not fw.config.signing_key_is_ephemeral,
        # The evidentiary record is unbroken.
        "audit_chain_intact": bool(integrity.intact),
        # Findings are being closed, not accumulating unread.
        "review_queue_clear": not fw.pending_reviews(),
        # An approval gate exists for at least some scopes.
        "approval_gate_configured": bool(fw.config.sensitive_scopes),
    }
    return sum(1 for passed in evidence.values() if passed), evidence


def herfindahl(shares: dict[str, float]) -> float:
    """Concentration statistic ``R(v) = sum(v_k^2)`` from the paper.

    1.0 means a single provider carries everything; 1/K means perfectly spread
    across K providers. Shares are normalised first so a caller passing counts
    or percentages gets a meaningful answer.
    """
    total = sum(shares.values())
    if total <= 0:
        return 0.0
    return sum((value / total) ** 2 for value in shares.values())


def compute_risk_state(
    fw: "Firewall",
    subject_id: str,
    *,
    since: _dt.datetime | None = None,
    dependency_shares: dict[str, float] | None = None,
    permission_weights: dict[str, float] | None = None,
    scope_permission_classes: dict[str, str] | None = None,
) -> RiskState:
    """Compute the risk-state vector for one subject from durable records.

    Reads the audit log and token metadata; writes nothing and adds no storage
    requirements. ``since`` bounds the observation window used for ``beta``,
    matching the paper's ``beta(T) = N_auto(T) / N_total(T)`` telemetry
    estimator.

    ``dependency_shares`` is the caller's own vendor mix, which agperms cannot
    observe. Omit it and the dependency components stay ``None``.
    """
    scopes, depth, delegates_further = _grant_profile(fw, subject_id)
    worst = fw.config.worst_reversibility(scopes)

    eta, exposure = permission_exposure(
        scopes,
        weights=permission_weights,
        class_overrides=scope_permission_classes,
    )
    observed, autonomous = _authority_counts(fw, subject_id, since=since)
    tier, evidence = governance_tier(fw)

    return RiskState(
        subject_id=subject_id,
        alpha=autonomy_category(
            depth=depth, worst=worst, delegates_further=delegates_further
        ),
        beta=(autonomous / observed) if observed else None,
        eta=eta,
        eta_exposure=exposure,
        governance_tier=tier,
        governance_evidence=evidence,
        dependency_shares=dependency_shares,
        dependency_concentration=(
            herfindahl(dependency_shares) if dependency_shares else None
        ),
        actions_observed=observed,
        actions_autonomous=autonomous,
        worst_reversibility=worst,
    )


def _grant_profile(fw: "Firewall", subject_id: str) -> tuple[list[str], int, bool]:
    """Scopes held by ``subject_id``, its deepest token, and whether it delegated.

    Reads durable token metadata rather than any token the caller presents, on
    the same principle as :meth:`Firewall.chain`: a subject should not be the
    sole source of its own provenance.
    """
    scopes: set[str] = set()
    deepest = 0
    delegated = False

    for row in fw.audit_events(action="root_minted") + fw.audit_events(
        action="delegated"
    ):
        jti = row.get("jti")
        if not jti:
            continue
        meta = fw.storage.get_token(jti)
        if meta is None or meta.subject_id != subject_id:
            continue
        scopes.update(meta.scopes)
        deepest = max(deepest, meta.depth)
        if fw.storage.children_of([jti]):
            delegated = True

    return sorted(scopes), deepest, delegated


def _authority_counts(
    fw: "Firewall", subject_id: str, *, since: _dt.datetime | None
) -> tuple[int, int]:
    """``(total_actions, autonomous_actions)`` for the paper's beta estimator.

    An action counts as autonomous when the token it ran under was not minted
    through the human-approval gate. That is the operative question the paper
    asks -- did a human authorise this execution path -- and agperms records the
    answer durably in ``TokenMetadata.approval_required``.
    """
    total = 0
    autonomous = 0

    for row in fw.audit_events(action="action_started"):
        if row.get("actor_id") != subject_id:
            continue
        if since is not None and not _row_at_or_after(row, since):
            continue
        total += 1
        jti = row.get("jti")
        meta = fw.storage.get_token(jti) if jti else None
        # No metadata means we cannot establish that a human approved it. Count
        # it as autonomous: assuming an unverifiable approval happened would
        # flatter the score in exactly the direction that matters.
        if meta is None or not meta.approval_required:
            autonomous += 1

    return total, autonomous


def _row_at_or_after(row: dict[str, object], since: _dt.datetime) -> bool:
    raw = row.get("event_ts")
    if not isinstance(raw, str):
        return True
    try:
        stamp = as_utc(_dt.datetime.fromisoformat(raw))
    except ValueError:
        return True
    bound = as_utc(since)
    if stamp is None or bound is None:
        return True
    return stamp >= bound


__all__ = [
    "DEFAULT_SCOPE_PERMISSION_CLASS",
    "PERMISSION_WEIGHTS",
    "RiskState",
    "autonomy_category",
    "compute_risk_state",
    "governance_tier",
    "herfindahl",
    "permission_class_of",
    "permission_exposure",
]
