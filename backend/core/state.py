"""
VAPT Multi-Agent System — Scan Pipeline State Machine

Implements a deterministic finite automaton (DFA) that governs the order
in which scan phases execute.  Supports forward transitions, loop-backs
based on discovery results, and parallel phase execution.
"""

from enum import Enum
from typing import Callable, Awaitable, Optional
from loguru import logger

from core.models import ScanPhase


# ────────────────────────────────────────────────────────────────────
# Transition Table
# ────────────────────────────────────────────────────────────────────

# Maps each *source* phase to the set of *destination* phases that are
# legally reachable.  Terminal phases (completed / failed / cancelled)
# intentionally have no outgoing transitions.
TRANSITIONS: dict[ScanPhase, set[ScanPhase]] = {
    ScanPhase.INIT: {
        ScanPhase.RECON,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.RECON: {
        ScanPhase.ENUMERATION,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.ENUMERATION: {
        ScanPhase.VULN_SCANNING,
        ScanPhase.FUZZING,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.VULN_SCANNING: {
        ScanPhase.FUZZING,
        ScanPhase.EXPLOITATION,
        ScanPhase.INTELLIGENCE,
        ScanPhase.REPORTING,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.FUZZING: {
        ScanPhase.REPORTING,
        ScanPhase.EXPLOITATION,
        ScanPhase.INTELLIGENCE,
        ScanPhase.VULN_SCANNING,    # loop back if new endpoints found
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.EXPLOITATION: {
        ScanPhase.INTELLIGENCE,
        ScanPhase.REPORTING,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.INTELLIGENCE: {
        ScanPhase.REPORTING,
        ScanPhase.EXPLOITATION,     # loop back if new attack vectors found
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    ScanPhase.REPORTING: {
        ScanPhase.COMPLETED,
        ScanPhase.FAILED,
        ScanPhase.CANCELLED,
    },
    # Terminal states — no outgoing transitions
    ScanPhase.COMPLETED: set(),
    ScanPhase.FAILED: set(),
    ScanPhase.CANCELLED: set(),
}

# Phases that *any* phase can transition to regardless of the table above.
# These are implicitly included in every entry already, but we keep them
# here for semantic clarity and for ``should_loop_back`` logic.
EMERGENCY_TRANSITIONS: set[ScanPhase] = {
    ScanPhase.FAILED,
    ScanPhase.CANCELLED,
}

# Groups of phases that may safely execute in parallel.  The inner lists
# represent independent "lanes" that can be awaited concurrently.
PARALLEL_PHASE_GROUPS: list[list[ScanPhase]] = [
    [ScanPhase.VULN_SCANNING, ScanPhase.FUZZING],
    [ScanPhase.EXPLOITATION, ScanPhase.INTELLIGENCE],
]

# ────────────────────────────────────────────────────────────────────
# Loop-back triggers
# ────────────────────────────────────────────────────────────────────

# Context keys that, when present in the ``result_context`` dict, signal
# that the state machine should loop back to an earlier phase.
LOOP_BACK_TRIGGERS: dict[str, ScanPhase] = {
    "new_endpoints_found": ScanPhase.VULN_SCANNING,
    "new_attack_vectors": ScanPhase.EXPLOITATION,
}


class ScanStateMachine:
    """Deterministic state machine governing the VAPT scan pipeline.

    The machine holds a single ``current_phase`` and exposes methods to
    query valid transitions, advance the phase, and detect when a
    loop-back is warranted by fresh discovery data.

    Usage::

        sm = ScanStateMachine()
        assert sm.can_transition(ScanPhase.INIT, ScanPhase.RECON)
        sm.transition(ScanPhase.RECON)
        print(sm.current_phase)  # ScanPhase.RECON
    """

    def __init__(self) -> None:
        """Initialise the state machine at the ``init`` phase."""
        self.current_phase: ScanPhase = ScanPhase.INIT
        self._transition_history: list[tuple[ScanPhase, ScanPhase]] = []
        self._loop_back_count: int = 0
        self._max_loop_backs: int = 3
        logger.debug("State machine initialised at phase 'init'")

    # ── Query Methods ──────────────────────────────────────────────

    def can_transition(self, from_phase: ScanPhase, to_phase: ScanPhase) -> bool:
        """Check whether a transition from *from_phase* to *to_phase* is valid.

        Args:
            from_phase: The source phase.
            to_phase:   The destination phase.

        Returns:
            ``True`` if the transition is permitted by the transition table,
            ``False`` otherwise.
        """
        valid = TRANSITIONS.get(from_phase, set())
        return to_phase in valid

    def get_next_phases(self) -> list[ScanPhase]:
        """Return all phases that are valid next transitions from the current phase.

        Terminal phases will return an empty list.

        Returns:
            A list of ``ScanPhase`` values reachable from ``current_phase``.
        """
        valid = TRANSITIONS.get(self.current_phase, set())
        return sorted(valid, key=lambda p: p.value)

    def get_parallel_phases(self) -> list[list[ScanPhase]]:
        """Return groups of phases that may safely execute in parallel.

        Only returns groups where *at least one* phase in the group is
        a valid next phase from the current state.  This ensures the
        orchestrator does not launch parallel work that is not yet
        reachable.

        Returns:
            A list of phase-groups.  Each inner list contains phases that
            can be ``asyncio.gather``-ed together.
        """
        current_valid = set(self.get_next_phases())
        result: list[list[ScanPhase]] = []
        for group in PARALLEL_PHASE_GROUPS:
            overlap = [p for p in group if p in current_valid]
            if len(overlap) >= 2:
                result.append(overlap)
        return result

    # ── Transition Methods ─────────────────────────────────────────

    def transition(self, to_phase: ScanPhase) -> ScanPhase:
        """Advance the state machine to *to_phase*.

        Args:
            to_phase: The phase to transition to.

        Returns:
            The new ``current_phase`` after the transition.

        Raises:
            ValueError: If the transition is not permitted.
        """
        if not self.can_transition(self.current_phase, to_phase):
            valid = self.get_next_phases()
            valid_str = ", ".join(p.value for p in valid)
            raise ValueError(
                f"Invalid transition: {self.current_phase.value} → "
                f"{to_phase.value}.  Valid next phases: [{valid_str}]"
            )

        previous = self.current_phase
        self.current_phase = to_phase
        self._transition_history.append((previous, to_phase))

        is_loop_back = (
            to_phase in TRANSITIONS
            and any(
                ordered_phase == to_phase
                for ordered_phase in self._phase_order()
                if ordered_phase != previous
            )
            and self._phase_order().index(to_phase) < self._phase_order().index(previous)
        ) if to_phase in self._phase_order() and previous in self._phase_order() else False

        if is_loop_back:
            self._loop_back_count += 1
            logger.info(
                "State loop-back #{loop_count}: {prev} → {curr}",
                loop_count=self._loop_back_count,
                prev=previous.value,
                curr=to_phase.value,
            )
        else:
            logger.info(
                "State transition: {prev} → {curr}",
                prev=previous.value,
                curr=to_phase.value,
            )

        return self.current_phase

    def should_loop_back(self, result_context: dict) -> Optional[ScanPhase]:
        """Determine whether the pipeline should revisit an earlier phase.

        Inspects *result_context* for well-known keys (e.g.
        ``new_subdomains_found``) and returns the appropriate earlier
        phase to loop back to.  Respects a maximum loop-back count to
        prevent infinite cycles.

        Args:
            result_context: A dictionary that may contain discovery
                signals such as ``new_subdomains_found``, ``new_endpoints_found``,
                or ``new_attack_vectors``.

        Returns:
            The ``ScanPhase`` to loop back to, or ``None`` if no loop-back
            is warranted.
        """
        if self._loop_back_count >= self._max_loop_backs:
            logger.warning(
                "Maximum loop-back count ({max}) reached — proceeding forward",
                max=self._max_loop_backs,
            )
            return None

        for key, loop_phase in LOOP_BACK_TRIGGERS.items():
            if result_context.get(key):
                value = result_context[key]
                # Accept truthy values or explicit True / non-empty collections
                is_truthy = bool(value)
                if is_truthy and self.can_transition(self.current_phase, loop_phase):
                    logger.info(
                        "Loop-back triggered by '{key}' → {phase}",
                        key=key,
                        phase=loop_phase.value,
                    )
                    return loop_phase

        return None

    def reset(self) -> None:
        """Reset the state machine back to the ``init`` phase.

        Clears all transition history and loop-back counters.
        """
        self.current_phase = ScanPhase.INIT
        self._transition_history.clear()
        self._loop_back_count = 0
        logger.debug("State machine reset to 'init'")

    # ── Properties ─────────────────────────────────────────────────

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` if the current phase is a terminal state
        (completed, failed, or cancelled)."""
        return self.current_phase in (
            ScanPhase.COMPLETED,
            ScanPhase.FAILED,
            ScanPhase.CANCELLED,
        )

    @property
    def transition_count(self) -> int:
        """Return the total number of transitions that have occurred."""
        return len(self._transition_history)

    @property
    def history(self) -> list[tuple[ScanPhase, ScanPhase]]:
        """Return a copy of the full transition history as a list of
        ``(from_phase, to_phase)`` tuples."""
        return list(self._transition_history)

    # ── Internal Helpers ───────────────────────────────────────────

    @staticmethod
    def _phase_order() -> list[ScanPhase]:
        """Return the canonical forward ordering of non-terminal phases.

        This is used to determine whether a transition is a "loop-back"
        (going to an earlier phase) versus a forward progression.
        """
        return [
            ScanPhase.INIT,
            ScanPhase.RECON,
            ScanPhase.ENUMERATION,
            ScanPhase.VULN_SCANNING,
            ScanPhase.FUZZING,
            ScanPhase.EXPLOITATION,
            ScanPhase.INTELLIGENCE,
            ScanPhase.REPORTING,
        ]

    def __repr__(self) -> str:
        return (
            f"ScanStateMachine(current_phase={self.current_phase.value!r}, "
            f"transitions={self.transition_count})"
        )
