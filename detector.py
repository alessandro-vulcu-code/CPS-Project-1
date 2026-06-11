"""
detector.py
-----------
F1 attack detector for the WeepingCAN simulator.

Reproduces the bus-off attack detector of Cho & Shin [4] used by the
WeepingCAN paper (§II-C, §IV-A.3) to *measure* stealthiness.

Feature F1
----------
The original bus-off attack forces a victim frame into a cascade of
retransmissions: the *same* message ID fails repeatedly with no successful
transmission in between. A passive monitor on the bus flags this as
**feature F1 — consecutive errors on a single message ID**.

WeepingCAN avoids F1 by disabling retransmission of the attack message
``v_A`` (paper §III-C): every injected error is followed immediately by a
*successful* transmission of the same ID (the victim's retransmission),
so consecutive-error runs never exceed 1. The detector therefore reports
0% detection against a correct WeepingCAN run — which is exactly the
"stealth" claim the paper quantifies.

How it works
------------
The detector observes two bus events per CAN ID:

  * ``record_error(can_id)``    — a bit/stuff error flag was emitted for an
                                  in-flight frame with this ID.
  * ``record_success(can_id)``  — a frame with this ID transmitted cleanly.

It tracks the length of the current run of consecutive errors per ID. When
a success arrives (or the run is finalised at end-of-run), a run whose
length is >= ``consecutive_threshold`` is recorded as an F1 event.

Detection rate is reported as the fraction of *attacked frames* (= error
events) that occurred inside an F1 run, matching the paper's "% of attacks
identified" metric.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from logger import get_logger, RED, GREEN, YELLOW, BOLD, RESET

# An F1 event is a run of at least this many consecutive errors on one ID
# with no successful transmission in between. The original attack produces
# runs of ~16; healthy traffic / WeepingCAN never exceed 1.
DEFAULT_CONSECUTIVE_THRESHOLD = 2


@dataclass
class F1Detector:
    """Passive bus monitor that detects feature F1 (consecutive errors)."""

    consecutive_threshold: int = DEFAULT_CONSECUTIVE_THRESHOLD

    # ── Running state ────────────────────────────────────────────────────────
    _run_len:      Dict[int, int] = field(default_factory=dict)  # current error run per ID
    total_errors:    int = 0
    total_successes: int = 0
    max_consecutive: int = 0
    f1_events:       int = 0   # number of consecutive-error runs that tripped F1
    errors_in_f1:    int = 0   # error events that occurred inside an F1 run

    # ── Bus event hooks ──────────────────────────────────────────────────────
    def record_error(self, can_id: int) -> None:
        """An error flag was raised for an in-flight frame with *can_id*."""
        self.total_errors += 1
        run = self._run_len.get(can_id, 0) + 1
        self._run_len[can_id] = run
        if run > self.max_consecutive:
            self.max_consecutive = run

        if run == self.consecutive_threshold:
            # Run just reached the threshold → this is a fresh F1 event.
            self.f1_events += 1
            self.errors_in_f1 += run               # count the errors so far
            get_logger().attack(
                f"{RED}{BOLD}\n[F1-DETECTOR] ⚑ FEATURE F1 DETECTED on "
                f"CAN-ID=0x{can_id:03X}: {run} consecutive errors "
                f"(threshold={self.consecutive_threshold}){RESET}"
            )
        elif run > self.consecutive_threshold:
            # Still inside the same F1 run → keep counting its errors.
            self.errors_in_f1 += 1

    def record_success(self, can_id: int) -> None:
        """A frame with *can_id* transmitted cleanly → close any error run."""
        self.total_successes += 1
        self._run_len[can_id] = 0

    # ── Reporting ────────────────────────────────────────────────────────────
    @property
    def detection_rate(self) -> float:
        """Fraction of error events that fell inside an F1 run (0.0–1.0)."""
        if self.total_errors == 0:
            return 0.0
        return self.errors_in_f1 / self.total_errors

    @property
    def detected(self) -> bool:
        return self.f1_events > 0

    def report(self) -> str:
        verdict = (
            f"{RED}{BOLD}DETECTED — attack is NOT stealthy{RESET}"
            if self.detected else
            f"{GREEN}{BOLD}STEALTHY — F1 never triggered{RESET}"
        )
        return (
            f"[F1-DETECTOR] errors={self.total_errors}  "
            f"successes={self.total_successes}  "
            f"max-consecutive={self.max_consecutive}  "
            f"F1-events={self.f1_events}  "
            f"detection-rate={self.detection_rate*100:.1f}%  "
            f"→ {verdict}"
        )
