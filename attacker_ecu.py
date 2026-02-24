"""
attacker_ecu.py
---------------
AttackerECU — implements the WeepingCAN attack logic.
"""
from __future__ import annotations
import random
from ecu import ECU, ECUState
from can_bus import CANFrame
from logger import get_logger, RED, YELLOW, CYAN, MAGENTA, GREEN, GRAY, RESET

N_VALID_MSGS = 5

# ── Probabilistic realism: hardware sync jitter ──────────────────────────
# Probability that the attacker loses perfect synchronization during an
# injection cycle, causing a "mis-timed" injection (see paper §IV-B).
# When this happens the injected recessive bit lands on a random position
# and is very likely to hit another recessive bit, producing no bus error.
SYNC_ERROR_PROBABILITY: float = 0.05   # 5 %

# Bit positions derived from offline traffic analysis of the victim's known-static payload.
# Victim data template: [0xDE, 0xAD, 0xBE, <seq>]
#   0xDE = 1101_1110  →  zeros at frame offsets 13, 18
#   0xAD = 1010_1101  →  zeros at frame offsets 20, 22, 25
#   0xBE = 1011_1110  →  zeros at frame offsets 28, 34
# The seq byte (offsets 35–42) is excluded: it changes every cycle.
# Injecting a recessive (1) at any of these positions guarantees the victim is
# driving dominant (0) there, so the wire-AND exposes a bit error to the attacker.
SAFE_INJECT_POSITIONS: list[int] = [13, 18, 20, 22, 25, 28, 34]

# Skipping threshold: if the attacker's TEC is at or above this value at the
# start of a cycle, the attacker deliberately skips the attack and sends only
# valid frames instead.  This keeps the attacker's TEC oscillating near zero
# (well below the Error-Passive boundary of 128) while the victim's TEC still
# climbs inexorably toward Bus-Off.
#
# Math with SKIP_TEC_THRESHOLD = 6 (≈ 2 attacks per skip in steady state):
#   Attack cycle : attacker +3,  victim +7
#   Skip   cycle : attacker −5,  victim −1
#   Attacker TEC : oscillates in [0, ~8]  → always Error-Active
#   Victim   TEC : net ≈ +20 per 3 cycles → Bus-Off after ~38 × 3/2 = ~57 cycles
SKIP_TEC_THRESHOLD: int = 6


class AttackerECU(ECU):
    def __init__(self, name: str = "ATTACKER", target_can_id: int = 0x100,
                 verbose: bool = True):
        super().__init__(name, verbose)
        self.target_can_id  = target_can_id
        self._attack_count  = 0
        self._skip_count    = 0
        self._mistimed_count = 0
        self._cycle_count   = 0
        self._valid_count   = 0

    def analyze_pattern(self, victim_can_id: int, victim_period_ms: int) -> None:
        self.target_can_id = victim_can_id
        get_logger().attack(
            f"{CYAN}\n[{self.name}] Pattern analysis complete → "
            f"target CAN-ID=0x{victim_can_id:03X}  "
            f"period≈{victim_period_ms}ms{RESET}"
        )

    def _make_attack_frame(self, victim_frame: CANFrame) -> CANFrame:
        mirrored_data = list(victim_frame.data)
        inject_pos    = random.choice(SAFE_INJECT_POSITIONS)

        get_logger().attack(
            f"{MAGENTA}\n[{self.name}] Building attack frame  "
            f"CAN-ID=0x{self.target_can_id:03X}  "
            f"recessive-inject-at bit {inject_pos}  "
            f"(targeted — safe pool: {SAFE_INJECT_POSITIONS}){RESET}"
        )
        return CANFrame(
            can_id              = self.target_can_id,
            data                = mirrored_data,
            sender_id           = self.name,
            inject_recessive_at = inject_pos,
            is_malicious        = True,
        )

    def _should_skip(self) -> bool:
        """Decide whether to skip this attack cycle to keep TEC near zero.

        The heuristic is simple: if TEC >= SKIP_TEC_THRESHOLD the attacker
        deliberately skips, letting the victim send without interference while
        the attacker sends N_VALID_MSGS valid frames to drain its own TEC.
        """
        return self.tec >= SKIP_TEC_THRESHOLD

    def _execute_skip(self, victim_frame: CANFrame) -> bool:
        """Execute a 'skip' cycle — no error injection.

        During a skipped cycle:
          • The victim sends its message without interference → TEC victim −1.
          • The attacker sends N_VALID_MSGS valid frames      → TEC attacker −5
            (clamped at 0).
        """
        log = get_logger()
        self._skip_count += 1
        tec_cycle_start = self.tec

        log.attack(
            f"{GREEN}\n{'─'*70}\n"
            f"[{self.name}] SKIP CYCLE #{self._skip_count}  "
            f"(attacker TEC={tec_cycle_start} ≥ threshold={SKIP_TEC_THRESHOLD})\n"
            f"{'─'*70}{RESET}"
        )

        # ── Victim sends in peace: its TEC −1 (successful transmission) ──────
        victim_node = self.bus._nodes.get(victim_frame.sender_id) if self.bus else None
        if victim_node and victim_node.state != ECUState.BUS_OFF:
            old_vtec = victim_node.tec
            victim_node._decrement_tec(1)
            victim_node._check_state_transition()
            log.attack(
                f"{GREEN}[{self.name}] Skip — victim transmits OK → "
                f"Victim TEC: {old_vtec} → {victim_node.tec}  (−1){RESET}"
            )

        # ── Attacker sends N_VALID_MSGS valid frames: TEC −5 (min 0) ─────────
        if self.bus:
            tec_before_valid = self.tec
            self.bus.transmit_valid(self.name, N_VALID_MSGS)
            actual_decrease = tec_before_valid - self.tec
            log.attack(
                f"{GREEN}[{self.name}] Skip — {N_VALID_MSGS} valid frames: "
                f"Attacker TEC: {tec_before_valid} → {self.tec}  "
                f"(−{actual_decrease}){RESET}"
            )
        self._valid_count += N_VALID_MSGS

        log.attack(
            f"{GREEN}[{self.name}] After skip #{self._skip_count}: "
            f"TEC={self.tec}  state={self.state}  "
            f"[cycle net attacker: {self.tec - tec_cycle_start:+d}  "
            f"| cycle net victim: −1]{RESET}"
        )
        return True

    def _execute_mistimed(self, victim_frame: CANFrame) -> bool:
        """Handle a mis-timed injection — attacker loses sync.

        The injected recessive bit lands on a random frame position.
        With very high probability the random position carries a recessive (1)
        bit from the victim, so overwriting 1 with 1 produces no bus error.
        The victim's transmission succeeds normally (TEC −1) and the attacker
        simply wastes the cycle.
        """
        log = get_logger()
        self._mistimed_count += 1

        log.attack(
            f"{YELLOW}\n{'~'*70}\n"
            f"[{self.name}] ⚠ MIS-TIMED INJECTION  "
            f"(attacker TEC={self.tec})\n"
            f"{'~'*70}{RESET}"
        )
        log.bus(
            f"{YELLOW}[BUS] Injection mis-timed! "
            f"Attacker missed the dominant bit. Attack cycle failed.{RESET}"
        )

        # Victim's frame goes through without interference → TEC victim −1
        victim_node = (
            self.bus._nodes.get(victim_frame.sender_id) if self.bus else None
        )
        if victim_node and victim_node.state != ECUState.BUS_OFF:
            old_vtec = victim_node.tec
            victim_node._decrement_tec(1)
            victim_node._check_state_transition()
            log.attack(
                f"{GREEN}[{self.name}] Mis-timed — victim transmits OK → "
                f"Victim TEC: {old_vtec} → {victim_node.tec}  (−1){RESET}"
            )

        # Attacker sent a harmless recessive bit — no bus error, no TEC change
        log.attack(
            f"{YELLOW}[{self.name}] Mis-timed — attacker sent harmless "
            f"recessive bit, no TEC penalty.  "
            f"(mistimed #{self._mistimed_count}){RESET}"
        )
        return True

    def _execute_attack(self, victim_frame: CANFrame) -> bool:
        """Execute a real attack cycle — inject error + send valid frames.

        During an attack cycle:
          • Error injection → TEC +8 to both attacker and victim.
          • Victim retransmits → TEC victim −1.  Net victim: +7.
          • Attacker sends N_VALID_MSGS valid frames → TEC −5.  Net attacker: +3.

        Before injecting, a sync-error check is performed.  If the attacker
        loses hardware synchronization (probability = SYNC_ERROR_PROBABILITY),
        the injection is mis-timed and the cycle is wasted.
        """
        log = get_logger()
        self._attack_count += 1
        tec_cycle_start = self.tec

        log.attack(
            f"{RED}\n{'═'*70}\n"
            f"[{self.name}] ATTACK CYCLE #{self._attack_count}  "
            f"(attacker TEC={tec_cycle_start})\n"
            f"{'═'*70}{RESET}"
        )

        # ── Sync-error jitter check ───────────────────────────────────────────
        if random.random() < SYNC_ERROR_PROBABILITY:
            return self._execute_mistimed(victim_frame)

        # ── Step 1: inject recessive bit → bit error → TEC +8 both nodes ─────
        attack_frame = self._make_attack_frame(victim_frame)
        self.send(attack_frame, concurrent_frame=victim_frame)
        log.attack(
            f"{RED}[{self.name}] Step 1 — error injected: "
            f"TEC +8: {tec_cycle_start} → {self.tec}{RESET}"
        )

        # ── Step 2 (victim side, handled by bus): victim retransmits → TEC −1 ─
        #    Net effect on victim per cycle: +8 − 1 = +7.

        # ── Step 3: attacker sends N_VALID_MSGS valid frames → TEC −5 ─────────
        #    Net effect on attacker per cycle: +8 − 5 = +3.
        if self.bus:
            tec_after_error = self.tec
            self.bus.transmit_valid(self.name, N_VALID_MSGS)
            log.attack(
                f"{YELLOW}[{self.name}] Step 3 — {N_VALID_MSGS} valid frames: "
                f"TEC −{N_VALID_MSGS}: {tec_after_error} → {self.tec}  "
                f"[cycle net: +{self.tec - tec_cycle_start}  "
                f"| victim cycle net: +7]{RESET}"
            )
        self._valid_count += N_VALID_MSGS

        log.attack(
            f"{YELLOW}\n[{self.name}] After attack #{self._attack_count}: "
            f"TEC={self.tec}  state={self.state}{RESET}"
        )
        return True

    def attack(self, victim_frame: CANFrame) -> bool:
        """Main entry point: decide whether to attack or skip, then execute."""
        log = get_logger()
        if self.state != ECUState.ERROR_ACTIVE:
            log.attack(
                f"{RED}[{self.name}] Not in Error-Active state "
                f"(state={self.state}, TEC={self.tec}). Attack aborted.{RESET}"
            )
            return False

        self._cycle_count += 1

        if self._should_skip():
            return self._execute_skip(victim_frame)
        else:
            return self._execute_attack(victim_frame)

    def stats(self) -> str:
        return (f"[{self.name}] Total cycles={self._cycle_count}  "
                f"Attack cycles={self._attack_count}  "
                f"Mis-timed={self._mistimed_count}  "
                f"Skip cycles={self._skip_count}  "
                f"Valid msgs sent={self._valid_count}  "
                f"TEC={self.tec}  state={self.state}")
