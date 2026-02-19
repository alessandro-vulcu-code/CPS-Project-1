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


class AttackerECU(ECU):
    def __init__(self, name: str = "ATTACKER", target_can_id: int = 0x100,
                 verbose: bool = True):
        super().__init__(name, verbose)
        self.target_can_id  = target_can_id
        self.healing_can_id = 0x010          # high-priority ID used during post-error healing
        self._attack_count  = 0
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
        total_bits    = 11 + len(mirrored_data) * 8
        inject_pos    = random.randint(11, total_bits - 1)

        get_logger().attack(
            f"{MAGENTA}\n[{self.name}] Building attack frame  "
            f"CAN-ID=0x{self.target_can_id:03X}  "
            f"recessive-inject-at bit {inject_pos}{RESET}"
        )
        return CANFrame(
            can_id              = self.target_can_id,
            data                = mirrored_data,
            sender_id           = self.name,
            inject_recessive_at = inject_pos,
            is_malicious        = True,
        )

    def attack(self, victim_frame: CANFrame) -> bool:
        log = get_logger()
        if self.state != ECUState.ERROR_ACTIVE:
            log.attack(
                f"{RED}[{self.name}] Not in Error-Active state "
                f"(state={self.state}, TEC={self.tec}). Attack aborted.{RESET}"
            )
            return False

        self._attack_count += 1
        log.attack(
            f"{RED}\n{'═'*70}\n"
            f"[{self.name}] ATTACK CYCLE #{self._attack_count}  "
            f"(attacker TEC={self.tec})\n"
            f"{'═'*70}{RESET}"
        )

        attack_frame = self._make_attack_frame(victim_frame)
        old_tec = self.tec
        self.send(attack_frame, concurrent_frame=victim_frame)

        # Arbitraggio e cure SOLO se l'attacco ha causato un errore (TEC dell'attaccante è salito)
        if self.bus and self.tec > old_tec:
            self.bus.resolve_post_error_arbitration(
                victim_name    = victim_frame.sender_id,
                attacker_name  = self.name,
                victim_id      = victim_frame.can_id,
                healing_id     = self.healing_can_id,
                n_healing_msgs = N_VALID_MSGS,
            )
            self._valid_count += N_VALID_MSGS

        log.attack(
            f"{YELLOW}\n[{self.name}] After cycle #{self._attack_count}: "
            f"TEC={self.tec}  state={self.state}{RESET}"
        )
        return True

    def stats(self) -> str:
        return (f"[{self.name}] Attack cycles={self._attack_count}  "
                f"Valid msgs sent={self._valid_count}  "
                f"TEC={self.tec}  state={self.state}")
