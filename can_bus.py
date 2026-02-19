"""
can_bus.py
----------
Simulates the CAN shared bus medium.
All output goes through the centralised SimLogger (logger.py).
"""

import threading
from dataclasses import dataclass
from typing import Optional, List

from logger import (
    get_logger,
    RED, GREEN, YELLOW, CYAN, MAGENTA, WHITE, GRAY, BOLD, RESET,
)

DOMINANT  = 0
RECESSIVE = 1

ACTIVE_ERROR_FLAG  = [DOMINANT]  * 6
PASSIVE_ERROR_FLAG = [RECESSIVE] * 6
ERROR_DELIMITER    = [RECESSIVE] * 8


@dataclass
class CANFrame:
    """Represents a CAN 2.0A frame (11-bit ID)."""
    can_id:              int
    data:                List[int]
    sender_id:           str
    inject_recessive_at: Optional[int] = None
    is_malicious:        bool = False


def _id_to_bits(can_id: int, length: int = 11) -> List[int]:
    return [(can_id >> (length - 1 - i)) & 1 for i in range(length)]


def _data_to_bits(data: List[int]) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


class CANBus:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._nodes: dict = {}
        self._lock  = threading.Lock()

    def register(self, ecu) -> None:
        self._nodes[ecu.name] = ecu
        get_logger().bus(f"{GRAY}[BUS] Node registered: {ecu.name}{RESET}")

    def transmit(self, frame: CANFrame,
                 concurrent_frame: Optional[CANFrame] = None) -> bool:
        with self._lock:
            return self._do_transmit(frame, concurrent_frame)

    def _do_transmit(self, frame: CANFrame,
                     concurrent: Optional[CANFrame]) -> bool:
        log = get_logger()
        log.separator("─", 70, CYAN)
        log.bus(
            f"{CYAN}[BUS] Transmission attempt  sender={frame.sender_id}  "
            f"CAN-ID=0x{frame.can_id:03X}  malicious={frame.is_malicious}{RESET}"
        )

        id_bits   = _id_to_bits(frame.can_id)
        data_bits = _data_to_bits(frame.data)

        log.bits("CAN-ID bits (11-bit):", id_bits,   YELLOW)
        log.bits("DATA bits:",            data_bits,  WHITE)

        if concurrent is not None:
            log.bus(f"{MAGENTA}\n[BUS] Simultaneous transmissions → ARBITRATION{RESET}")
            victim_id_bits   = _id_to_bits(concurrent.can_id)
            attacker_id_bits = id_bits
            log.bits("Victim  CAN-ID bits:",  victim_id_bits,   GREEN)
            log.bits("Attacker CAN-ID bits:", attacker_id_bits, RED)

            winner_id = "TIE"
            for i, (vb, ab) in enumerate(zip(victim_id_bits, attacker_id_bits)):
                bus_bit = DOMINANT if (vb == DOMINANT or ab == DOMINANT) else RECESSIVE
                if vb != ab:
                    winner_id = (concurrent.sender_id if vb == DOMINANT else frame.sender_id)
                    log.bus(
                        f"{MAGENTA}  Arbitration lost at bit {i}: "
                        f"bus={bus_bit}  victim={vb}  attacker={ab}  "
                        f"→ winner={winner_id}{RESET}"
                    )
                    break
            if winner_id == "TIE":
                log.bus(f"{MAGENTA}  Arbitration: SAME ID → both transmit together (WeepingCAN){RESET}")

        if frame.is_malicious and frame.inject_recessive_at is not None:
            inject_pos = frame.inject_recessive_at
            log.bus(f"{RED}\n[BUS] ATTACKER injects RECESSIVE bit at position {inject_pos}{RESET}")

            victim_data_bits = _data_to_bits(concurrent.data) if concurrent else data_bits[:]
            victim_full = (
                _id_to_bits(concurrent.can_id if concurrent else frame.can_id)
                + victim_data_bits
            )

            attacker_sent = RECESSIVE
            victim_sent   = victim_full[inject_pos] if inject_pos < len(victim_full) else DOMINANT
            bus_result    = DOMINANT if (victim_sent == DOMINANT or attacker_sent == DOMINANT) else RECESSIVE

            log.bits(f"Attacker bit @ pos {inject_pos}:", [attacker_sent], RED)
            log.bits(f"Victim   bit @ pos {inject_pos}:", [victim_sent],   GREEN)
            log.bits("Bus result (wire-AND):",             [bus_result],    YELLOW)

            if attacker_sent == RECESSIVE and bus_result == DOMINANT:
                log.bus(
                    f"{RED}\n[BUS] BIT ERROR detected by attacker "
                    f"(sent={attacker_sent}, read={bus_result}){RESET}"
                )
                self._emit_error_flag(
                    frame.sender_id,
                    concurrent.sender_id if concurrent else None,
                )
                return False

        log.bus(f"{GREEN}\n[BUS] Frame transmitted successfully by {frame.sender_id}{RESET}")
        self._deliver_frame(frame)
        return True

    def _emit_error_flag(self, attacker_name: str, victim_name: Optional[str]) -> None:
        log = get_logger()
        log.error_flag(f"{RED}\n[BUS] ══ ERROR FLAG SEQUENCE ══{RESET}")

        attacker_node = self._nodes.get(attacker_name)
        if attacker_node and attacker_node.tec >= 128:
            flag, flag_label, flag_color = PASSIVE_ERROR_FLAG, "PASSIVE Error Flag", YELLOW
        else:
            flag, flag_label, flag_color = ACTIVE_ERROR_FLAG,  "ACTIVE Error Flag",  RED

        log.bits(f"{flag_label} (attacker):", flag,           flag_color)
        log.bits("Error Delimiter:",          ERROR_DELIMITER, GRAY)
        log.tec(f"{YELLOW}\n[BUS] TEC update (+8 to both nodes):{RESET}")

        if attacker_node:
            old = attacker_node.tec
            attacker_node._increment_tec(8)
            log.tec(f"{YELLOW}  Attacker ({attacker_name}) TEC: {old} → {attacker_node.tec}{RESET}")

        victim_node = self._nodes.get(victim_name) if victim_name else None
        if victim_node:
            old = victim_node.tec
            victim_node._increment_tec(8)
            log.tec(f"{YELLOW}  Victim   ({victim_name})   TEC: {old} → {victim_node.tec}{RESET}")
            victim_node._check_state_transition()

            if victim_node.state != "Bus-Off":
                log.tec(f"{GREEN}\n[BUS] Victim ({victim_name}) retransmits... SUCCESS → TEC -1{RESET}")
                old = victim_node.tec
                victim_node._decrement_tec(1)
                log.tec(f"{GREEN}  Victim ({victim_name}) TEC: {old} → {victim_node.tec}{RESET}")
                victim_node._check_state_transition()
            else:
                log.tec(f"{RED}\n[BUS] Victim ({victim_name}) is BUS-OFF — cannot retransmit!{RESET}")

        if attacker_node:
            attacker_node._check_state_transition()

    def _deliver_frame(self, frame: CANFrame) -> None:
        for name, node in self._nodes.items():
            if name != frame.sender_id:
                node._receive(frame)

    def transmit_valid(self, sender_name: str, n: int = 1) -> None:
        node = self._nodes.get(sender_name)
        if node is None:
            return
        log = get_logger()
        log.bus(f"{GRAY}\n[BUS] {sender_name} sends {n} valid frame(s) → TEC -{n}{RESET}")
        for _ in range(n):
            if node.tec > 0:
                node._decrement_tec(1)
        log.bus(f"{GRAY}  {sender_name} TEC now: {node.tec}{RESET}")
        node._check_state_transition()
