"""
can_bus.py
----------
Simula il bus CAN. Modificato per modellare un frame CAN 2.0A completo
e unificare il campo Control (IDE, r0, DLC).
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
    """Rappresenta un frame CAN 2.0A logico."""
    can_id:              int
    data:                List[int]
    sender_id:           str
    inject_recessive_at: Optional[int] = None
    is_malicious:        bool = False


def id_to_bits(can_id: int, length: int = 11) -> List[int]:
    return [(can_id >> (length - 1 - i)) & 1 for i in range(length)]


def data_to_bits(data: List[int]) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def calculate_mock_crc(bits: List[int]) -> List[int]:
    """Genera un CRC-15 simulato basato su xor per mantenere coerenza dimensionale."""
    crc = 0x45A9 # Valore base arbitrario
    for b in bits:
        crc ^= b
    return [(crc >> i) & 1 for i in range(14, -1, -1)]


def build_physical_frame(can_id: int, data: List[int]) -> tuple[List[int], List[int]]:
    """
    Costruisce la rappresentazione fisica del frame CAN.
    Restituisce:
      - physical_stream: Il flusso completo di bit sul cavo.
      - data_index_map: Mappa che collega l'indice logico all'interno del DATA FIELD 
                        al rispettivo indice fisico nel physical_stream.
    """
    # 1. Campi soggetti a Bit Stuffing
    sof      = [DOMINANT]
    id_bits  = id_to_bits(can_id)
    rtr      = [DOMINANT] # Data frame
    
    # Control Field (6 bit): IDE (1) + r0 (1) + DLC (4)
    dlc_val  = len(data)
    dlc_bits = [(dlc_val >> i) & 1 for i in range(3, -1, -1)]
    control_bits = [DOMINANT, DOMINANT] + dlc_bits
    
    data_bits = data_to_bits(data)
    
    header_bits = sof + id_bits + rtr + control_bits
    crc_bits    = calculate_mock_crc(header_bits + data_bits)
    
    stuffable_section = header_bits + data_bits + crc_bits
    
    # Applicazione Bit Stuffing
    stuffed_section = []
    data_index_map = []
    
    count = 0
    last_bit = -1
    logical_data_start = len(header_bits)
    logical_data_end = logical_data_start + len(data_bits)
    
    for i, bit in enumerate(stuffable_section):
        if bit == last_bit:
            count += 1
        else:
            count = 1
            last_bit = bit

        stuffed_section.append(bit)
        
        # Mappatura specifica per gli indici del campo dati
        if logical_data_start <= i < logical_data_end:
            data_index_map.append(len(stuffed_section) - 1)

        if count == 5:
            stuff_bit = 1 - last_bit
            stuffed_section.append(stuff_bit)
            count = 1
            last_bit = stuff_bit
            
    # 2. Campi NON soggetti a Bit Stuffing
    crc_delim  = [RECESSIVE]
    ack_slot   = [RECESSIVE] # Trasmesso come recessivo
    ack_delim  = [RECESSIVE]
    eof        = [RECESSIVE] * 7
    
    tail_section = crc_delim + ack_slot + ack_delim + eof
    
    physical_stream = stuffed_section + tail_section
    return physical_stream, data_index_map


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

        physical_stream, _ = build_physical_frame(frame.can_id, frame.data)
        log.bits("PHYSICAL bits:", physical_stream, YELLOW)

        if concurrent is not None:
            log.bus(f"{MAGENTA}\n[BUS] Simultaneous transmissions → ARBITRATION{RESET}")
            victim_stream, _ = build_physical_frame(concurrent.can_id, concurrent.data)

            winner_id = "TIE"
            for i, (vb, ab) in enumerate(zip(victim_stream, physical_stream)):
                bus_bit = DOMINANT if (vb == DOMINANT or ab == DOMINANT) else RECESSIVE
                if vb != ab:
                    winner_id = (concurrent.sender_id if vb == DOMINANT else frame.sender_id)
                    log.bus(
                        f"{MAGENTA}  Arbitration lost at physical bit {i}: "
                        f"bus={bus_bit}  victim={vb}  attacker={ab}  "
                        f"→ winner={winner_id}{RESET}"
                    )
                    break
            if winner_id == "TIE":
                log.bus(f"{MAGENTA}  Arbitration: SAME ID → both transmit together{RESET}")

        if frame.is_malicious and frame.inject_recessive_at is not None:
            inject_pos = frame.inject_recessive_at
            log.bus(f"{RED}\n[BUS] ATTACKER injects RECESSIVE bit at physical position {inject_pos}{RESET}")

            if concurrent:
                victim_stream_local, _ = build_physical_frame(concurrent.can_id, concurrent.data)
            else:
                victim_stream_local = physical_stream

            victim_sent = victim_stream_local[inject_pos] if inject_pos < len(victim_stream_local) else DOMINANT
            attacker_sent = RECESSIVE
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
                log.tec(f"{GREEN}  Victim ({victim_name}) TEC: {old} → {victim_node.tec}  "
                        f"[cycle net so far: +7]{RESET}")
                victim_node._check_state_transition()
            else:
                log.tec(f"{RED}\n[BUS] Victim ({victim_name}) is BUS-OFF — cannot retransmit!{RESET}")

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