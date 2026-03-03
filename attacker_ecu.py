"""
attacker_ecu.py
---------------
AttackerECU — implements the WeepingCAN attack logic.
Modello DES con fisica e deviazione standard gaussiana.
"""
from __future__ import annotations
import random
from ecu import ECU, ECUState
from can_bus import CANFrame, build_physical_frame
from logger import get_logger, RED, YELLOW, CYAN, MAGENTA, GREEN, GRAY, RESET

N_VALID_MSGS = 5
SKIP_TEC_THRESHOLD: int = 6

# --- Variabili Fisiche DES ---
BAUD_RATE_KBPS = 500
BIT_TIME_US    = 1000.0 / BAUD_RATE_KBPS  # 2.0 µs per bit
ATTACKER_JITTER_STD_DEV_US = 0.65         # Deviazione standard dell'oscillatore (µs)

# Indici logici calcolati relativi allo START del campo dati
SAFE_INJECT_POSITIONS: list[int] = [2, 7, 9, 11, 14, 18, 23]

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
        
        # Variabili richieste dal motore DES in simulation.py
        self._last_action   = ""
        self.valid_msgs_sent_last_cycle = 0

    def analyze_pattern(self, victim_can_id: int, victim_period_ms: int) -> None:
        self.target_can_id = victim_can_id
        get_logger().attack(
            f"{CYAN}\n[{self.name}] Pattern analysis complete → "
            f"target CAN-ID=0x{victim_can_id:03X}{RESET}"
        )

    def _calculate_jitter_result(self, inject_pos: int) -> bool:
        """
        Determina deterministicamente se l'attacco va a segno calcolando
        lo scostamento fisico (jitter) in microsecondi rispetto alla finestra del bit.
        """
        ideal_time_us = inject_pos * BIT_TIME_US
        # Aggiunge rumore gaussiano all'orologio dell'attaccante
        actual_time_us = ideal_time_us + random.gauss(0, ATTACKER_JITTER_STD_DEV_US)
        
        # La finestra per sovrascrivere il bit è centrata sul tempo ideale, larga 1 bit_time
        window_start = ideal_time_us - (BIT_TIME_US / 2)
        window_end   = ideal_time_us + (BIT_TIME_US / 2)
        
        log = get_logger()
        log.raw(f"{GRAY}  [PHYSICS] Bit pos: {inject_pos} | Ideal time: {ideal_time_us:.2f} µs | Actual: {actual_time_us:.2f} µs{RESET}")

        if window_start <= actual_time_us <= window_end:
            return True # Iniezione centrata
        else:
            log.raw(f"{YELLOW}  [PHYSICS] Drift superato! Missed window [{window_start:.2f}, {window_end:.2f}]{RESET}")
            return False # Fuori sincrono (mis-timed)

    def _make_attack_frame(self, victim_frame: CANFrame) -> CANFrame:
        mirrored_data = list(victim_frame.data)
        _, data_index_map = build_physical_frame(self.target_can_id, mirrored_data)
        
        safe_stuffed_positions = [
            data_index_map[pos] for pos in SAFE_INJECT_POSITIONS 
            if pos < len(data_index_map)
        ]
        
        return CANFrame(
            can_id              = self.target_can_id,
            data                = mirrored_data,
            sender_id           = self.name,
            inject_recessive_at = random.choice(safe_stuffed_positions),
            is_malicious        = True,
        )

    def _should_skip(self) -> bool:
        return self.tec >= SKIP_TEC_THRESHOLD

    def _execute_skip(self, victim_frame: CANFrame) -> bool:
        log = get_logger()
        self._skip_count += 1
        self._last_action = "SKIP"
        self.valid_msgs_sent_last_cycle = N_VALID_MSGS

        log.attack(f"{GREEN}\n[{self.name}] SKIP CYCLE #{self._skip_count} (TEC={self.tec}){RESET}")

        victim_node = self.bus._nodes.get(victim_frame.sender_id) if self.bus else None
        if victim_node and victim_node.state != ECUState.BUS_OFF:
            victim_node._decrement_tec(1)
            victim_node._check_state_transition()

        if self.bus:
            self.bus.transmit_valid(self.name, N_VALID_MSGS)
        self._valid_count += N_VALID_MSGS

        return True

    def _execute_mistimed(self, victim_frame: CANFrame) -> bool:
        log = get_logger()
        self._mistimed_count += 1
        self._last_action = "MISTIMED"
        self.valid_msgs_sent_last_cycle = 0

        log.attack(f"{YELLOW}\n[{self.name}] ⚠ MIS-TIMED INJECTION (Physics Drift){RESET}")

        victim_node = self.bus._nodes.get(victim_frame.sender_id) if self.bus else None
        if victim_node and victim_node.state != ECUState.BUS_OFF:
            victim_node._decrement_tec(1)
            victim_node._check_state_transition()

        return True

    def _execute_attack(self, victim_frame: CANFrame) -> bool:
        log = get_logger()
        self._attack_count += 1
        tec_cycle_start = self.tec
        self._last_action = "ATTACK"

        log.attack(f"{RED}\n[{self.name}] ATTACK CYCLE #{self._attack_count} (TEC={tec_cycle_start}){RESET}")

        attack_frame = self._make_attack_frame(victim_frame)
        
        # Valutazione fisica del jitter
        if not self._calculate_jitter_result(attack_frame.inject_recessive_at):
            return self._execute_mistimed(victim_frame)

        self.send(attack_frame, concurrent_frame=victim_frame)
        
        if self.bus:
            self.bus.transmit_valid(self.name, N_VALID_MSGS)
            self.valid_msgs_sent_last_cycle = N_VALID_MSGS
        self._valid_count += N_VALID_MSGS

        return True

    def attack(self, victim_frame: CANFrame) -> bool:
        if self.state != ECUState.ERROR_ACTIVE:
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