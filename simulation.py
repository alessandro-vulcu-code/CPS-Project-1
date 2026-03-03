"""
simulation.py
-------------
Orchestrates the WeepingCAN simulation using a Discrete Event Simulation (DES) model.
Time is tracked in microseconds (µs) based on baud rate, entirely replacing time.sleep().
"""

import sys

from logger      import init_logger, get_logger, RED, GREEN, YELLOW, CYAN, BOLD, RESET
from can_bus     import CANBus, build_physical_frame
from ecu         import ECUState
from victim_ecu  import VictimECU
from attacker_ecu import AttackerECU

BANNER = f"""
{CYAN}  WeepingCAN Bus-Off Attack Simulator (DES Engine){RESET}
{CYAN}  Time resolution: Microseconds (µs) | Baud Rate: 500 kbps{RESET}
"""

# Parametri fisici della rete
BAUD_RATE_KBPS = 500
BIT_TIME_US    = 1000.0 / BAUD_RATE_KBPS  # A 500 kbps, 1 bit = 2.0 µs

def run_simulation(max_time_ms: float | None = None,
                   verbose:     bool  = True,
                   log_dir:     str   = "logs",
                   no_log:      bool  = False) -> None:

    logger = init_logger(log_dir=log_dir, run_name="weepingcan_des", console=True)
    logger.raw(BANNER)

    VICTIM_CAN_ID = 0x100
    VICTIM_PERIOD_MS = 10.0
    VICTIM_PERIOD_US = VICTIM_PERIOD_MS * 1000.0

    bus      = CANBus(verbose=verbose)
    victim   = VictimECU(can_id=VICTIM_CAN_ID, period_ms=int(VICTIM_PERIOD_MS), verbose=verbose)
    attacker = AttackerECU(target_can_id=VICTIM_CAN_ID, verbose=verbose)

    victim.attach(bus)
    attacker.attach(bus)
    attacker.analyze_pattern(VICTIM_CAN_ID, int(VICTIM_PERIOD_MS))

    # Variabili temporali DES
    clock_us = 0.0
    victim_next_tx_us = 0.0
    attacker_busy_until_us = 0.0
    cycle = 0

    max_time_us = (max_time_ms * 1000.0) if max_time_ms else float('inf')

    try:
        while clock_us < max_time_us:
            # Avanza il tempo al prossimo evento della vittima
            clock_us = victim_next_tx_us
            cycle += 1

            logger.raw(f"\n{BOLD}{CYAN}--- TIMESTAMP: {clock_us/1000.0:.3f} ms ---{RESET}")

            try:
                victim_frame = victim.broadcast()
            except RuntimeError:
                break

            # Calcolo durata fisica del frame della vittima
            physical_stream, _ = build_physical_frame(victim_frame.can_id, victim_frame.data)
            frame_duration_us = len(physical_stream) * BIT_TIME_US

            # 1. Verifica congestione: l'attaccante è libero?
            if clock_us < attacker_busy_until_us:
                logger.raw(
                    f"{YELLOW}[SIM] Attacker BUSY cooling down "
                    f"(until {attacker_busy_until_us/1000.0:.3f} ms). Missed opportunity!{RESET}"
                )
                bus.transmit(victim_frame)
                victim_next_tx_us += VICTIM_PERIOD_US
                continue

            # 2. L'attaccante è libero, esegue logica di attacco
            ok = attacker.attack(victim_frame)
            if not ok:
                break

            # 3. Aggiornamento stato temporale basato sulle azioni intraprese
            if attacker._last_action == "ATTACK":
                # La vittima ritrasmette (costa frame_duration_us)
                # L'attaccante invia frame di raffreddamento validi (N_VALID_MSGS * frame_duration_us)
                cooldown_time_us = frame_duration_us + (attacker.valid_msgs_sent_last_cycle * frame_duration_us)
                attacker_busy_until_us = clock_us + cooldown_time_us
            elif attacker._last_action == "SKIP":
                # L'attaccante salta e invia frame di raffreddamento
                cooldown_time_us = attacker.valid_msgs_sent_last_cycle * frame_duration_us
                attacker_busy_until_us = clock_us + cooldown_time_us
            elif attacker._last_action == "MISTIMED":
                # Frame vittima passa normalmente
                attacker_busy_until_us = clock_us + frame_duration_us

            # Schedula prossimo frame vittima
            victim_next_tx_us += VICTIM_PERIOD_US

            logger.cycle_summary(
                cycle          = cycle,
                victim_tec     = victim.tec,
                attacker_tec   = attacker.tec,
                victim_state   = victim.state,
                attacker_state = attacker.state,
            )

            if victim.state == ECUState.BUS_OFF:
                msg = (
                    f"\n{BOLD}{RED}{'═'*60}{RESET}\n"
                    f"{BOLD}{RED}  VICTIM HAS GONE BUS-OFF at {clock_us/1000.0:.3f} ms!{RESET}\n"
                    f"{BOLD}{RED}{'═'*60}{RESET}"
                )
                logger.summary(msg)
                break

            if attacker.state != ECUState.ERROR_ACTIVE:
                logger.summary(
                    f"\n{BOLD}{YELLOW}[SIM] Attacker left Error-Active: "
                    f"{attacker.state}{RESET}"
                )
                break

    except KeyboardInterrupt:
        logger.raw(f"\n{YELLOW}[SIM] Interrupted by user.{RESET}")

    sep = BOLD + "═" * 60 + RESET
    logger.summary(f"\n{sep}")
    logger.summary(f"{BOLD}{CYAN}  SIMULATION COMPLETE (Time: {clock_us/1000.0:.3f} ms){RESET}")
    logger.summary(f"{sep}")
    logger.summary(f"  {victim.status()}")
    logger.summary(f"  {attacker.status()}")
    logger.summary(f"\n  {attacker.stats()}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WeepingCAN DES Simulator")
    parser.add_argument("--max-time-ms", type=float, default=2000.0, help="Max sim time in ms")
    parser.add_argument("--quiet", action="store_true", help="Suppress bit dumps")
    args = parser.parse_args()
    
    run_simulation(max_time_ms=args.max_time_ms, verbose=not args.quiet)