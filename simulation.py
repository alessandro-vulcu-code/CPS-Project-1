"""
simulation.py
-------------
Orchestrates the WeepingCAN simulation.
Initialises the SimLogger so every module writes to the same .log / .jsonl files.
"""

import sys
import time

from logger      import init_logger, get_logger, RED, GREEN, YELLOW, CYAN, BOLD, RESET
from can_bus     import CANBus
from ecu         import ECUState
from victim_ecu  import VictimECU
from attacker_ecu import AttackerECU


BANNER = f"""
{CYAN}  WeepingCAN Bus-Off Attack Simulator{RESET}
{CYAN}  Stealth variant — attacker stays Error-Active throughout{RESET}
"""


def run_simulation(max_cycles: int  = 100,
                   delay:      float = 0.05,
                   verbose:    bool  = True,
                   log_dir:    str   = "logs",
                   no_log:     bool  = False) -> None:

    # ── Init logger ────────────────────────────────────────────────────────────
    logger = init_logger(
        log_dir  = log_dir,
        run_name = "weepingcan",
        console  = True,          # always print to stdout
    )

    # Print and log the banner
    logger.raw(BANNER)
    logger.raw(
        f"  Log file  : {logger.get_log_path()}\n"
        f"  JSON log  : {logger.get_json_path()}"
    )

    # ── Setup ──────────────────────────────────────────────────────────────────
    VICTIM_CAN_ID = 0x100
    VICTIM_PERIOD = 10

    bus      = CANBus(verbose=verbose)
    victim   = VictimECU(can_id=VICTIM_CAN_ID, period_ms=VICTIM_PERIOD, verbose=verbose)
    attacker = AttackerECU(target_can_id=VICTIM_CAN_ID, verbose=verbose)

    victim.attach(bus)
    attacker.attach(bus)
    attacker.analyze_pattern(VICTIM_CAN_ID, VICTIM_PERIOD)

    logger.raw(f"\n{BOLD}{CYAN}Initial state:{RESET}")
    logger.raw(f"  {victim.status()}")
    logger.raw(f"  {attacker.status()}\n")

    # ── Main loop ──────────────────────────────────────────────────────────────
    cycle = 0
    try:
        while cycle < max_cycles:
            cycle += 1

            try:
                victim_frame = victim.broadcast()
            except RuntimeError:
                break

            ok = attacker.attack(victim_frame)
            if not ok:
                logger.raw(f"\n{RED}[SIM] Attacker could not attack. Stopping.{RESET}")
                break

            # Per-cycle summary (goes to console + both log files)
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
                    f"{BOLD}{RED}  VICTIM HAS GONE BUS-OFF after {cycle} cycle(s)!{RESET}\n"
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

            time.sleep(delay)

    except KeyboardInterrupt:
        logger.raw(f"\n{YELLOW}[SIM] Interrupted by user.{RESET}")

    # ── Final report ───────────────────────────────────────────────────────────
    sep = BOLD + "═" * 60 + RESET
    logger.summary(f"\n{sep}")
    logger.summary(f"{BOLD}{CYAN}  SIMULATION COMPLETE{RESET}")
    logger.summary(f"{sep}")
    logger.summary(f"\n  Cycles executed : {cycle}")
    logger.summary(f"  {victim.status()}")
    logger.summary(f"  {attacker.status()}")
    logger.summary(f"\n  {attacker.stats()}")

    if attacker.state == ECUState.ERROR_ACTIVE:
        logger.summary(f"\n  {GREEN}Attacker remained in Error-Active throughout.{RESET}")
    else:
        logger.summary(f"\n  {RED}Attacker left Error-Active — attack model violated!{RESET}")

    logger.summary(
        f"\n  Log saved to : {logger.get_log_path()}"
        f"\n  JSON saved to: {logger.get_json_path()}"
    )
    logger.raw("")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="WeepingCAN Bus-Off Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulation.py                        # verbose, saves logs/
  python simulation.py --quiet                # suppress bit dumps
  python simulation.py --max-cycles 200       # more cycles
  python simulation.py --log-dir /tmp/can     # custom log directory
  python simulation.py --no-log               # disable file logging
        """,
    )
    parser.add_argument("--max-cycles", type=int,   default=100,
                        help="Max simulation cycles (default: 100)")
    parser.add_argument("--delay",      type=float, default=0.05,
                        help="Seconds between cycles (default: 0.05)")
    parser.add_argument("--quiet",      action="store_true",
                        help="Suppress per-frame bit-stream dumps")
    parser.add_argument("--log-dir",    type=str,   default="logs",
                        help="Directory for log files (default: logs/)")
    parser.add_argument("--no-log",     action="store_true",
                        help="Disable file logging (console only)")
    args = parser.parse_args()

    run_simulation(
        max_cycles = args.max_cycles,
        delay      = args.delay,
        verbose    = not args.quiet,
        log_dir    = args.log_dir,
        no_log     = args.no_log,
    )
