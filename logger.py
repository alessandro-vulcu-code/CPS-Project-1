"""
logger.py
---------
Centralised logging for the WeepingCAN simulator.

Architecture
------------
Two handlers are attached to the root "weepingcan" logger:

  ┌─────────────────────────────────────────────────────────────────┐
  │  SimLogger                                                      │
  │                                                                 │
  │   write(msg, level) ──► ConsoleHandler  ──► stdout  (ANSI on)  │
  │                    └──► FileHandler     ──► .log    (ANSI off)  │
  └─────────────────────────────────────────────────────────────────┘

The file uses a structured plain-text format:
    2025-06-10 14:23:01.042 | INFO     | [BUS] Transmission attempt ...

A separate structured JSON log is also written so the simulation can be
replayed or analysed programmatically.

Usage (inside any module)
-------------------------
    from logger import get_logger
    log = get_logger()
    log.bus("Transmission attempt ...")
    log.attack("ATTACK CYCLE #1")
    log.error_flag("ACTIVE Error Flag: 0 0 0 0 0 0")
    log.tec("Victim TEC: 0 → 8")
    log.state_change("VICTIM", "Error-Active", "Error-Passive")
    log.cycle_summary(cycle=5, victim_tec=35, attacker_tec=15,
                      victim_state="Error-Active", attacker_state="Error-Active")
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── ANSI palette (re-exported so other modules don't need their own) ──────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# Regex to strip ANSI escape codes from a string
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove all ANSI colour/style escape sequences from *text*."""
    return _ANSI_RE.sub("", text)


# ── Custom log levels ─────────────────────────────────────────────────────────
# We add application-specific levels so each category can be filtered
# independently when replaying the log file.
LEVEL_BUS        = 21   # bus medium events
LEVEL_ATTACK     = 22   # attack cycle headline
LEVEL_BITS       = 23   # bit-stream dumps
LEVEL_ERROR_FLAG = 24   # error flag / TEC updates
LEVEL_STATE      = 25   # state transitions
LEVEL_CYCLE      = 26   # per-cycle summary table
LEVEL_SUMMARY    = 27   # end-of-simulation report

_CUSTOM_LEVELS = {
    "BUS":        LEVEL_BUS,
    "ATTACK":     LEVEL_ATTACK,
    "BITS":       LEVEL_BITS,
    "ERRFLAG":    LEVEL_ERROR_FLAG,
    "STATE":      LEVEL_STATE,
    "CYCLE":      LEVEL_CYCLE,
    "SUMMARY":    LEVEL_SUMMARY,
}

for _name, _val in _CUSTOM_LEVELS.items():
    logging.addLevelName(_val, _name)


# ── Plain-text file formatter ─────────────────────────────────────────────────
class PlainFormatter(logging.Formatter):
    """Formats records as   TIMESTAMP | LEVELNAME | message  (no ANSI)."""

    def format(self, record: logging.LogRecord) -> str:
        ts      = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level   = f"{record.levelname:<8}"
        message = strip_ansi(record.getMessage())
        return f"{ts} | {level} | {message}"


# ── Console formatter (keeps ANSI, adds subtle level prefix) ─────────────────
class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


# ── JSON structured log handler ───────────────────────────────────────────────
class JSONFileHandler(logging.FileHandler):
    """Writes one JSON object per line (JSON Lines / NDJSON format)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "ts":      datetime.fromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                "level":   record.levelname,
                "message": strip_ansi(record.getMessage()),
            }
            # Attach structured extras if present
            for key in ("cycle", "victim_tec", "attacker_tec",
                        "victim_state", "attacker_state",
                        "inject_pos", "bit_sent", "bit_read", "bus_result"):
                if hasattr(record, key):
                    entry[key] = getattr(record, key)
            self.stream.write(json.dumps(entry) + "\n")
            self.stream.flush()
        except Exception:
            self.handleError(record)


# ── SimLogger ─────────────────────────────────────────────────────────────────
class SimLogger:
    """
    Facade over the Python logging system.

    Parameters
    ----------
    log_dir   : directory where log files are written (created if absent)
    run_name  : base name for the log files (timestamp appended automatically)
    console   : whether to also print to stdout
    """

    def __init__(self,
                 log_dir:  str  = "logs",
                 run_name: str  = "weepingcan",
                 console:  bool = True):

        self._console = console

        # ── Ensure log directory exists ───────────────────────────────────────
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file      = str(log_path / f"{run_name}_{ts}.log")
        self.json_log_file = str(log_path / f"{run_name}_{ts}.jsonl")

        # ── Build logger ──────────────────────────────────────────────────────
        self._logger = logging.getLogger(f"weepingcan.{ts}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False

        # Plain-text file handler
        fh = logging.FileHandler(self.log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(PlainFormatter())
        self._logger.addHandler(fh)

        # JSON Lines file handler
        jh = JSONFileHandler(self.json_log_file, encoding="utf-8")
        jh.setLevel(logging.DEBUG)
        self._logger.addHandler(jh)

        # Console handler (optional)
        if console:
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(ConsoleFormatter())
            self._logger.addHandler(ch)

        self._logger.info(f"WeepingCAN simulation log started — {datetime.now().isoformat()}")
        self._logger.info(f"Plain log : {self.log_file}")
        self._logger.info(f"JSON log  : {self.json_log_file}")

    # ── Low-level emit helper ─────────────────────────────────────────────────
    def _emit(self, level: int, msg: str, **extras) -> None:
        if extras:
            self._logger.log(level, msg, extra=extras)
        else:
            self._logger.log(level, msg)

    # ── Convenience category methods ──────────────────────────────────────────

    def raw(self, msg: str) -> None:
        """Generic info-level message (used for banners, separators)."""
        self._emit(logging.INFO, msg)

    def bus(self, msg: str) -> None:
        """Bus-medium event (arbitration, transmission attempt, delivery)."""
        self._emit(LEVEL_BUS, msg)

    def attack(self, msg: str) -> None:
        """Attack cycle headline."""
        self._emit(LEVEL_ATTACK, msg)

    def bits(self, label: str, bit_list: list[int], color: str = WHITE) -> None:
        """
        Bit-stream dump line.

        Prints coloured bits to the console; stores plain text in the log.
        """
        plain_bits  = " ".join(str(b) for b in bit_list)
        console_msg = f"  {BOLD}{label:<30}{RESET}{color}{plain_bits}{RESET}"
        plain_msg   = f"  {label:<30}{plain_bits}"

        # For the console handler we want colours; for file handlers plain text.
        # We achieve this by temporarily replacing getMessage on the record.
        # Simpler: emit two separate records, one per handler.
        # Even simpler: use a custom LogRecord that stores both versions.
        record = self._logger.makeRecord(
            self._logger.name, LEVEL_BITS, "(bits)", 0,
            console_msg, (), None
        )
        # Override getMessage so file handlers (which call strip_ansi) get plain
        record._plain_override = plain_msg      # read by PlainFormatter below

        # Patch PlainFormatter to honour the override
        for handler in self._logger.handlers:
            if isinstance(handler, logging.FileHandler) and not isinstance(handler, JSONFileHandler):
                # Directly write the plain version
                try:
                    ts      = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    handler.stream.write(f"{ts} | {'BITS':<8} | {plain_msg}\n")
                    handler.stream.flush()
                except Exception:
                    pass
            elif isinstance(handler, JSONFileHandler):
                try:
                    entry = {
                        "ts":      datetime.fromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                        "level":   "BITS",
                        "message": plain_msg,
                    }
                    handler.stream.write(json.dumps(entry) + "\n")
                    handler.stream.flush()
                except Exception:
                    pass
            elif isinstance(handler, logging.StreamHandler) and self._console:
                # Console: coloured
                try:
                    handler.stream.write(console_msg + "\n")
                    handler.stream.flush()
                except Exception:
                    pass

    def error_flag(self, msg: str) -> None:
        """Error flag emission / TEC update event."""
        self._emit(LEVEL_ERROR_FLAG, msg)

    def tec(self, msg: str) -> None:
        """TEC counter update (convenience alias for error_flag level)."""
        self._emit(LEVEL_ERROR_FLAG, msg)

    def state_change(self, node: str, old: str, new: str) -> None:
        """Node state transition (Error-Active → Error-Passive → Bus-Off)."""
        color = RED if new in ("Error-Passive", "Bus-Off") else GREEN
        msg   = f"{color}[{node}] STATE TRANSITION: {old} → {new}{RESET}"
        self._emit(LEVEL_STATE, msg,
                   node=node, old_state=old, new_state=new)

    def cycle_summary(self,
                      cycle:          int,
                      victim_tec:     int,
                      attacker_tec:   int,
                      victim_state:   str,
                      attacker_state: str) -> None:
        """Per-cycle TEC / state summary row."""
        v_color = RED   if victim_state   != "Error-Active" else GREEN
        a_color = RED   if attacker_state != "Error-Active" else GREEN
        sep     = BOLD + "─" * 50 + RESET

        lines = [
            f"\n{sep}",
            f"  Cycle {cycle:>3}  |  "
            f"{v_color}[VICTIM]   TEC={victim_tec:>3}  state={victim_state}{RESET}",
            f"           |  "
            f"{a_color}[ATTACKER] TEC={attacker_tec:>3}  state={attacker_state}{RESET}",
            sep,
        ]
        msg = "\n".join(lines)
        self._emit(LEVEL_CYCLE, msg,
                   cycle=cycle,
                   victim_tec=victim_tec, attacker_tec=attacker_tec,
                   victim_state=victim_state, attacker_state=attacker_state)

    def summary(self, msg: str) -> None:
        """End-of-simulation summary line."""
        self._emit(LEVEL_SUMMARY, msg)

    def separator(self, char: str = "─", n: int = 70,
                  color: str = CYAN) -> None:
        """Print a visual separator (only to console + log as INFO)."""
        self._emit(logging.INFO, color + BOLD + char * n + RESET)

    # ── Accessors ─────────────────────────────────────────────────────────────
    def get_log_path(self) -> str:
        return self.log_file

    def get_json_path(self) -> str:
        return self.json_log_file


# ── Module-level singleton ────────────────────────────────────────────────────
_instance: Optional[SimLogger] = None


def init_logger(log_dir:  str  = "logs",
                run_name: str  = "weepingcan",
                console:  bool = True) -> SimLogger:
    """Initialise (or reinitialise) the module-level singleton logger."""
    global _instance
    _instance = SimLogger(log_dir=log_dir, run_name=run_name, console=console)
    return _instance


def get_logger() -> SimLogger:
    """Return the singleton logger; auto-initialises with defaults if needed."""
    global _instance
    if _instance is None:
        _instance = SimLogger()
    return _instance
