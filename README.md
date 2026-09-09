# WeepingCAN Bus-Off Attack Simulator

This repository contains the simulator we built for CPS Project 1 in the
*Cyberphysical and IoT Security* course. It reproduces the main WeepingCAN
result: a victim ECU reaches Bus-Off while the attacker remains Error-Active.

## How the model works

CAN uses a Transmit Error Counter (TEC) to isolate faulty nodes:

| TEC | State | Behaviour |
|---:|---|---|
| 0–127 | Error-Active | Emits Active Error Flags |
| 128–255 | Error-Passive | Emits only recessive Passive Error Flags |
| 256 or more | Bus-Off | Cannot transmit |

The attacker copies the victim's 11-bit CAN ID, so both nodes finish
arbitration together. It then sends a recessive bit while the victim sends a
dominant bit at the same position. The bus remains dominant, the attacker sees
a Bit Error, and its Active Error Flag corrupts the victim's frame.

An effective cycle adds 8 to both TEC counters. The victim retransmits and
recovers 1 point, for a net change of +7. The attacker sends five valid frames
and recovers 5 points. When its TEC reaches 6, it skips an injection cycle and
uses those valid frames to bring the counter back down. The model also treats
5% of injection attempts as mis-timed.

Injection positions come from dominant bits in the known static part of the
victim payload, `[0xDE, 0xAD, 0xBE, seq]`:

```python
SAFE_INJECT_POSITIONS = [13, 18, 20, 22, 25, 28, 34]
N_VALID_MSGS = 5
SYNC_ERROR_PROBABILITY = 0.05
SKIP_TEC_THRESHOLD = 6
```

The passive F1 detector watches for two consecutive errors on the same CAN ID.
WeepingCAN avoids that pattern because each injected error is followed by a
clean victim retransmission.

## Repository layout

| Path | Purpose |
|---|---|
| `simulation.py` | CLI entry point and simulation loop |
| `can_bus.py` | Arbitration, wire-AND resolution and error flags |
| `ecu.py` | TEC counter and ECU state transitions |
| `victim_ecu.py` | Periodic victim traffic |
| `attacker_ecu.py` | Injection, skip, jitter and recovery logic |
| `detector.py` | F1 consecutive-error detector |
| `logger.py` | Console, plain-text and JSONL logging |
| `Notebook/weepingcan_analysis.ipynb` | Log analysis and plots |
| `Report/weepingcan_report.md` | Experiment report |
| `logs/` | Recorded simulator runs |

## Running the simulator

Python 3.10 or newer is required. The simulator itself uses only the standard
library.

```bash
python simulation.py
```

The default run continues until the victim reaches Bus-Off, waits 0.05 seconds
between cycles, prints detailed events and writes `.log` and `.jsonl` files
under `logs/`.

Useful alternatives:

```bash
# Final summary only
python simulation.py --quiet

# Fast smoke test with a cycle limit
python simulation.py --quiet --max-cycles 200 --delay 0.01

# Write logs elsewhere
python simulation.py --log-dir /tmp/can_logs

# Disable file logging
python simulation.py --no-log
```

The simulation can also be called from Python:

```python
from simulation import run_simulation

run_simulation(max_cycles=50, delay=0.0, verbose=False)
```

## Analysing runs

The notebook requires NumPy, pandas and Matplotlib:

```bash
pip install numpy pandas matplotlib
jupyter lab Notebook/weepingcan_analysis.ipynb
```

By default, the notebook loads all JSONL files under `logs/`. `LOG_FILES` can be
set to one or more paths when only selected runs are needed. Generated plots cover
TEC progression, attack phases, successful and mis-timed injections, injection
positions, F1 detection and variation across runs.

## Scope

This is a software model of the attack logic, not a hardware CAN implementation.
It does not model controller timing, physical-layer fingerprints, bit stuffing,
traffic from additional ECUs or Bus-Off recovery. See
`Report/weepingcan_report.md` for experiment data and discussion.
