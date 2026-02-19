# WeepingCAN Bus-Off Attack Simulator

A Python simulation of the **WeepingCAN** attack — a stealth CAN bus denial-of-service technique that forces a victim ECU into Bus-Off state while keeping the attacker ECU in the Error-Active state throughout.

This project was developed for the *Cyberphysical and IoT Security* course (CPS Project 1).

---

## Background

The **Controller Area Network (CAN)** protocol uses a Transmit Error Counter (TEC) to track transmission faults. Each detected error increments TEC by 8; each successful transmission decrements it by 1. Nodes transition through three states:

| TEC range | State          | Behaviour |
|-----------|----------------|-----------|
| 0 – 127   | Error-Active   | Emits Active Error Flags (6 dominant bits) |
| 128 – 255 | Error-Passive  | Can only emit Passive Error Flags (recessive) |
| ≥ 256     | Bus-Off        | Disconnected from the bus — cannot transmit |

**WeepingCAN** exploits this by having an attacker node transmit the same CAN ID as a victim (passing arbitration as a tie), then injecting a **recessive bit** into the victim's dominant data field. The wire-AND rule on the CAN bus causes the attacker to detect a Bit Error, which triggers an error flag that corrupts the victim's frame (+8 TEC). The attacker then immediately sends 5+ valid frames to cancel its own TEC increase, remaining in Error-Active indefinitely while the victim's TEC climbs toward Bus-Off.

---

## Project Structure

```
CPS Project 1/
├── simulation.py        # Entry point — orchestrates the full simulation
├── can_bus.py           # CAN bus medium: arbitration, error flags, frame delivery
├── ecu.py               # Base ECU class: TEC counter and state machine
├── attacker_ecu.py      # AttackerECU: WeepingCAN attack logic
├── victim_ecu.py        # VictimECU: periodic frame broadcaster
├── logger.py            # Centralised logging (console + .log + .jsonl)
├── logs/                # Generated simulation logs (plain-text + JSON Lines)
└── Notebook/
    ├── weepingcan_analysis.ipynb   # Jupyter notebook for log analysis & plots
    ├── plot_tec_timeline.png
    ├── plot_phase_analysis.png
    ├── plot_success_rate.png
    └── plot_injection_dist.png
```

---

## Source Files

### `ecu.py` — Base ECU

The foundation class for all nodes on the bus.

```
ECUState
  ERROR_ACTIVE  = "Error-Active"
  ERROR_PASSIVE = "Error-Passive"
  BUS_OFF       = "Bus-Off"

ECU(name, verbose)
  .attach(bus)              — register this node on a CANBus
  .send(frame, [concurrent_frame]) — transmit a frame (returns bool)
  .listen()                 — drain and return the receive buffer
  .status()                 — coloured status string (TEC, state)
  ._increment_tec(amount)   — add to TEC (capped at 256)
  ._decrement_tec(amount)   — subtract from TEC (floor 0)
  ._check_state_transition() — update Error-Active/Passive/Bus-Off
```

**Constants:** `TEC_ERROR_PASSIVE_THRESHOLD = 128`, `TEC_BUS_OFF_THRESHOLD = 256`

---

### `can_bus.py` — CAN Bus Medium

Simulates the shared CAN wire with wire-AND logic, arbitration, and error flag handling.

```
CANFrame(can_id, data, sender_id, inject_recessive_at, is_malicious)
  — Represents a CAN 2.0A frame (11-bit ID, up to 8 data bytes)
  — inject_recessive_at: bit position where the attacker injects recessive
  — is_malicious: marks attacker-crafted frames

CANBus(verbose)
  .register(ecu)                  — add a node to the bus
  .transmit(frame, [concurrent])  — attempt frame transmission
  .transmit_valid(sender_name, n) — simulate n successful transmissions (TEC -n)
```

Key internal methods:
- `_do_transmit()` — runs arbitration, bit injection, and wire-AND resolution
- `_emit_error_flag()` — increments TEC on both nodes, drives victim to retransmit or Bus-Off
- `_deliver_frame()` — fan-out to all nodes except the sender

**Bus constants:** `DOMINANT = 0`, `RECESSIVE = 1`

---

### `victim_ecu.py` — Victim ECU

A normal CAN node that sends periodic frames.

```
VictimECU(name, can_id, period_ms, verbose)
  .broadcast()  — build and return the next periodic frame (raises RuntimeError if Bus-Off)
```

Each frame payload is `[0xDE, 0xAD, 0xBE, seq]` where `seq` is an 8-bit rolling counter.

---

### `attacker_ecu.py` — Attacker ECU

Implements the WeepingCAN stealth attack. Extends `ECU`.

```
AttackerECU(name, target_can_id, verbose)
  .analyze_pattern(victim_can_id, victim_period_ms)
      — log the snooped target CAN ID and period
  .attack(victim_frame)
      — execute one attack cycle: inject recessive bit + send N_VALID_MSGS valid frames
      — returns False if attacker left Error-Active (attack model violated)
  .stats()
      — return a summary string (cycle count, valid messages sent, TEC, state)
```

**Key constant:** `N_VALID_MSGS = 5` — valid frames sent after each attack cycle to recover attacker TEC.

Attack cycle flow:
1. Mirror victim's CAN ID (wins arbitration on tie).
2. Pick a **random** bit position in the DATA field to inject a recessive bit.
3. `bus.transmit()` resolves wire-AND: victim dominant + attacker recessive → bus reads dominant → attacker Bit Error → error flag → victim TEC +8.
4. Attacker sends 5 valid frames → attacker TEC −5, stays Error-Active.

---

### `logger.py` — Centralised Logger

A singleton facade (`SimLogger`) writing to three simultaneous outputs:

| Output | Format | ANSI colours |
|--------|--------|-------------|
| stdout / console | raw message | yes |
| `logs/<run>_<ts>.log` | `TIMESTAMP \| LEVEL \| message` | stripped |
| `logs/<run>_<ts>.jsonl` | JSON Lines (one object per line) | stripped |

**Custom log levels** (all above `INFO = 20`):

| Level name | Value | Purpose |
|------------|-------|---------|
| `BUS`      | 21    | Bus medium events (arbitration, delivery) |
| `ATTACK`   | 22    | Attack cycle headlines |
| `BITS`     | 23    | Bit-stream dumps |
| `ERRFLAG`  | 24    | Error flag emission and TEC updates |
| `STATE`    | 25    | ECU state transitions |
| `CYCLE`    | 26    | Per-cycle summary rows |
| `SUMMARY`  | 27    | End-of-simulation report |

**Public API:**

```python
from logger import init_logger, get_logger

# Initialise once at startup
log = init_logger(log_dir="logs", run_name="weepingcan", console=True)

# Use anywhere in the codebase
log = get_logger()
log.bus("Transmission attempt ...")
log.attack("ATTACK CYCLE #1")
log.bits("CAN-ID bits:", [0,0,1,0,0,0,0,0,0,0,0], color=YELLOW)
log.error_flag("ACTIVE Error Flag emitted")
log.tec("Victim TEC: 0 → 8")
log.state_change("VICTIM", "Error-Active", "Error-Passive")
log.cycle_summary(cycle=1, victim_tec=7, attacker_tec=3,
                  victim_state="Error-Active", attacker_state="Error-Active")
log.summary("Simulation complete")
```

**ANSI colour constants** exported by `logger.py`: `RED`, `GREEN`, `YELLOW`, `CYAN`, `MAGENTA`, `WHITE`, `GRAY`, `BOLD`, `RESET`.

---

### `simulation.py` — Simulation Orchestrator

Wires everything together and runs the main loop.

```python
run_simulation(
    max_cycles = 100,    # maximum attack cycles before stopping
    delay      = 0.05,   # seconds between cycles
    verbose    = True,   # if False, suppresses bit-stream dumps
    log_dir    = "logs", # directory for log files
    no_log     = False,  # disable file logging (console only)
)
```

Loop logic:
1. Victim calls `broadcast()` to produce a frame.
2. Attacker calls `attack(victim_frame)`.
3. Per-cycle summary is logged.
4. Loop exits when victim reaches Bus-Off, attacker leaves Error-Active, or `max_cycles` is reached.

---

### `Notebook/weepingcan_analysis.ipynb` — Log Analysis

A Jupyter notebook that parses a `.jsonl` simulation log and produces four plots:

| Plot file | Description |
|-----------|-------------|
| `plot_tec_timeline.png` | Victim and attacker TEC over every cycle with state-transition annotations |
| `plot_phase_analysis.png` | Shaded Phase 1/2 areas + per-cycle TEC delta bar chart |
| `plot_success_rate.png` | Stacked bar of effective vs wasted injections + cumulative success rate |
| `plot_injection_dist.png` | Histogram of injection bit positions and per-position success rate heatmap |

Configure the log path in the `LOG_PATH` variable in §1, then **Run All**.

---

## Requirements

- Python ≥ 3.10
- Standard library only for the simulator (`threading`, `dataclasses`, `logging`, `json`)
- For the notebook: `numpy`, `pandas`, `matplotlib`

Install notebook dependencies:

```bash
pip install numpy pandas matplotlib
```

---

## Usage

### Run the simulation

```bash
# Default: 100 cycles, verbose, logs saved to logs/
python simulation.py

# Quieter output (no bit-stream dumps)
python simulation.py --quiet

# More cycles, faster
python simulation.py --max-cycles 200 --delay 0.01

# Custom log directory
python simulation.py --log-dir /tmp/can_logs

# Console only (no log files)
python simulation.py --no-log
```

### Run programmatically

```python
from simulation import run_simulation

run_simulation(max_cycles=50, delay=0.0, verbose=False)
```

### Analyse results

1. Open `Notebook/weepingcan_analysis.ipynb` in JupyterLab or VS Code.
2. Set `LOG_PATH` to the `.jsonl` file produced in `logs/`.
3. Run All cells — plots are saved as PNG files in `Notebook/`.

---

## Attack Model Summary

The WeepingCAN variant implemented here is a **stealth** attack: the attacker is designed to remain in Error-Active state throughout the entire simulation. This is achieved by:

1. **Matching the victim's CAN ID exactly** — arbitration resolves as a tie, so both nodes transmit simultaneously.
2. **Injecting a recessive bit into the victim's dominant DATA field** — the attacker detects a self-generated Bit Error, which it uses to emit an error flag.
3. **Recovering TEC immediately** — after each attack cycle, 5 valid frames bring the attacker's TEC back below the threshold before the next cycle.

The victim, unable to distinguish the attacker's error flag from a legitimate bus fault, accumulates TEC at approximately +7 per cycle until it reaches Bus-Off (TEC ≥ 256).
