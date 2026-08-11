# Repository Guidelines

## Project Structure & Module Organization

This repository contains a Python WeepingCAN bus-off attack simulator. Core
source files live at the repository root:

- `simulation.py`: CLI entry point and simulation loop.
- `can_bus.py`, `ecu.py`, `victim_ecu.py`, `attacker_ecu.py`: CAN bus and ECU model.
- `detector.py`, `logger.py`: F1 detection and console/file logging.
- `Notebook/`: Jupyter analysis notebook and generated plots.
- `logs/`: generated `.log` and `.jsonl` simulation runs.
- `Report/` and `md/`: written report and source paper notes/assets.

Avoid committing cache files such as `__pycache__/`. Treat new files in `logs/`
and generated notebook plots as artifacts unless needed for a report update.

## Build, Test, and Development Commands

No build step is required; simulator code uses Python standard library only.

```bash
python simulation.py
```

Runs the default simulation and writes logs under `logs/`.

```bash
python simulation.py --quiet --max-cycles 200 --delay 0.01
```

Runs a faster, less verbose simulation for smoke testing.

```bash
python -m py_compile simulation.py can_bus.py ecu.py attacker_ecu.py victim_ecu.py detector.py logger.py
```

Checks all simulator modules for syntax errors.

```bash
pip install numpy pandas matplotlib
jupyter lab Notebook/weepingcan_analysis.ipynb
```

Installs notebook-only dependencies and opens analysis workflow.

## Coding Style & Naming Conventions

Use Python 3.10+ and keep code compatible with standard library modules unless
notebook work requires scientific packages. Follow existing style: 4-space
indentation, type hints for public functions, dataclasses for simple records,
and descriptive constants in `UPPER_SNAKE_CASE`. Use `snake_case` for functions,
methods, and variables; use `PascalCase` for classes such as `CANBus` and
`AttackerECU`. Route runtime output through `logger.py` rather than direct
`print()` calls.

## Testing Guidelines

There is no formal test suite yet. Before submitting code, run `py_compile` and
at least one quiet simulation smoke test. If adding tests, place them under
`tests/`, name files `test_<module>.py`, and prefer focused unit tests for TEC
state transitions, bus arbitration, detector behavior, and attacker skip logic.

## Commit & Pull Request Guidelines

Git history uses short subjects, often with bracketed prefixes such as `[new]`,
`[feat]`, and `[test]`. Keep commits concise and imperative, for example
`[feat] add jitter model`. Pull requests should describe behavior changes, list
commands run, note generated logs or plots, and include screenshots when notebook
visual outputs change.
