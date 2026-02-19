"""
ecu.py
------
Base ECU class. Manages TEC counter and state transitions.
All output goes through SimLogger.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List

if TYPE_CHECKING:
    from can_bus import CANBus, CANFrame

from logger import get_logger, RED, GREEN, YELLOW, CYAN, GRAY, BOLD, RESET

TEC_ERROR_PASSIVE_THRESHOLD = 128
TEC_BUS_OFF_THRESHOLD       = 256


class ECUState:
    ERROR_ACTIVE  = "Error-Active"
    ERROR_PASSIVE = "Error-Passive"
    BUS_OFF       = "Bus-Off"


class ECU:
    def __init__(self, name: str, verbose: bool = True):
        self.name    = name
        self.tec:  int = 0
        self.state: str = ECUState.ERROR_ACTIVE
        self.bus         = None
        self.verbose     = verbose
        self._rx_buffer: List = []

    def attach(self, bus) -> None:
        self.bus = bus
        bus.register(self)

    def send(self, frame, concurrent_frame=None) -> bool:
        if self.state == ECUState.BUS_OFF:
            get_logger().bus(f"{RED}[{self.name}] BUS-OFF: cannot transmit.{RESET}")
            return False
        if self.bus is None:
            raise RuntimeError(f"{self.name} is not attached to any bus.")
        return self.bus.transmit(frame, concurrent_frame)

    def listen(self) -> List:
        frames = list(self._rx_buffer)
        self._rx_buffer.clear()
        return frames

    def _receive(self, frame) -> None:
        self._rx_buffer.append(frame)

    def _increment_tec(self, amount: int) -> None:
        self.tec = min(self.tec + amount, 256)

    def _decrement_tec(self, amount: int) -> None:
        self.tec = max(self.tec - amount, 0)

    def _check_state_transition(self) -> None:
        old_state = self.state
        if self.tec >= TEC_BUS_OFF_THRESHOLD:
            self.state = ECUState.BUS_OFF
        elif self.tec >= TEC_ERROR_PASSIVE_THRESHOLD:
            self.state = ECUState.ERROR_PASSIVE
        else:
            self.state = ECUState.ERROR_ACTIVE

        if self.state != old_state:
            get_logger().state_change(self.name, old_state, self.state)

    def status(self) -> str:
        color = RED if self.state != ECUState.ERROR_ACTIVE else GREEN
        return (f"{color}[{self.name}]  TEC={self.tec:3d}  "
                f"state={self.state}{RESET}")
