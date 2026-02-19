"""
victim_ecu.py
-------------
VictimECU — normal CAN node with periodic transmissions.
"""
from __future__ import annotations
from ecu import ECU, ECUState
from can_bus import CANFrame
from logger import get_logger, RED, GREEN, RESET


class VictimECU(ECU):
    def __init__(self, name: str = "VICTIM", can_id: int = 0x100,
                 period_ms: int = 10, verbose: bool = True):
        super().__init__(name, verbose)
        self.can_id    = can_id
        self.period_ms = period_ms
        self._seq: int = 0

    def _make_frame(self) -> CANFrame:
        self._seq = (self._seq + 1) & 0xFF
        data = [0xDE, 0xAD, 0xBE, self._seq]
        return CANFrame(can_id=self.can_id, data=data, sender_id=self.name)

    def broadcast(self) -> CANFrame:
        if self.state == ECUState.BUS_OFF:
            get_logger().bus(
                f"{RED}[{self.name}] BUS-OFF reached! "
                f"Node is disconnected from the bus.{RESET}"
            )
            raise RuntimeError(f"{self.name} has gone Bus-Off.")
        frame = self._make_frame()
        get_logger().bus(
            f"{GREEN}\n[{self.name}] Preparing periodic frame  "
            f"CAN-ID=0x{frame.can_id:03X}  seq={self._seq:#04x}  "
            f"data={[hex(b) for b in frame.data]}{RESET}"
        )
        return frame
