#!/usr/bin/env python3
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Protocol, Tuple

import websockets
from websockets.typing import Data

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler("ws_timing_test.log"), logging.StreamHandler()],
)


class WebSocketProtocol(Protocol):
    async def send(self, message: str) -> None: ...
    async def recv(self) -> Data: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...


class WSTimingAnalyzer:
    def __init__(self) -> None:
        self.crash_times: List[float] = []
        self.message_times: List[Tuple[float, str]] = []
        self.pre_crash_messages: List[List[Tuple[float, str]]] = []
        self.auth_timing: List[float] = []
        self.undefined_timing: List[float] = []
        self.last_crash: Optional[float] = None
        self.crash_intervals: List[float] = []

    def analyze_timing(self, message: Data, timestamp: float) -> None:
        """Analyze timing patterns in WebSocket messages"""
        try:
            if isinstance(message, str) and message.startswith("42"):
                data = json.loads(message[2:])
                if len(data) >= 2:
                    event_name = data[0]
                    event_data = data[1]

                    # Track all message timings
                    self.message_times.append((timestamp, event_name))

                    # Analyze crash events
                    if event_name == "crash.tick":
                        if self.last_crash:
                            interval = timestamp - self.last_crash
                            self.crash_intervals.append(interval)
                            if len(self.crash_intervals) >= 3:
                                self.analyze_intervals()
                        self.last_crash = timestamp
                        self.crash_times.append(timestamp)

                        # Store pre-crash messages
                        recent_messages = self.message_times[-5:]  # Last 5 messages
                        self.pre_crash_messages.append(recent_messages)

                    # Track authentication timing
                    if "401" in str(event_data):
                        self.auth_timing.append(timestamp)
                        if len(self.auth_timing) >= 2:
                            self.analyze_auth_pattern()

                    # Track undefined states timing
                    if "undefined" in str(event_data):
                        self.undefined_timing.append(timestamp)
                        if len(self.undefined_timing) >= 2:
                            self.analyze_undefined_pattern()
        except Exception as e:
            logging.error(f"Error analyzing timing: {str(e)}")

    def analyze_intervals(self) -> None:
        """Analyze patterns in crash intervals"""
        recent = self.crash_intervals[-3:]
        avg_interval = sum(recent) / 3

        # Check for consistent intervals
        if all(abs(i - avg_interval) < 0.5 for i in recent):
            logging.warning(f"Consistent crash interval detected: {avg_interval:.2f}s")

        # Check for decreasing intervals
        if all(recent[i] > recent[i + 1] for i in range(len(recent) - 1)):
            logging.warning("Decreasing crash intervals detected")

    def analyze_auth_pattern(self) -> None:
        """Analyze authentication error patterns"""
        recent = self.auth_timing[-2:]
        if recent[1] - recent[0] < 2.0:
            logging.warning(f"Rapid auth errors: {recent[1] - recent[0]:.2f}s apart")

    def analyze_undefined_pattern(self) -> None:
        """Analyze undefined state patterns"""
        recent = self.undefined_timing[-2:]
        if recent[1] - recent[0] < 1.0:
            logging.warning(
                f"Rapid undefined states: {recent[1] - recent[0]:.2f}s apart"
            )

    def get_statistics(self) -> Dict[str, float]:
        """Get current timing statistics"""
        stats = {
            "total_crashes": len(self.crash_times),
            "avg_interval": (
                sum(self.crash_intervals) / len(self.crash_intervals)
                if self.crash_intervals
                else 0
            ),
            "auth_errors": len(self.auth_timing),
            "undefined_states": len(self.undefined_timing),
            "message_count": len(self.message_times),
        }
        return stats


async def test_ws_timing() -> None:
    analyzer = WSTimingAnalyzer()
    uri = "wss://trustdice.win/crash/socket.io/?EIO=4&transport=websocket"

    try:
        async with websockets.connect(uri) as websocket:
            logging.info("Connected to WebSocket")

            while True:
                try:
                    message = await websocket.recv()
                    timestamp = time.time()
                    analyzer.analyze_timing(message, timestamp)

                    # Log statistics every 10 messages
                    if len(analyzer.message_times) % 10 == 0:
                        stats = analyzer.get_statistics()
                        logging.info(f"Current statistics: {stats}")

                except websockets.exceptions.ConnectionClosed:
                    logging.error("WebSocket connection closed")
                    break
    except Exception as e:
        logging.error(f"Connection error: {str(e)}")
    finally:
        # Save analysis results
        with open("timing_analysis.json", "w") as f:
            json.dump(
                {
                    "crash_intervals": analyzer.crash_intervals,
                    "auth_timing": analyzer.auth_timing,
                    "undefined_timing": analyzer.undefined_timing,
                    "statistics": analyzer.get_statistics(),
                },
                f,
                indent=2,
            )


if __name__ == "__main__":
    asyncio.run(test_ws_timing())
