#!/usr/bin/env python3
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Union

import websockets
from websockets.legacy.client import WebSocketClientProtocol

from ws_minimal_test import MinimalWSTest

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("ws_test_patterns.log"),
        logging.StreamHandler(),
    ],
)


class WSPatternAnalyzer:
    def __init__(self) -> None:
        self.crash_times: List[float] = []
        self.intervals: List[float] = []
        self.pre_crash_patterns: List[Tuple[float, int]] = []
        self.suspicious_sequences: List[Tuple[float, str]] = []

    def analyze_crash_pattern(self, message: str) -> None:
        """Analyze crash patterns in WebSocket messages"""
        try:
            if message.startswith("42"):
                data = json.loads(message[2:])
                if len(data) >= 2:
                    event_name = data[0]
                    event_data = data[1]

                    current_time = time.time()

                    # Track crash events
                    if event_name == "crash.tick":
                        if len(self.crash_times) > 0:
                            interval = current_time - self.crash_times[-1]
                            self.intervals.append(interval)

                            # Analyze intervals for patterns
                            if len(self.intervals) >= 3:
                                recent_intervals = self.intervals[-3:]
                                avg_interval = sum(recent_intervals) / 3
                                if abs(recent_intervals[-1] - avg_interval) > 5:
                                    logging.warning(
                                        f"Unusual interval detected: {recent_intervals[-1]:.2f}s vs avg {avg_interval:.2f}s"
                                    )

                        self.crash_times.append(current_time)

                        # Track pre-crash patterns
                        if "elements" in str(event_data):
                            try:
                                elements = int(
                                    str(event_data).split('elements":')[1].split(",")[0]
                                )
                                self.pre_crash_patterns.append((current_time, elements))
                                self.analyze_element_pattern()
                            except Exception as e:
                                logging.error(f"Failed to parse elements: {str(e)}")

                        # Track undefined states
                        if "undefined" in str(event_data):
                            self.suspicious_sequences.append(
                                (current_time, "undefined_state")
                            )
                            self.analyze_suspicious_sequence()

                        # Track 401 errors
                        if "401" in str(event_data):
                            self.suspicious_sequences.append(
                                (current_time, "auth_error")
                            )
                            self.analyze_suspicious_sequence()
        except Exception as e:
            logging.error(f"Error analyzing crash pattern: {str(e)}")

    def analyze_element_pattern(self) -> None:
        """Analyze patterns in element counts before crashes"""
        if len(self.pre_crash_patterns) >= 3:
            recent_patterns = self.pre_crash_patterns[-3:]

            # Check for rapid element count changes
            if (recent_patterns[-1][0] - recent_patterns[0][0]) < 2.0:
                count_delta = recent_patterns[-1][1] - recent_patterns[0][1]
                if abs(count_delta) > 50:
                    logging.warning(
                        f"Rapid element count change detected: {count_delta} in {recent_patterns[-1][0] - recent_patterns[0][0]:.2f}s"
                    )

    def analyze_suspicious_sequence(self) -> None:
        """Analyze sequences of suspicious events"""
        if len(self.suspicious_sequences) >= 3:
            recent_events = self.suspicious_sequences[-3:]

            # Check for rapid succession of suspicious events
            if (recent_events[-1][0] - recent_events[0][0]) < 5.0:
                event_types = [event[1] for event in recent_events]
                logging.warning(
                    f"Multiple suspicious events in quick succession: {event_types}"
                )

    def get_statistics(self) -> Dict[str, Union[int, float]]:
        """Get current pattern statistics"""
        stats = {
            "total_crashes": len(self.crash_times),
            "avg_interval": (
                sum(self.intervals) / len(self.intervals) if self.intervals else 0
            ),
            "suspicious_sequences": len(self.suspicious_sequences),
            "pre_crash_patterns": len(self.pre_crash_patterns),
        }
        return stats


async def main() -> None:
    analyzer = WSPatternAnalyzer()
    test = MinimalWSTest()

    try:
        logging.info("Starting WebSocket connection test with pattern analysis...")

        # Connect and analyze patterns
        connected = await test.connect()
        if not connected:
            logging.error("Failed to establish WebSocket connection")
            return

        logging.info("Successfully connected to WebSocket")

        # Run for a specified duration or until enough patterns are collected
        while len(analyzer.crash_times) < 10:  # Collect data for 10 crashes
            try:
                if test.websocket and test.connected:
                    message = await test.websocket.recv()
                    analyzer.analyze_crash_pattern(message)

                    # Log statistics periodically
                    if len(analyzer.crash_times) % 5 == 0:
                        stats = analyzer.get_statistics()
                        logging.info(f"Current statistics: {stats}")
                else:
                    logging.error("WebSocket connection lost")
                    # Try to reconnect
                    if not await test.connect():
                        logging.error("Failed to reconnect")
                        break

            except websockets.exceptions.ConnectionClosed:
                logging.error("WebSocket connection closed")
                # Try to reconnect
                if not await test.connect():
                    logging.error("Failed to reconnect")
                    break
            except Exception as e:
                logging.error(f"Error during pattern analysis: {str(e)}")
                break

    except Exception as e:
        logging.error(f"Test failed: {str(e)}")
    finally:
        # Save analysis results
        with open("pattern_analysis.json", "w") as f:
            json.dump(
                {
                    "intervals": analyzer.intervals,
                    "suspicious_sequences": analyzer.suspicious_sequences,
                    "statistics": analyzer.get_statistics(),
                },
                f,
                indent=2,
            )


if __name__ == "__main__":
    asyncio.run(main())
