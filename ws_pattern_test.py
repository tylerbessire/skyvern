#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import time
from datetime import datetime

import websockets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("ws_pattern_test.log"), logging.StreamHandler()],
)


class WSPatternTest:
    def __init__(self):
        self.t = str(int(time.time() * 1000))
        self.uri = (
            f"wss://trustdice.win/crash/socket.io/?EIO=4&transport=websocket&t={self.t}"
        )
        self.message_history = []
        self.crash_times = []
        self.intervals = []
        self.undefined_states = []
        self.auth_errors = []

    async def analyze_patterns(self, message):
        """Analyze message patterns and timing"""
        try:
            # Store message with timestamp
            timestamp = time.time()
            self.message_history.append((timestamp, message))

            # Check for undefined states
            if "undefined" in message:
                self.undefined_states.append(timestamp)
                if len(self.undefined_states) >= 2:
                    interval = self.undefined_states[-1] - self.undefined_states[-2]
                    logging.info(f"Undefined state interval: {interval:.2f}s")

            # Check for authentication errors
            if "401" in message:
                self.auth_errors.append(timestamp)
                if len(self.auth_errors) >= 2:
                    interval = self.auth_errors[-1] - self.auth_errors[-2]
                    logging.info(f"Auth error interval: {interval:.2f}s")

            # Analyze crash events
            if "crash" in message.lower():
                self.crash_times.append(timestamp)
                if len(self.crash_times) >= 2:
                    interval = self.crash_times[-1] - self.crash_times[-2]
                    self.intervals.append(interval)
                    avg_interval = sum(self.intervals) / len(self.intervals)
                    logging.info(
                        f"Crash interval: {interval:.2f}s (avg: {avg_interval:.2f}s)"
                    )

                    # Check for consistent patterns
                    if len(self.intervals) >= 3:
                        std_dev = (
                            sum((x - avg_interval) ** 2 for x in self.intervals[-3:])
                            / 3
                        ) ** 0.5
                        if std_dev < 0.5:  # Very consistent timing
                            logging.warning(
                                f"Highly consistent crash intervals detected: {avg_interval:.2f}s ±{std_dev:.2f}s"
                            )

            # Analyze message sequences
            if len(self.message_history) >= 5:
                recent_msgs = self.message_history[-5:]
                # Look for repeated sequences before crashes
                if any("crash" in msg[1].lower() for msg in recent_msgs):
                    sequence = "\n".join(msg[1] for msg in recent_msgs[:-1])
                    logging.info(f"Message sequence before crash:\n{sequence}")

        except Exception as e:
            logging.error(f"Error analyzing patterns: {str(e)}")

    async def run(self):
        """Main test loop"""
        while True:
            try:
                async with websockets.connect(self.uri) as websocket:
                    logging.info("Connected to WebSocket")
                    while True:
                        try:
                            message = await websocket.recv()
                            logging.info(f"Received: {message}")
                            await self.analyze_patterns(message)
                        except websockets.exceptions.ConnectionClosed:
                            logging.error("Connection closed")
                            break
            except Exception as e:
                logging.error(f"Connection error: {str(e)}")

            # Wait before reconnecting
            await asyncio.sleep(5)


async def main():
    test = WSPatternTest()
    await test.run()


if __name__ == "__main__":
    asyncio.run(main())
