#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import random
import string
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, Tuple
from urllib.parse import quote

import websockets
import websockets.exceptions
from websockets.typing import Data

# Get authentication keys from environment
WALLET_PRIVATE_KEY = os.getenv("WALLET_PRIVATE_KEY", "")
PUBLIC_KEY = os.getenv("PUBLIC_KEY", "")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("websocket_test.log"), logging.StreamHandler()],
)


class WebSocketProtocol(Protocol):
    async def send(self, message: str) -> None: ...
    async def recv(self) -> Data: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...


class CrashWebsocketTester:
    def __init__(self) -> None:
        # Generate required Socket.IO parameters
        self.sid: str = "".join(
            random.choices(string.ascii_letters + string.digits, k=20)
        )
        self.t: str = str(int(time.time() * 1000))

        # Use proper Socket.IO v4 connection URL format
        query_params: Dict[str, str] = {
            "EIO": "4",
            "transport": "websocket",
            "t": self.t,
            "sid": self.sid,
        }
        query_string: str = "&".join(f"{k}={v}" for k, v in query_params.items())
        self.uri: str = f"wss://trustdice.win/crash/socket.io/?{query_string}"

        # Connection state
        self.last_crash_time: Optional[float] = None
        self.crash_intervals: List[float] = []
        self.multiplier_sequence: List[float] = []
        self.state_transitions: List[Dict[str, Any]] = []

        # Authentication headers
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Origin": "https://trustdice.win",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "Sec-WebSocket-Version": "13",
            "Cookie": f"wallet_private_key={quote(WALLET_PRIVATE_KEY)}; public_key={quote(PUBLIC_KEY)}",
        }

        # Log initialization
        logging.info("WebSocket test initialized")

    async def connect(self) -> bool:
        reconnect_delay: int = 5
        max_retries: int = 5
        retry_count: int = 0

        # Default return value
        success: bool = False

        while retry_count < max_retries:
            try:
                # Create connection with proper headers
                # Create basic connection first
                async with websockets.connect(
                    self.uri,
                    additional_headers={"Cookie": self.headers["Cookie"]},
                    compression=None,
                    max_size=2**23,
                ) as websocket:
                    logging.info(f"Connected to {self.uri}")
                    retry_count = 0  # Reset counter on successful connection

                    try:
                        while True:
                            message = await websocket.recv()
                            await self.process_message(websocket, message)

                    except websockets.exceptions.ConnectionClosed as e:
                        if e.code == 1000:  # Normal closure
                            logging.info("Connection closed normally")
                            success = True
                            break
                        logging.error(f"Connection closed unexpectedly: {str(e)}")

                    except Exception as e:
                        logging.error(f"Error during message processing: {str(e)}")
                        if "undefined" in str(e):
                            logging.warning("Undefined state detected in error")

            except websockets.exceptions.WebSocketException as e:
                error_msg = str(e)
                if "403" in error_msg:
                    logging.error("Authentication failed. Checking credentials...")
                    if not WALLET_PRIVATE_KEY or not PUBLIC_KEY:
                        logging.error(
                            "Missing authentication keys. Please check environment variables."
                        )
                        return False
                    logging.info(
                        f"Retrying connection in {reconnect_delay} seconds... (Attempt {retry_count + 1}/{max_retries})"
                    )

                elif "401" in error_msg:
                    logging.warning("Unauthorized. This could indicate a pattern...")
                    self.state_transitions.append(
                        {
                            "time": time.time(),
                            "type": "auth_error_401",
                            "data": error_msg,
                        }
                    )
                    # Track timing of auth errors for pattern analysis
                    if len(self.state_transitions) >= 2:
                        last_two = [
                            x
                            for x in self.state_transitions[-2:]
                            if x["type"] == "auth_error_401"
                        ]
                        if len(last_two) == 2:
                            time_diff = last_two[1]["time"] - last_two[0]["time"]
                            if time_diff < 5.0:
                                logging.warning(
                                    f"Rapid auth errors detected ({time_diff:.2f}s apart)"
                                )

                else:
                    logging.error(f"Connection failed: {error_msg}")
                    return False

            except Exception as e:
                logging.error(f"Connection error: {str(e)}")

            retry_count += 1
            if retry_count < max_retries:
                logging.info(
                    f"Retrying connection in {reconnect_delay} seconds... (Attempt {retry_count}/{max_retries})"
                )
                await asyncio.sleep(reconnect_delay)
            else:
                logging.error("Max retries reached. Exiting...")
                success = False

        return success

    async def process_message(
        self, websocket: WebSocketProtocol, message: Data
    ) -> None:
        try:
            # Handle different Socket.IO message types
            if isinstance(message, str) and message.startswith("0"):  # Socket.IO open
                logging.info("Socket.IO connection opened")
                return

            if isinstance(message, str) and message.startswith(
                "40"
            ):  # Socket.IO connection
                logging.info("Socket.IO namespace connected")
                await self.send_auth_sequence(websocket)
                return

            if isinstance(message, str) and message.startswith("2"):  # Socket.IO ping
                logging.debug("Received ping")
                await websocket.send("3")  # Send pong
                return

            if isinstance(message, str) and message.startswith("3"):  # Socket.IO pong
                logging.debug("Received pong")
                return

            # Try to parse as JSON if it's a data message
            try:
                if isinstance(message, str) and message.startswith(
                    "42"
                ):  # Socket.IO event
                    data = json.loads(message[2:])
                    await self.handle_game_data(data)

                    # Track undefined states
                    if "undefined" in str(data):
                        logging.warning("Undefined state detected")
                        self.state_transitions.append(
                            {
                                "time": time.time(),
                                "type": "undefined_state",
                                "data": data,
                            }
                        )

            except json.JSONDecodeError:
                if isinstance(message, str) and (
                    "401" in message or "unauthorized" in message.lower()
                ):
                    logging.warning("Authentication error detected")
                    self.state_transitions.append(
                        {"time": time.time(), "type": "auth_error", "data": message}
                    )
                else:
                    logging.warning(f"Failed to decode JSON: {message}")

        except Exception as e:
            logging.error(f"Error processing message: {str(e)}")

    async def send_auth_sequence(self, websocket: WebSocketProtocol) -> None:
        """Send the authentication sequence observed in successful connections"""
        try:
            # Initial Socket.IO handshake
            await websocket.send("40")
            await asyncio.sleep(0.1)  # Small delay between messages

            # Engine.IO upgrade
            await websocket.send("2probe")
            await asyncio.sleep(0.1)

            # Confirm upgrade
            await websocket.send("5")
            await asyncio.sleep(0.1)

            # Auth message with credentials
            auth_data = {
                "token": WALLET_PRIVATE_KEY,
                "publicKey": PUBLIC_KEY,
                "timestamp": str(int(time.time() * 1000)),
            }
            await websocket.send("42" + json.dumps(["auth", auth_data]))
            await asyncio.sleep(0.2)

            # Subscribe to crash game events
            await websocket.send("42" + json.dumps(["subscribe", "crash"]))

            # Send heartbeat
            await websocket.send("2")

            logging.info("Full authentication sequence sent")

            # Start heartbeat loop in background
            asyncio.create_task(self.heartbeat_loop(websocket))

        except Exception as e:
            logging.error(f"Error in auth sequence: {str(e)}")

    async def heartbeat_loop(self, websocket: WebSocketProtocol) -> None:
        """Maintain connection with periodic heartbeats"""
        try:
            while True:
                await asyncio.sleep(25)  # Socket.IO default heartbeat interval
                try:
                    await websocket.send("2")
                    logging.debug("Heartbeat sent")
                except Exception as e:
                    logging.error(f"Failed to send heartbeat: {str(e)}")
                    break
        except asyncio.CancelledError:
            logging.info("Heartbeat loop cancelled")
            return

    async def handle_game_data(self, data: List[Any]) -> None:
        try:
            event_type = data[0] if len(data) > 0 else None
            event_data = data[1] if len(data) > 1 else None

            if not event_type or not event_data:
                return

            current_time = time.time()

            # Log all game state transitions
            self.state_transitions.append(
                {"time": current_time, "event": event_type, "data": event_data}
            )

            # Track crash events and analyze patterns
            if event_type == "crash":
                if self.last_crash_time:
                    interval = current_time - self.last_crash_time
                    self.crash_intervals.append(interval)

                    # Check for extended intervals (potential high crash indicator)
                    if interval > 45.0:
                        logging.warning(
                            f"EXTENDED INTERVAL DETECTED: {interval:.2f}s - Possible high crash incoming"
                        )

                    # Check for specific timing patterns
                    if 82.0 <= interval <= 96.0:
                        logging.warning(
                            f"EXTREME CRASH PATTERN: {interval:.2f}s interval detected - Possible >80x crash incoming"
                        )
                    elif 45.0 <= interval <= 67.0:
                        logging.warning(
                            f"HIGH CRASH PATTERN: {interval:.2f}s interval detected - Possible 8-15x crash incoming"
                        )

                self.last_crash_time = current_time

                if "multiplier" in event_data:
                    multiplier = float(event_data["multiplier"])
                    self.multiplier_sequence.append(multiplier)

                    # Analyze sequence patterns
                    if len(self.multiplier_sequence) >= 3:
                        last_three = self.multiplier_sequence[-3:]
                        # Check for three consecutive low crashes pattern
                        if all(x < 2.0 for x in last_three):
                            logging.warning(
                                "THREE LOW CRASHES DETECTED - High crash probability in next round"
                            )

                        # Check for progressive increase pattern
                        if len(self.multiplier_sequence) >= 4:
                            if all(
                                last_three[i] < last_three[i + 1]
                                for i in range(len(last_three) - 1)
                            ):
                                logging.warning(
                                    "PROGRESSIVE INCREASE DETECTED - Possible extreme crash incoming"
                                )

                    if len(self.multiplier_sequence) > 3:
                        self.analyze_sequence()

            # Track player count changes
            if "players" in str(event_data):
                try:
                    player_count = int(event_data.get("players", 0))
                    if player_count > 3:
                        logging.warning(
                            f"HIGH PLAYER COUNT: {player_count} - Increased crash probability"
                        )
                    elif player_count <= 2:
                        logging.info(
                            f"LOW PLAYER COUNT: {player_count} - Possible low crash incoming"
                        )
                except (ValueError, AttributeError):
                    pass

            # Log detailed state information
            logging.info(f"Event: {event_type}")
            logging.info(f"Data: {json.dumps(event_data, indent=2)}")

        except Exception as e:
            logging.error(f"Error handling game data: {str(e)}")

    def analyze_sequence(self):
        """Analyze the last 4 multipliers in the sequence for patterns"""
        if len(self.multiplier_sequence) < 4:
            return

        last_four = self.multiplier_sequence[-4:]
        logging.info(f"Analyzing sequence: {last_four}")

        # Check for known patterns
        if all(x < 2.0 for x in last_four[:-1]) and last_four[-1] > 5.0:
            logging.warning(
                "PATTERN DETECTED: Three low crashes followed by high crash"
            )

        # Check for extended intervals
        if len(self.crash_intervals) >= 2:
            last_interval = self.crash_intervals[-1]
            if last_interval > 45.0:
                logging.warning(f"EXTENDED INTERVAL DETECTED: {last_interval:.2f}s")


async def main() -> None:
    tester = CrashWebsocketTester()
    while True:
        try:
            await tester.connect()
        except Exception as e:
            logging.error(f"Connection error: {str(e)}")
            logging.info("Attempting to reconnect in 5 seconds...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
