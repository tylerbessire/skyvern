#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union, cast
from urllib.parse import quote, urlencode

import aiohttp
import websockets
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from websockets.legacy.client import WebSocketClientProtocol

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,  # Enable debug logging
    format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("ws_minimal_test.log"),
        logging.StreamHandler(),
    ],
)

# Track suspicious patterns
suspicious_patterns = {
    "rapid_auth_errors": [],
    "long_intervals": [],
    "undefined_states": [],
    "connection_delays": [],
    "crash_sequences": [],
}


class MinimalWSTest:
    def __init__(self) -> None:
        self.t: str = str(int(time.time() * 1000))
        # Use proper Socket.IO v4 URL format with crash namespace and browser-like parameters
        self.uri: str = (
            f"wss://trustdice.win/crash/socket.io/?EIO=4&transport=websocket&t={self.t}&sid={self.t}"
        )

        # Initialize session and websocket with proper type annotations
        self.session: Optional[aiohttp.ClientSession] = None
        self.websocket: Optional[WebSocketClientProtocol] = None

        # Initialize session and cookie management
        self.session_id: Optional[str] = None
        self.last_ping: Optional[float] = None
        self.ping_interval: int = 25000  # Default Socket.IO ping interval
        self.cookies: Dict[str, str] = {}  # Store cookies
        self.session: Optional[aiohttp.ClientSession] = None
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.connected: bool = False

        # Track suspicious patterns
        self.suspicious_patterns: Dict[str, List[Union[float, Tuple[float, str]]]] = {
            "rapid_auth_errors": [],
            "long_intervals": [],
            "undefined_states": [],
            "connection_delays": [],
            "crash_sequences": [],
        }

        # Get credentials from environment
        self.wallet_key = os.getenv("WALLET_PRIVATE_KEY")
        self.public_key = os.getenv("PUBLIC_KEY")

        if not self.wallet_key or not self.public_key:
            raise ValueError("Missing required environment variables")

        # Enhanced browser-like headers
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Origin": "https://trustdice.win",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

        # Initialize cookie jar with credentials
        self.update_cookies(
            {
                "wallet_private_key": quote(self.wallet_key),
                "public_key": quote(self.public_key),
            }
        )

        # Track message patterns
        self.last_crash_time: Optional[float] = None
        self.intervals: List[float] = []
        self.undefined_states: List[float] = []
        self.auth_errors: List[float] = []
        self.element_counts: List[Tuple[float, int]] = []
        self.bodytext_values: List[Tuple[float, int]] = []
        self.error_sequence: List[Tuple[float, str]] = []
        self.undefined_sequence: List[float] = []
        self.last_401_time: Optional[float] = None

    def update_cookies(self, new_cookies):
        """Update cookies and cookie header"""
        self.cookies.update(new_cookies)
        cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
        self.headers["Cookie"] = cookie_str
        logging.debug(f"Updated cookies: {cookie_str}")

    async def handle_message(self, message):
        """Process incoming websocket messages with enhanced pattern detection"""
        if not self.websocket or not self.connected:
            logging.error("Cannot handle message: WebSocket not connected")
            return

        try:
            logging.debug(f"Raw message: {message}")
            message_time = time.time()

            # Initialize pattern tracking if not exists
            if not hasattr(self, "error_sequence"):
                self.error_sequence = []
            if not hasattr(self, "element_counts"):
                self.element_counts = []
            if not hasattr(self, "bodytext_values"):
                self.bodytext_values = []
            if not hasattr(self, "last_401_time"):
                self.last_401_time = None
            if not hasattr(self, "undefined_sequence"):
                self.undefined_sequence = []

            # Handle Socket.IO message types
            if message.startswith("0"):  # Socket.IO open
                logging.info("Socket.IO connection opened")
                self.connection_time = message_time
                await asyncio.sleep(0.1)
                await self.websocket.send("2probe")
                return

            if message.startswith("3"):  # Engine.IO pong
                logging.debug("Received pong")
                return

            if message.startswith("40"):  # Socket.IO connection established
                logging.info("Socket.IO namespace connected")
                if hasattr(self, "connection_time"):
                    setup_time = time.time() - self.connection_time
                    logging.info(f"Connection setup time: {setup_time:.3f}s")
                    if setup_time > 2.0:
                        logging.warning(f"Unusual connection delay: {setup_time:.3f}s")
                await self.send_auth()
                return

            if message.startswith("2"):  # Engine.IO ping
                await self.websocket.send("3")  # Send pong
                logging.debug("Ping-pong completed")
                return

            if message.startswith("42"):  # Socket.IO event
                try:
                    data = json.loads(message[2:])
                    if len(data) >= 2:
                        event_name = data[0]
                        event_data = data[1]

                        # Track crash events with enhanced pattern detection
                        if event_name == "crash.tick":
                            current_time = time.time()
                            if self.last_crash_time:
                                interval = current_time - self.last_crash_time
                                self.intervals.append(interval)

                                # Check for suspicious intervals
                                if interval > 45.0:
                                    logging.warning(
                                        f"Long interval detected: {interval:.2f}s"
                                    )
                                    self.check_crash_indicators()

                            self.last_crash_time = current_time

                            # Track element counts
                            if "elements" in str(event_data):
                                try:
                                    count = int(
                                        str(event_data)
                                        .split('elements":')[1]
                                        .split(",")[0]
                                    )
                                    self.element_counts.append((time.time(), count))
                                    self.analyze_element_pattern()
                                except (ValueError, IndexError):
                                    logging.warning("Failed to parse element count")

                            # Track bodyText values
                            if "bodyText" in str(event_data):
                                try:
                                    value = int(
                                        str(event_data)
                                        .split('bodyText":')[1]
                                        .split(",")[0]
                                    )
                                    self.bodytext_values.append((time.time(), value))
                                    self.analyze_bodytext_pattern()
                                except (ValueError, IndexError):
                                    logging.warning("Failed to parse bodyText value")

                        # Enhanced undefined state tracking
                        if "undefined" in str(event_data):
                            self.undefined_sequence.append(time.time())
                            if len(self.undefined_sequence) >= 3:
                                recent_undefined = self.undefined_sequence[-3:]
                                if (recent_undefined[-1] - recent_undefined[0]) < 2.0:
                                    logging.warning(
                                        "Multiple undefined states detected in quick succession"
                                    )
                                    self.check_crash_indicators()

                        # Track 401 errors
                        if "401" in str(event_data):
                            current_time = time.time()
                            if (
                                self.last_401_time
                                and (current_time - self.last_401_time) < 2.0
                            ):
                                logging.warning(
                                    "Multiple 401 errors in quick succession"
                                )
                                self.check_crash_indicators()
                            self.last_401_time = current_time

                except json.JSONDecodeError:
                    logging.error(f"Failed to parse event data: {message}")

        except Exception as e:
            logging.error(f"Error processing message: {str(e)}")

    def check_crash_indicators(self):
        """Check for patterns that might indicate an imminent crash"""
        current_time = time.time()

        # Check element count transitions
        if len(self.element_counts) >= 2:
            last_counts = self.element_counts[-2:]
            if last_counts[0][1] == 1199 and last_counts[1][1] >= 1270:
                logging.warning("Suspicious element count transition detected")

        # Check bodyText drops
        if len(self.bodytext_values) >= 2:
            last_values = self.bodytext_values[-2:]
            if (last_values[0][1] - last_values[1][1]) > 100:
                logging.warning("Significant bodyText value drop detected")

        # Check for error sequence pattern
        if self.last_401_time and len(self.undefined_sequence) > 0:
            if (
                self.undefined_sequence
                and 0 < (current_time - self.last_401_time) < 5.0
            ):
                logging.warning(
                    "Potential crash pattern: 401 error followed by undefined state"
                )

    def analyze_element_pattern(self):
        """Analyze element count patterns for crash indicators"""
        if len(self.element_counts) < 3:
            return

        recent_counts = self.element_counts[-3:]
        # Check for known patterns
        if recent_counts[0][1] == 1199 and recent_counts[1][1] == 1270:
            time_diff = recent_counts[1][0] - recent_counts[0][0]
            if time_diff < 1.0:  # Rapid transition
                logging.warning("High-risk element count pattern detected")

    def analyze_bodytext_pattern(self):
        """Analyze bodyText patterns for crash indicators"""
        if len(self.bodytext_values) < 3:
            return

        recent_values = self.bodytext_values[-3:]
        # Check for rapid drops
        if (recent_values[0][1] - recent_values[1][1]) > 50 and (
            recent_values[1][1] - recent_values[2][1]
        ) > 50:
            logging.warning(
                "Consecutive bodyText drops detected - potential crash indicator"
            )

    async def send_auth(self):
        """Send Socket.IO authentication sequence"""
        try:
            if not self.websocket or not self.connected:
                logging.error("Cannot send auth: WebSocket not connected")
                return False

            # Engine.IO upgrade after probe response
            await self.websocket.send("5")  # Engine.IO upgrade
            await asyncio.sleep(0.1)

            # Send ping to maintain connection
            await self.websocket.send("2")
            await asyncio.sleep(0.1)

            # Auth message with credentials and timestamp
            auth_data = {
                "token": self.wallet_key,
                "publicKey": self.public_key,
                "timestamp": str(int(time.time() * 1000)),
            }
            auth_message = "42" + json.dumps(["auth", auth_data])
            await self.websocket.send(auth_message)
            logging.info("Auth sequence sent")
            await asyncio.sleep(0.2)

            # Subscribe to crash events
            await self.websocket.send("42" + json.dumps(["subscribe", "crash"]))
            logging.info("Subscribed to crash events")

            # Start heartbeat
            asyncio.create_task(self.heartbeat_loop())
            return True

        except Exception as e:
            logging.error(f"Auth sequence failed: {str(e)}")
            self.connected = False
            return False

    async def heartbeat_loop(self):
        """Maintain connection with periodic heartbeats"""
        try:
            while True:
                await asyncio.sleep(25)  # Socket.IO default heartbeat interval
                try:
                    if not self.websocket or not self.connected:
                        logging.error("Cannot send heartbeat: WebSocket not connected")
                        break
                    await self.websocket.send("2")  # Engine.IO ping
                    logging.debug("Heartbeat sent")
                except Exception as e:
                    logging.error(f"Failed to send heartbeat: {str(e)}")
                    self.connected = False
                    break
        except asyncio.CancelledError:
            logging.info("Heartbeat loop cancelled")
            return

    async def get_session_id(self):
        """Perform initial Socket.IO HTTP handshake with enhanced browser simulation"""
        try:
            # Create persistent session with cookie jar
            if not self.session:
                cookie_jar = aiohttp.CookieJar(unsafe=True)
                self.session = aiohttp.ClientSession(cookie_jar=cookie_jar)
                if not self.session:
                    logging.error("Failed to create aiohttp session")
                    return False

            # First, visit the main page to get necessary cookies
            main_url = "https://trustdice.win/crash"
            logging.info("Visiting main page...")

            # Initial page visit with browser-like behavior
            if self.session:  # Type guard
                async with self.session.get(
                    main_url, headers=self.headers, allow_redirects=True
                ) as response:
                    # Extract and store cookies from response
                    if response.cookies:
                        for cookie in response.cookies.values():
                            self.update_cookies({cookie.key: cookie.value})
                            if cookie.key == "cf_clearance":
                                logging.info("Received Cloudflare clearance cookie")

                # Handle Cloudflare challenge if needed
                if response.status == 403:
                    logging.warning(
                        "Initial visit blocked by Cloudflare, attempting with enhanced headers..."
                    )
                    # Add more browser-like headers
                    self.headers.update(
                        {
                            "DNT": "1",
                            "Sec-Fetch-Site": "same-origin",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-User": "?1",
                            "Sec-Fetch-Dest": "document",
                        }
                    )
                    # Retry with enhanced headers
                    if self.session:  # Type guard
                        async with self.session.get(
                            main_url, headers=self.headers, allow_redirects=True
                        ) as retry_response:
                            if retry_response.cookies:
                                for cookie in retry_response.cookies.values():
                                    self.update_cookies({cookie.key: cookie.value})

                # Wait for potential JavaScript execution
                await asyncio.sleep(2)

                # Now attempt Socket.IO handshake with proper headers
                params = {"EIO": "4", "transport": "polling", "t": self.t}
                url = f"https://trustdice.win/crash/socket.io/?{urlencode(params)}"

                # Enhanced headers for Socket.IO request
                socket_headers = {
                    **self.headers,
                    "Referer": "https://trustdice.win/crash",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                }

                logging.info("Attempting Socket.IO handshake...")
                if self.session:  # Type guard
                    async with self.session.get(
                        url, headers=socket_headers
                    ) as response:
                        # Update cookies from handshake response
                        if response.cookies:
                            for cookie in response.cookies.values():
                                self.update_cookies({cookie.key: cookie.value})

                    if response.status == 200:
                        data = await response.text()
                        logging.debug(f"Handshake response: {data}")

                        if data.startswith("0"):
                            session_data = json.loads(data[1:])
                            self.session_id = session_data.get("sid")
                            self.ping_interval = session_data.get("pingInterval", 25000)
                            logging.info(f"Got session ID: {self.session_id}")

                            # Perform post-handshake request
                            post_data = '40{"jwt":null}'
                            post_url = f"https://trustdice.win/crash/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.session_id}"

                            if self.session:  # Type guard
                                async with self.session.post(
                                    post_url, data=post_data, headers=socket_headers
                                ) as post_response:
                                    if post_response.cookies:
                                        for cookie in post_response.cookies.values():
                                            self.update_cookies(
                                                {cookie.key: cookie.value}
                                            )

                                if post_response.status == 200:
                                    logging.info("Post-handshake request successful")
                                    return True
                                else:
                                    logging.error(
                                        f"Post-handshake request failed: {post_response.status}"
                                    )
                    else:
                        logging.error(f"Failed to get session ID: {response.status}")
                        return False

            return False

        except Exception as e:
            logging.error(f"Session ID request failed: {str(e)}")
            return False

    async def connect(self):
        """Establish websocket connection with proper handshake and browser simulation"""
        try:
            # Get session ID first
            if not await self.get_session_id():
                logging.error(
                    "Failed to get session ID, analyzing browser connection..."
                )
                # Analyze successful browser connection
                if not await self.analyze_browser_connection():
                    return False
                # Try getting session ID again after browser analysis
                if not await self.get_session_id():
                    logging.error(
                        "Still unable to get session ID after browser analysis"
                    )
                    return False

            # Construct WebSocket URL with session ID
            ws_params = {
                "EIO": "4",
                "transport": "websocket",
                "sid": self.session_id,
                "t": self.t,
            }
            self.uri = f"wss://trustdice.win/crash/socket.io/?{urlencode(ws_params)}"

            # Enhanced WebSocket headers based on browser analysis
            ws_headers = {
                "Host": "trustdice.win",
                "Connection": "Upgrade",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache",
                "User-Agent": self.headers["User-Agent"],
                "Upgrade": "websocket",
                "Origin": "https://trustdice.win",
                "Sec-WebSocket-Version": "13",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
                "Sec-WebSocket-Key": self.generate_websocket_key(),
                "Cookie": self.headers.get("Cookie", ""),
            }

            # Add all security headers
            ws_headers.update(
                {
                    "Sec-Fetch-Dest": "websocket",
                    "Sec-Fetch-Mode": "websocket",
                    "Sec-Fetch-Site": "same-origin",
                    "sec-ch-ua": self.headers["sec-ch-ua"],
                    "sec-ch-ua-mobile": self.headers["sec-ch-ua-mobile"],
                    "sec-ch-ua-platform": self.headers["sec-ch-ua-platform"],
                }
            )

            # Create new websocket connection with proper type casting
            connection = await websockets.connect(
                self.uri,
                open_timeout=20,
                close_timeout=20,
                max_size=2**23,
                extra_headers=[(k, v) for k, v in ws_headers.items()],
                compression=None,
            )
            # Cast the connection to WebSocketClientProtocol and assign
            self.websocket = cast(WebSocketClientProtocol, connection)

            logging.info(f"Connected to {self.uri}")
            self.connected = True

            # Initialize connection with proper Socket.IO sequence
            await self.initialize_socket_io(self.websocket)

            return True

        except Exception as e:
            logging.error(f"Connection error: {str(e)}")
            if "403" in str(e):
                logging.error(
                    "Cloudflare protection detected, analyzing browser connection..."
                )
                if await self.analyze_browser_connection():
                    # Try connecting again after successful browser analysis
                    return await self.connect()
            self.connected = False
            if hasattr(self, "websocket") and self.websocket:
                await self.websocket.close()
                self.websocket = None
            return False

    def generate_websocket_key(self):
        """Generate a valid WebSocket key"""
        import base64
        import os

        return base64.b64encode(os.urandom(16)).decode()

    async def initialize_socket_io(self, websocket):
        """Initialize Socket.IO connection with proper sequence"""
        try:
            if not websocket:
                logging.error("Cannot initialize: WebSocket is None")
                self.connected = False
                return False

            # Send initial probe
            await websocket.send("2probe")
            response = await websocket.recv()
            if response == "3probe":
                logging.info("Probe successful")
                # Send connection upgrade
                await websocket.send("5")
                # Start heartbeat
                asyncio.create_task(self.heartbeat_loop())
                return True
            else:
                logging.error(f"Unexpected probe response: {response}")
                self.connected = False
                return False

        except Exception as e:
            logging.error(f"Socket.IO initialization failed: {str(e)}")
            self.connected = False
            return False

    async def analyze_browser_connection(self):
        """Use Selenium to handle Cloudflare and extract cookies"""
        logging.info("Starting browser connection analysis with Selenium...")
        try:
            # Initialize Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument(f'user-agent={self.headers["User-Agent"]}')

            # Add authentication cookies
            chrome_options.add_argument(
                f'--cookie="wallet_private_key={self.cookies.get("wallet_private_key", "")}; public_key={self.cookies.get("public_key", "")}"'
            )

            # Initialize WebDriver
            driver = webdriver.Chrome(options=chrome_options)
            try:
                logging.info("Visiting page with Selenium...")
                driver.get("https://trustdice.win/crash")

                # Wait for Cloudflare challenge to complete (max 30 seconds)
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Wait a bit more for any JavaScript to execute
                await asyncio.sleep(5)

                # Get all cookies
                selenium_cookies = driver.get_cookies()
                for cookie in selenium_cookies:
                    self.cookies[cookie["name"]] = cookie["value"]
                    if cookie["name"] == "cf_clearance":
                        logging.info(
                            "Successfully obtained Cloudflare clearance cookie"
                        )

                # Update headers with new cookies
                self.update_cookies(self.cookies)

                # Log success and save analysis
                logging.info("Browser connection analysis complete")
                with open("connection_analysis.log", "w") as f:
                    f.write("=== Headers ===\n")
                    for k, v in self.headers.items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n=== Cookies ===\n")
                    for k, v in self.cookies.items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n=== Selenium Cookies ===\n")
                    for cookie in selenium_cookies:
                        f.write(f"{cookie['name']}: {cookie['value']}\n")

                return True

            finally:
                driver.quit()

        except Exception as e:
            logging.error(f"Selenium analysis failed: {str(e)}")
            return False


async def main():
    test = MinimalWSTest()
    await test.connect()


if __name__ == "__main__":
    asyncio.run(main())
