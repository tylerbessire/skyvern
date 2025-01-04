#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
import time
import os
import ssl
import aiohttp
import base64
import secrets
from urllib.parse import urlencode, quote
from collections import deque
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('crash_pattern_test.log'),
        logging.StreamHandler()
    ]
)

class CrashPatternTest:
    def __init__(self):
        self.t = str(int(time.time() * 1000))
        self.uri = f"wss://trustdice.win/crash/socket.io/?EIO=4&transport=websocket&t={self.t}"
        self.wallet_key = os.getenv("WALLET_PRIVATE_KEY")
        self.public_key = os.getenv("PUBLIC_KEY")
        
        # Connection state
        self.session_id = None
        self.connected = False
        self.cookies = {}
        self.websocket = None
        self.session = None
        self.last_ping = None
        self.ping_interval = 25000

        # Headers for browser simulation
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Origin": "https://trustdice.win",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Pattern tracking
        self.element_history = deque(maxlen=5)
        self.bodytext_history = deque(maxlen=5)
        self.crash_times = deque(maxlen=10)
        self.undefined_sequence = deque(maxlen=5)
        self.auth_errors = deque(maxlen=5)

        # Prediction tracking
        self.predicted_crashes = []
        self.actual_crashes = []
        self.prediction_accuracy = []

        # Initialize cookies with credentials
        self.update_cookies({
            'wallet_private_key': self.wallet_key,
            'public_key': self.public_key
        })
        
    def update_cookies(self, new_cookies):
        """Update cookies and cookie header"""
        self.cookies.update(new_cookies)
        cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
        self.headers['Cookie'] = cookie_str
        logging.debug(f"Updated cookies: {cookie_str}")

    async def get_session_id(self):
        """Perform initial Socket.IO HTTP handshake with enhanced browser simulation"""
        try:
            # Create persistent session with cookie jar
            if not self.session:
                cookie_jar = aiohttp.CookieJar(unsafe=True)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                conn = aiohttp.TCPConnector(ssl=ssl_context)
                self.session = aiohttp.ClientSession(cookie_jar=cookie_jar, connector=conn)
            
            # First, visit the main page to get necessary cookies
            main_url = "https://trustdice.win/crash"
            logging.info("Visiting main page...")
            
            # Initial page visit with browser-like behavior
            async with self.session.get(main_url, headers=self.headers, allow_redirects=True) as response:
                # Extract and store cookies from response
                if response.cookies:
                    for cookie in response.cookies.values():
                        self.update_cookies({cookie.key: cookie.value})
                        if cookie.key == 'cf_clearance':
                            logging.info("Received Cloudflare clearance cookie")
                
                # Handle Cloudflare challenge if needed
                if response.status == 403:
                    logging.warning("Initial visit blocked by Cloudflare, attempting with enhanced headers...")
                    # Add more browser-like headers
                    self.headers.update(
                        {
                            "DNT": "1",
                            "Sec-Fetch-Site": "same-origin",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-User": "?1",
                            "Sec-Fetch-Dest": "document"
                        }
                    )
                    # Retry with enhanced headers
                    async with self.session.get(main_url, headers=self.headers, allow_redirects=True) as retry_response:
                        if retry_response.cookies: 
                            for cookie in retry_response.cookies.values():
                                self.update_cookies({cookie.key: cookie.value})
                
                # Wait for potential JavaScript execution
                await asyncio.sleep(2)
                
                # Now attempt Socket.IO handshake with proper headers
                params = {
                    "EIO": "4",
                    "transport": "polling",
                    "t": self.t
                }
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
                    "X-Requested-With": "XMLHttpRequest"
                }
                
                logging.info("Attempting Socket.IO handshake...")
                async with self.session.get(url, headers=socket_headers) as response:
                    # Update cookies from handshake response
                    if response.cookies:
                        for cookie in response.cookies.values():
                            self.update_cookies({cookie.key: cookie.value})
                    
                    if response.status == 200:
                        data = await response.text()
                        logging.debug(f"Handshake response: {data}")
                        
                        if data.startswith('0'):
                            try:
                                session_data = json.loads(data[1:])
                                self.session_id = session_data.get('sid')
                                self.ping_interval = session_data.get('pingInterval', 25000)
                                logging.info(f"Got session ID: {self.session_id}")
                                
                                # Perform post-handshake request
                                post_data = '40{"jwt":null}'
                                post_url = f"https://trustdice.win/crash/socket.io/?EIO=4&transport=polling&t={self.t}&sid={self.session_id}"
                                
                                async with self.session.post(post_url, data=post_data, headers=socket_headers) as post_response:
                                    if post_response.cookies:
                                        for cookie in post_response.cookies.values():
                                            self.update_cookies({cookie.key: cookie.value})
                                            
                                    if post_response.status == 200:
                                        logging.info("Post-handshake request successful")
                                        return True
                                    else:
                                        logging.error(f"Post-handshake request failed: {post_response.status}")
                            except json.JSONDecodeError as je:
                                logging.error(f"Failed to parse session data: {je}")
                        else:
                            logging.error(f"Unexpected response format: {data[:20]}...")
                    else:
                        logging.error(f"Failed to get session ID: {response.status}")
                        return False
            
            return False
            
        except Exception as e:
            logging.error(f"Session ID request failed: {str(e)}")
            logging.exception("Detailed error trace:")
            return False

    def generate_websocket_key(self):
        """Generate a random WebSocket key"""
        rand_bytes = secrets.token_bytes(16)
        return base64.b64encode(rand_bytes).decode()

    async def analyze_browser_connection(self):
        """Analyze successful browser connection patterns"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get('https://trustdice.win/crash')
            
            # Wait for WebSocket connection
            await asyncio.sleep(5)
            
            # Extract cookies and headers
            cookies = driver.get_cookies()
            for cookie in cookies:
                self.update_cookies({cookie['name']: cookie['value']})
            
            # Update headers based on successful connection
            self.headers.update({
                'Referer': driver.current_url,
                'sec-ch-ua': driver.execute_script('return navigator.userAgent'),
                'Cookie': '; '.join([f"{c['name']}={c['value']}" for c in cookies])
            })
            
            driver.quit()
            return True
            
        except Exception as e:
            logging.error(f"Browser analysis failed: {str(e)}")
            return False

    async def initialize_socket_io(self, websocket):
        """Initialize Socket.IO connection with proper sequence"""
        try:
            # Send initial probe
            await websocket.send('2probe')
            response = await websocket.recv()
            
            if response == '3probe':
                # Upgrade connection
                await websocket.send('5')
                await asyncio.sleep(0.1)
                
                # Connect to namespace
                await websocket.send('40')
                
                # Start heartbeat loop
                asyncio.create_task(self.heartbeat_loop())
                return True
            else:
                logging.error(f"Unexpected probe response: {response}")
                return False
                
        except Exception as e:
            logging.error(f"Socket.IO initialization failed: {str(e)}")
            return False

    async def connect(self):
        """Establish websocket connection with proper handshake and browser simulation"""
        try:
            # Get session ID first
            if not await self.get_session_id():
                logging.error("Failed to get session ID, analyzing browser connection...")
                # Analyze successful browser connection
                if not await self.analyze_browser_connection():
                    return False
                # Try getting session ID again after browser analysis
                if not await self.get_session_id():
                    logging.error("Still unable to get session ID after browser analysis")
                    return False
            
            # Construct WebSocket URL with session ID
            ws_params = {
                'EIO': '4',
                'transport': 'websocket',
                'sid': self.session_id,
                't': self.t
            }
            self.uri = f"wss://trustdice.win/crash/socket.io/?{urlencode(ws_params)}"
            
            # Enhanced WebSocket headers
            ws_headers = {
                'Host': 'trustdice.win',
                'Connection': 'Upgrade',
                'Pragma': 'no-cache',
                'Cache-Control': 'no-cache',
                'User-Agent': self.headers['User-Agent'],
                'Upgrade': 'websocket',
                'Origin': 'https://trustdice.win',
                'Sec-WebSocket-Version': '13',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits',
                'Sec-WebSocket-Key': self.generate_websocket_key(),
                'Cookie': self.headers.get('Cookie', '')
            }
            
            # Add security headers
            ws_headers.update({
                'Sec-Fetch-Dest': 'websocket',
                'Sec-Fetch-Mode': 'websocket',
                'Sec-Fetch-Site': 'same-origin',
                'sec-ch-ua': self.headers['sec-ch-ua'],
                'sec-ch-ua-mobile': self.headers['sec-ch-ua-mobile'],
                'sec-ch-ua-platform': self.headers['sec-ch-ua-platform']
            })
            
            self.websocket = await websockets.connect(
                self.uri,
                extra_headers=[(k, v) for k, v in ws_headers.items()],
                compression=None,
                max_size=2**23
            )
            
            logging.info(f"Connected to {self.uri}")
            self.connected = True
            
            # Initialize connection with proper Socket.IO sequence
            if not await self.initialize_socket_io(self.websocket):
                return False
            
            # Send authentication
            await self.send_auth()
            return True
            
        except Exception as e:
            logging.error(f"Connection error: {str(e)}")
            if "403" in str(e):
                logging.warning("Cloudflare protection detected, attempting browser simulation...")
                if await self.analyze_browser_connection():
                    return await self.connect()  # Retry connection
            elif "websocket" in str(e).lower():
                logging.error("WebSocket connection failed, attempting reconnection...")
                await asyncio.sleep(2)
                return await self.connect()
            return False
    
    def analyze_element_pattern(self, count):
        """Analyze element count patterns for crash prediction"""
        self.element_history.append((time.time(), count))
        
        if len(self.element_history) >= 3:
            # Check for rapid increase pattern
            recent = list(self.element_history)[-3:]
            if recent[0][1] == 1199 and recent[1][1] >= 1270:
                time_diff = recent[1][0] - recent[0][0]
                if time_diff < 1.0:
                    logging.warning("PREDICTION: Crash likely within 2-3 seconds (element pattern)")
                    self.predicted_crashes.append(('element', time.time()))
                    return True
        return False
    
    def analyze_bodytext_pattern(self, value):
        """Analyze bodyText patterns for crash prediction"""
        self.bodytext_history.append((time.time(), value))
        
        if len(self.bodytext_history) >= 3:
            recent = list(self.bodytext_history)[-3:]
            # Check for consecutive drops
            if (recent[0][1] - recent[1][1]) > 50 and \
               (recent[1][1] - recent[2][1]) > 50:
                logging.warning("PREDICTION: Crash likely within 1-2 seconds (bodyText pattern)")
                self.predicted_crashes.append(('bodytext', time.time()))
                return True
        return False
    
    def record_crash(self, timestamp):
        """Record actual crash and evaluate predictions"""
        self.actual_crashes.append(timestamp)
        
        # Evaluate recent predictions
        recent_predictions = [p for p in self.predicted_crashes 
                            if 0 <= timestamp - p[1] <= 3.0]  # 3-second window
        
        if recent_predictions:
            accuracy = len(recent_predictions) / len(self.predicted_crashes)
            self.prediction_accuracy.append(accuracy)
            logging.info(f"Prediction accuracy: {accuracy:.2%}")
            
            # Log successful prediction details
            for pred_type, pred_time in recent_predictions:
                time_diff = timestamp - pred_time
                logging.info(f"Successful prediction: {pred_type} pattern predicted crash {time_diff:.2f}s before occurrence")
    
    async def handle_message(self, message):
        """Process messages with focus on pattern detection"""
        try:
            if message.startswith('42'):
                data = json.loads(message[2:])
                if len(data) >= 2:
                    event_name = data[0]
                    event_data = data[1]
                    
                    if event_name == "crash.tick":
                        # Extract and analyze element count
                        if 'elements' in str(event_data):
                            try:
                                count = int(str(event_data).split('elements":')[1].split(',')[0])
                                self.analyze_element_pattern(count)
                            except:
                                pass
                        
                        # Extract and analyze bodyText
                        if 'bodyText' in str(event_data):
                            try:
                                value = int(str(event_data).split('bodyText":')[1].split(',')[0])
                                self.analyze_bodytext_pattern(value)
                            except:
                                pass
                    
                    
                    elif event_name == "crash":
                        self.record_crash(time.time())
                        
                    # Track undefined states
                    if "undefined" in str(event_data):
                        self.undefined_sequence.append(time.time())
                        if len(self.undefined_sequence) >= 3:
                            recent = list(self.undefined_sequence)[-3:]
                            if (recent[-1] - recent[0]) < 2.0:
                                logging.warning("Multiple undefined states detected - potential crash indicator")
                    
                    # Track authentication errors
                    if "401" in str(event_data):
                        self.auth_errors.append(time.time())
                        if len(self.auth_errors) >= 2:
                            recent = list(self.auth_errors)[-2:]
                            if (recent[1] - recent[0]) < 2.0:
                                logging.warning("Rapid auth errors detected - potential crash indicator")
        
        except Exception as e:
            logging.error(f"Error processing message: {str(e)}")
    
    async def heartbeat_loop(self):
        """Maintain connection with periodic heartbeats"""
        try:
            while True:
                await asyncio.sleep(25)  # Socket.IO default heartbeat interval
                if not self.websocket or not self.connected:
                    logging.error("Cannot send heartbeat: WebSocket not connected")
                    break
                await self.websocket.send('2')  # Engine.IO ping
                logging.debug("Heartbeat sent")
        except asyncio.CancelledError:
            logging.info("Heartbeat loop cancelled")
            return
        except Exception as e:
            logging.error(f"Failed to send heartbeat: {str(e)}")
            self.connected = False

    async def send_auth(self):
        """Send Socket.IO authentication sequence"""
        try:
            if not self.websocket or not self.connected:
                logging.error("Cannot send auth: WebSocket not connected")
                return False
            
            # Engine.IO upgrade after probe response
            await self.websocket.send('5')  # Engine.IO upgrade
            await asyncio.sleep(0.1)
            
            # Send ping to maintain connection
            await self.websocket.send('2')
            await asyncio.sleep(0.1)
            
            # Auth message with credentials and timestamp
            auth_data = {
                "token": self.wallet_key,
                "publicKey": self.public_key,
                "timestamp": str(int(time.time() * 1000))
            }
            auth_message = '42' + json.dumps(["auth", auth_data])
            await self.websocket.send(auth_message)
            logging.info("Auth sequence sent")
            await asyncio.sleep(0.2)
            
            # Subscribe to crash events
            await self.websocket.send('42' + json.dumps(["subscribe", "crash"]))
            logging.info("Subscribed to crash events")
            
            return True
            
        except Exception as e:
            logging.error(f"Auth sequence failed: {str(e)}")
            self.connected = False
            return False

    async def run(self):
        """Main test loop with enhanced error handling and reconnection"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            if not await self.connect():
                logging.error(f"Connection attempt {retry_count + 1}/{max_retries} failed")
                retry_count += 1
                await asyncio.sleep(5)
                continue
                
            try:
                while True:
                    if not self.websocket:
                        logging.error("WebSocket connection lost")
                        break
                        
                    try:
                        message = await self.websocket.recv()
                        await self.handle_message(message)
                        
                        # Log statistics periodically
                        if len(self.actual_crashes) % 10 == 0:
                            avg_accuracy = sum(self.prediction_accuracy) / len(self.prediction_accuracy) \
                                         if self.prediction_accuracy else 0
                            logging.info(f"Overall prediction accuracy: {avg_accuracy:.2%}")
                            
                            # Log pattern analysis
                            if self.element_history:
                                logging.info(f"Recent element patterns: {list(self.element_history)[-3:]}")
                            if self.bodytext_history:
                                logging.info(f"Recent bodyText patterns: {list(self.bodytext_history)[-3:]}")
                            if self.undefined_sequence:
                                logging.info(f"Recent undefined states: {list(self.undefined_sequence)[-3:]}")
                            
                    except websockets.exceptions.ConnectionClosed:
                        logging.error("WebSocket connection closed")
                        break
                        
            except Exception as e:
                logging.error(f"Error in main loop: {str(e)}")
                
            finally:
                if self.websocket:
                    try:
                        await self.websocket.close()
                    except:
                        pass
                    self.websocket = None
                    
            retry_count += 1
            if retry_count < max_retries:
                logging.info(f"Attempting reconnection ({retry_count + 1}/{max_retries})...")
                await asyncio.sleep(5)
                
        logging.error("Max retries reached, exiting...")

async def main():
    test = CrashPatternTest()
    await test.run()

if __name__ == "__main__":
    asyncio.run(main())
