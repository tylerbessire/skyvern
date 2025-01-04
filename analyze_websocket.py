import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import re
import subprocess
import os

def analyze_websocket_patterns():
    # Read crash data
    df = pd.read_csv("crash_data.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    # Get browser console logs by writing to a file
    with open("get_console.py", "w") as f:
        f.write('print("<get_browser_console/>")\n')
    
    # Execute the command to get console output
    with open("browser_console.txt", "w") as f:
        subprocess.run(["python3", "get_console.py"], stdout=f)
    
    # Read the console output
    with open("browser_console.txt", "r") as f:
        console_output = f.read()
    
    # Clean up temporary files
    os.remove("get_console.py")
    os.remove("browser_console.txt")
    
    # Parse console logs
    console_logs = []
    current_time = datetime.now()
    
    for line in console_output.split('\n'):
        if any(term in line.lower() for term in ["websocket", "socket", "ws:", "wss:", "401", "undefined", "crash", "multiplier"]):
            try:
                # Try to extract timestamp if present in the message
                timestamp_match = re.search(r"\[(.*?)\]", line)
                if timestamp_match:
                    timestamp_str = timestamp_match.group(1)
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                    except:
                        timestamp = current_time
                else:
                    timestamp = current_time
                
                # Determine message type
                if "websocket" in line.lower() or "ws:" in line or "wss:" in line:
                    msg_type = "websocket"
                elif "401" in line:
                    msg_type = "401"
                elif "undefined" in line:
                    msg_type = "undefined"
                elif "crash" in line.lower() or "multiplier" in line.lower():
                    msg_type = "game_state"
                else:
                    msg_type = "other"
                
                console_logs.append({
                    "timestamp": timestamp,
                    "type": msg_type,
                    "message": line.strip()
                })
            except Exception as e:
                print(f"Error parsing line: {e}")
    
    # Convert to DataFrame
    console_df = pd.DataFrame(console_logs)
    if len(console_df) == 0:
        print("No relevant console logs found")
        return
    
    # Sort by timestamp
    console_df = console_df.sort_values("timestamp")
    
    # Analyze patterns between undefined states and crashes
    print("\nAnalyzing Undefined State Patterns...")
    undefined_states = console_df[console_df["message"].str.contains("undefined", na=False)]
    crash_states = console_df[console_df["message"].str.contains("crash|0.00x", na=False)]
    
    if len(undefined_states) > 0 and len(crash_states) > 0:
        print(f"\nFound {len(undefined_states)} undefined states and {len(crash_states)} crash events")
        
        # Calculate time differences between undefined states and subsequent crashes
        for idx, undef in undefined_states.iterrows():
            next_crash = crash_states[crash_states["timestamp"] > undef["timestamp"]].iloc[0] if len(crash_states[crash_states["timestamp"] > undef["timestamp"]]) > 0 else None
            if next_crash is not None:
                time_to_crash = (next_crash["timestamp"] - undef["timestamp"]).total_seconds()
                print(f"Time from undefined state to crash: {time_to_crash:.2f}s")
                if time_to_crash < 5.0:  # Potential pattern if crash follows quickly
                    print("!!! Quick crash after undefined state detected !!!")
                    print(f"Undefined message: {undef['message']}")
                    print(f"Crash message: {next_crash['message']}")
    
    # Analyze 401 errors and their relation to game state
    auth_errors = console_df[console_df["message"].str.contains("401", na=False)]
    if len(auth_errors) > 0:
        print(f"\nFound {len(auth_errors)} authentication errors")
        for idx, error in auth_errors.iterrows():
            next_state = console_df[console_df["timestamp"] > error["timestamp"]].iloc[0] if len(console_df[console_df["timestamp"] > error["timestamp"]]) > 0 else None
            if next_state is not None:
                time_to_next = (next_state["timestamp"] - error["timestamp"]).total_seconds()
                print(f"Time from auth error to next state: {time_to_next:.2f}s")
                print(f"Next state: {next_state['message']}")
    
    # Analyze timing between console messages and crashes
    print("\nAnalyzing Console Message Patterns...")
    for idx, row in df.iterrows():
        crash_time = row["timestamp"]
        crash_value = row["crash_value"]
        
        # Find messages within 30 seconds before crash
        relevant_messages = console_df[
            (console_df["timestamp"] > crash_time - timedelta(seconds=30)) &
            (console_df["timestamp"] < crash_time)
        ]
        
        if len(relevant_messages) > 0:
            is_high_crash = crash_value > 5.0
            print(f"\nCrash at {crash_time}:")
            print(f"Crash value: {crash_value:.2f}x {'(HIGH)' if is_high_crash else ''}")
            print("Preceding messages:")
            for _, msg in relevant_messages.iterrows():
                time_diff = crash_time - msg["timestamp"]
                print(f"- {msg['type']} at {time_diff.total_seconds():.2f}s before crash: {msg['message']}")
    
    # Analyze message sequences
    print("\nAnalyzing Message Sequences...")
    console_df["time_diff"] = console_df["timestamp"].diff().dt.total_seconds()
    
    # Look for message clusters (multiple messages within 5 seconds)
    message_clusters = []
    current_cluster = []
    
    for idx, row in console_df.iterrows():
        if len(current_cluster) == 0:
            current_cluster.append(row)
        elif (row["timestamp"] - current_cluster[-1]["timestamp"]).total_seconds() < 5:
            current_cluster.append(row)
        else:
            if len(current_cluster) > 1:
                message_clusters.append(current_cluster)
            current_cluster = [row]
    
    if len(current_cluster) > 1:
        message_clusters.append(current_cluster)
    
    print(f"\nFound {len(message_clusters)} message clusters")
    
    # Analyze high crash patterns
    high_crashes = df[df["crash_value"] > 5.0]
    print(f"\nAnalyzing {len(high_crashes)} high crashes...")
    
    for idx, crash in high_crashes.iterrows():
        # Find messages before high crash
        pre_crash_messages = console_df[
            (console_df["timestamp"] > crash["timestamp"] - timedelta(seconds=60)) &
            (console_df["timestamp"] < crash["timestamp"])
        ]
        
        if len(pre_crash_messages) > 0:
            print(f"\nHigh crash ({crash['crash_value']:.2f}x) at {crash['timestamp']}:")
            print("Message sequence in last 60s:")
            for _, msg in pre_crash_messages.iterrows():
                time_diff = crash["timestamp"] - msg["timestamp"]
                print(f"- {time_diff.total_seconds():.2f}s before: {msg['type']} - {msg['message']}")

if __name__ == "__main__":
    analyze_websocket_patterns()
