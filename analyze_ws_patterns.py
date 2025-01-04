#!/usr/bin/env python3
import json
import logging
from datetime import datetime
import statistics
import matplotlib.pyplot as plt
import numpy as np

logging.basicConfig(level=logging.INFO)

def analyze_timing_patterns(timing_file):
    """Analyze timing patterns from collected WebSocket data"""
    with open(timing_file, 'r') as f:
        data = json.load(f)
    
    crash_intervals = data['crash_intervals']
    auth_timing = data['auth_timing']
    undefined_timing = data['undefined_timing']
    
    # Analyze crash intervals
    if crash_intervals:
        avg_interval = statistics.mean(crash_intervals)
        std_dev = statistics.stdev(crash_intervals) if len(crash_intervals) > 1 else 0
        logging.info(f"Average crash interval: {avg_interval:.2f}s")
        logging.info(f"Interval standard deviation: {std_dev:.2f}s")
        
        # Look for patterns in intervals
        for i in range(len(crash_intervals) - 2):
            seq = crash_intervals[i:i+3]
            if all(abs(x - seq[0]) < 0.5 for x in seq):
                logging.warning(f"Found consistent interval pattern: {seq}")
    
    # Analyze authentication patterns
    if len(auth_timing) >= 2:
        auth_gaps = [auth_timing[i + 1] - auth_timing[i] for i in range(len(auth_timing) - 1)]
        rapid_auths = [gap for gap in auth_gaps if gap < 2.0]
        if rapid_auths:
            logging.warning(f"Found {len(rapid_auths)} rapid authentication attempts")
    
    # Analyze undefined states
    if len(undefined_timing) >= 2:
        undefined_gaps = [undefined_timing[i + 1] - undefined_timing[i] for i in range(len(undefined_timing) - 1)]
        rapid_undefined = [gap for gap in undefined_gaps if gap < 1.0]
        if rapid_undefined:
            logging.warning(f"Found {len(rapid_undefined)} rapid undefined states")
    
    # Plot patterns
    plt.figure(figsize=(12, 6))
    plt.plot(crash_intervals, label='Crash Intervals')
    plt.axhline(y=avg_interval, color='r', linestyle='--', label='Average Interval')
    plt.title('Crash Interval Pattern Analysis')
    plt.xlabel('Crash Event Index')
    plt.ylabel('Interval (seconds)')
    plt.legend()
    plt.savefig('crash_patterns.png')
    
    return {
        'avg_interval': avg_interval if crash_intervals else None,
        'std_dev': std_dev if crash_intervals else None,
        'rapid_auth_count': len(rapid_auths) if auth_timing else 0,
        'rapid_undefined_count': len(rapid_undefined) if undefined_timing else 0
    }

def analyze_message_sequences(log_file):
    """Analyze WebSocket message sequences for patterns"""
    sequences = []
    current_sequence = []
    
    with open(log_file, 'r') as f:
        for line in f:
            if 'Raw message:' in line:
                msg = line.split('Raw message:')[1].strip()
                current_sequence.append(msg)
                
                # Look for specific patterns
                if msg.startswith('42["crash.tick"'):
                    sequences.append(current_sequence[-5:])  # Last 5 messages before crash
                    current_sequence = []
    
    # Analyze common sequences
    if sequences:
        common_patterns = {}
        for seq in sequences:
            pattern = tuple(msg[:10] for msg in seq)  # First 10 chars of each message
            common_patterns[pattern] = common_patterns.get(pattern, 0) + 1
        
        # Report frequent patterns
        for pattern, count in sorted(common_patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
            if count > 1:
                logging.warning(f"Found repeated message pattern ({count} times): {pattern}")
    
    return sequences

if __name__ == "__main__":
    # Analyze timing patterns
    timing_results = analyze_timing_patterns('timing_analysis.json')
    
    # Analyze message sequences
    sequence_results = analyze_message_sequences('ws_minimal_test.log')
    
    # Save combined analysis
    with open('pattern_analysis.json', 'w') as f:
        json.dump({
            'timing_analysis': timing_results,
            'sequence_count': len(sequence_results)
        }, f, indent=2)
