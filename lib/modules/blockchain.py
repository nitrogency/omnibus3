#!/usr/bin/env python3
# Blockchain.info API module
##

import requests
from typing import Dict, Optional

API_URL = "https://blockchain.info"

# Available commands and their corresponding API endpoints
COMMANDS = {
    'address': {
        'endpoint': '/rawaddr',
        'params': ['address'],
        'description': '(Default) Get information about a Bitcoin address'
    }
}

def info():
    """Print all available Blockchain.info commands and their descriptions"""
    print("\nAvailable Blockchain.info commands:")
    print("------------------------")
    for cmd, info in sorted(COMMANDS.items()):
        print(f"  {cmd}")
        print(f"    Description: {info['description']}")
        print(f"    Usage: run blockchain {cmd} <{info['params'][0]}>")
        print()

def main(artifact: Dict) -> Optional[Dict]:
    """Query Blockchain.info API for BTC address information

    Args:
        artifact (Dict): The artifact dictionary containing the BTC address and command

    Returns:
        Dict: Updated artifact with blockchain data if successful, None if failed
    """
    if not artifact or 'name' not in artifact:
        print("[!] Invalid artifact")
        return None

    # Check if command is provided in artifact data
    command = artifact.get('data', {}).get('command', 'address')
    if command not in COMMANDS:
        print(f"[!] Invalid command: {command}")
        info()
        return None

    headers = {
        'User-Agent': 'OSINT Omnibus'
    }

    try:
        # Get command details
        cmd_info = COMMANDS[command]
        endpoint = cmd_info['endpoint']
        
        # Build URL
        url = f"{API_URL}{endpoint}/{artifact['name']}"
        
        # Make API request
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Initialize blockchain data if not present
        if 'data' not in artifact:
            artifact['data'] = {}
        if 'blockchain' not in artifact['data']:
            artifact['data']['blockchain'] = {}
            
        # Store the command response in its own key
        artifact['data']['blockchain'][command] = data

        print(f"[*] MODE: {command}")
        print("[+] Blockchain.info lookup complete")
        
        # Print command-specific summary
        if command == 'address':
            total_received = data.get('total_received', 0) / 100000000
            total_sent = data.get('total_sent', 0) / 100000000
            final_balance = data.get('final_balance', 0) / 100000000
            print(f"    Total Transactions: {data.get('n_tx', 'Unknown')}")
            print(f"    Total Received: {total_received:.8f} BTC")
            print(f"    Total Sent: {total_sent:.8f} BTC")
            print(f"    Final Balance: {final_balance:.8f} BTC")
        elif command == 'balance':
            balance = data.get('final_balance', 0) / 100000000
            print(f"    Current Balance: {balance:.8f} BTC")

        return artifact

    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying blockchain.info: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None
