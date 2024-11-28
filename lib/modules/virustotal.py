#!/usr/bin/env python3
# VirusTotal API module
##

import os
import json
import requests
from typing import Dict, Optional

API_URL = "https://www.virustotal.com/api/v3"
API_REGISTER_URL = "https://www.virustotal.com/gui/join-us"

# Available commands and their corresponding API endpoints
COMMANDS = {
    'file': {
        'endpoint': '/files',
        'params': ['hash'],
        'format': 'hash',
        'description': '(Default) Get analysis results for a file hash'
    }
}

def info():
    """Print all available VirusTotal commands and their descriptions"""
    print("\nAvailable VirusTotal commands:")
    print("------------------------")
    for cmd, info in sorted(COMMANDS.items()):
        print(f"  {cmd}")
        print(f"    Description: {info['description']}")
        print(f"    Format: {info['format']}")
        print(f"    Usage: run virustotal {cmd} <{info['params'][0]}>")
        print()

def get_api_key() -> Optional[str]:
    """Get VirusTotal API key from config file"""
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                 "etc", "apikeys.json")
        if not os.path.exists(config_path):
            print("[!] API keys file not found")
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)
            
        api_key = config.get('virustotal')
        if not api_key:
            print("[!] VirusTotal API key not found in config. Please add it to /etc/apikeys.json")
            print(f"[*] Get an API key at: {API_REGISTER_URL}")
            return None
            
        return api_key
    except Exception as e:
        print(f"[!] Error loading API key: {str(e)}")
        return None

def main(artifact: Dict) -> Optional[Dict]:
    """Query VirusTotal API for file hash information

    Args:
        artifact (Dict): The artifact dictionary containing the hash and command

    Returns:
        Dict: Updated artifact with VirusTotal data if successful, None if failed
    """
    if not artifact or 'name' not in artifact:
        print("[!] Invalid artifact")
        return None

    # Check if command is provided in artifact data
    command = artifact.get('data', {}).get('command', 'file')
    if command not in COMMANDS and command is not None:
        print(f"[!] Invalid command: {command}")
        info()
        return None

    api_key = get_api_key()
    if not api_key:
        return None

    headers = {
        'x-apikey': api_key,
        'accept': 'application/json'
    }

    try:
        # Get command details
        cmd_info = COMMANDS[command]
        endpoint = cmd_info['endpoint']
        
        # Build URL with hash
        url = f"{API_URL}{endpoint}/{artifact['name']}"
        
        # Make API request
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Initialize virustotal data if not present
        if 'data' not in artifact:
            artifact['data'] = {}
        if 'virustotal' not in artifact['data']:
            artifact['data']['virustotal'] = {}
            
        # Store the command response in its own key
        artifact['data']['virustotal'][command] = data

        print(f"[*] MODE: {command}")
        print("[+] VirusTotal lookup complete")
        print(f"Output: {json.dumps(data, indent=2)}")
        
        return artifact

    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None