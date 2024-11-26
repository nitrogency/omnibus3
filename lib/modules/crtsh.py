#!/usr/bin/env python3
##
# The OSINT Omnibus
# crt.sh Certificate Search module
##

import json
import requests
from typing import Dict, Optional

API_URL = "https://crt.sh"

# Available commands and their corresponding API endpoints
COMMANDS = {
    'search': {
        'endpoint': '/json',
        'params': ['domain'],
        'format': 'domain',
        'description': '(Default) Get SSL/TLS certificate history for a domain'
    }
}

def info():
    """Print all available crt.sh commands and their descriptions"""
    print("\nAvailable crt.sh commands:")
    print("------------------------")
    for cmd, info in sorted(COMMANDS.items()):
        print(f"  {cmd}")
        print(f"    Description: {info['description']}")
        print(f"    Format: {info['format']}")
        print(f"    Usage: run crtsh {cmd} <{info['params'][0]}>")
        print()

def main(artifact: Dict) -> Optional[Dict]:
    """Query crt.sh for certificate information

    Args:
        artifact (Dict): The artifact dictionary containing the domain and command

    Returns:
        Dict: Updated artifact with certificate data if successful, None if failed
    """
    if not artifact or 'name' not in artifact:
        print("[!] Invalid artifact")
        return None

    # Get command from artifact data or use default
    command = artifact.get('data', {}).get('command', 'search')
    
    # If command is invalid or from another module, use default 'search'
    if command not in COMMANDS:
        command = 'search'

    try:
        # Get command details
        cmd_info = COMMANDS[command]
        endpoint = cmd_info['endpoint']
        
        # Build URL with query parameter
        url = f"{API_URL}{endpoint}?q={artifact['name']}"
        
        # Make API request
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Initialize crtsh data if not present
        if 'data' not in artifact:
            artifact['data'] = {}
        if 'crtsh' not in artifact['data']:
            artifact['data']['crtsh'] = {}
            
        # Store the command response in its own key
        artifact['data']['crtsh'][command] = data

        print(f"[*] MODE: {command}")
        print("[+] crt.sh lookup complete")
        print(f"Output: {json.dumps(data, indent=2)}")
        
        return artifact

    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None