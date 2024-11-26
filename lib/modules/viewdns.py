#!/usr/bin/env python3
##
# The OSINT Omnibus
# ViewDNS.info API module
##

import json
import os
import requests
import webbrowser
from typing import Dict, Optional

API_URL = "https://api.viewdns.info"
API_REGISTER_URL = "https://viewdns.info/api/#register"

# Available commands and their corresponding API endpoints
COMMANDS = {
    'dnslookup': {
        'endpoint': '/dnsrecord/',
        'params': ['domain'],
        'description': '(Default) Get DNS records for a domain (A, AAAA, MX, NS, SOA, TXT)'
    },
    'portscan': {
        'endpoint': '/portscan/',
        'params': ['domain'],
        'description': 'Scan common ports on a domain/IP to check for open services'
    }
}

def info():
    """Print all available ViewDNS commands and their descriptions"""
    print("\nAvailable ViewDNS.info commands:")
    print("------------------------")
    for cmd, info in sorted(COMMANDS.items()):
        print(f"  {cmd}")
        print(f"    Description: {info['description']}")
        print(f"    Usage: run viewdns {cmd} <{info['params'][0]}>")
        print()

def get_api_key() -> Optional[str]:
    """Get ViewDNS API key from config file"""
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                 "etc", "apikeys.json")
        if not os.path.exists(config_path):
            print("[!] API keys file not found")
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)
            
        api_key = config.get('viewdns')
        if not api_key:
            print("[!] ViewDNS API key not found in config. Please add it to /etc/apikeys.json")
            print(f"[*] Get an API key at: {API_REGISTER_URL}")
            if input("[?] Open registration page in browser? [Y/n]: ").lower() != 'n':
                webbrowser.open(API_REGISTER_URL)
            return None
            
        return api_key
    except Exception as e:
        print(f"[!] Error loading API key: {str(e)}")
        return None

def main(artifact: Dict) -> Optional[Dict]:
    """Query ViewDNS.info API for domain/IP information

    Args:
        artifact (Dict): The artifact dictionary containing the domain/IP and command

    Returns:
        Dict: Updated artifact with ViewDNS data if successful, None if failed
    """
    if not artifact or 'name' not in artifact:
        print("[!] Invalid artifact")
        return None

    # Check if command is provided in artifact data
    command = artifact.get('data', {}).get('command', 'dnslookup')
    if command not in COMMANDS:
        print(f"[!] Invalid command: {command}")
        print_commands()
        return None

    api_key = get_api_key()
    if not api_key:
        return None

    try:
        # Get command details
        cmd_info = COMMANDS[command]
        endpoint = cmd_info['endpoint']
        param_name = cmd_info['params'][0]  # Using first parameter as main identifier

        # Build URL with query parameters directly in the string
        url = f"{API_URL}{endpoint}?{param_name}={artifact['name']}&apikey={api_key}&output=json"
        
        # Make API request
        response = requests.get(url)
        response.raise_for_status()
        
        data = response.json()
        
        # Initialize viewdns data structure if it doesn't exist
        if 'data' not in artifact:
            artifact['data'] = {}
        if 'viewdns' not in artifact['data']:
            artifact['data']['viewdns'] = {}
            
        # Store the command response in its own key
        artifact['data']['viewdns'][command] = data

        print(f"[*] MODE: {command}")
        print("[+] ViewDNS lookup complete")
        if command == 'dnslookup':
            if 'records' in data:
                for record in data['records']:
                    print(f"  {record['type']} {record['name']} - {record['data']}")
        elif command == 'portscan':
            if 'ports' in data:
                for port in data['ports']:
                    print(f"  Port {port['number']}: {port['service']} - {port['state']}")
        
        return artifact

    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None