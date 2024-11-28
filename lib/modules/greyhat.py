#!/usr/bin/env python3
# GrayHatWarfare API module
##

import json
import requests
from typing import Dict, Optional
from urllib.parse import quote

API_URL = "https://buckets.grayhatwarfare.com/api/v2"

# Available commands and their corresponding API endpoints
COMMANDS = {
    'files': {
        'endpoint': '/files',
        'params': ['keyword'],
        'format': 'keyword',
        'description': '(Default) Search for files in public S3 buckets by keyword'
    }
}

def info():
    """Print all available GrayHatWarfare commands and their descriptions"""
    print("\nAvailable GrayHatWarfare commands:")
    print("------------------------")
    for cmd, info in sorted(COMMANDS.items()):
        print(f"  {cmd}")
        print(f"    Description: {info['description']}")
        print(f"    Format: {info['format']}")
        print(f"    Usage: run greyhat {cmd} <{info['params'][0]}>")
        print()

def get_api_key() -> Optional[str]:
    """Get GrayHatWarfare API key from config file"""
    try:
        with open('etc/apikeys.json', 'r') as f:
            keys = json.load(f)
            return keys.get('greyhat')
    except Exception as e:
        print(f"[!] Failed to get API key: {str(e)}")
        return None

def main(artifact: Dict) -> Optional[Dict]:
    """Query GrayHatWarfare API for files in public S3 buckets

    Args:
        artifact (Dict): The artifact dictionary containing the search term and command

    Returns:
        Dict: Updated artifact with GrayHatWarfare data if successful, None if failed
    """
    if not artifact or 'name' not in artifact:
        print("[!] Invalid artifact")
        return None

    # Get command from artifact data or use default
    command = artifact.get('data', {}).get('command', 'files')
    if command not in COMMANDS:
        command = 'files'

    api_key = get_api_key()
    if not api_key:
        return None

    try:
        # Get command details
        cmd_info = COMMANDS[command]
        endpoint = cmd_info['endpoint']
        
        # Build URL and parameters
        url = f"{API_URL}{endpoint}"
        
        # Query parameters
        params = {
            'keywords': artifact['name'],
            'limit': '100'
        }
        
        # Headers with Bearer token
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        
        # Make API request
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        # Initialize greyhat data if not present
        if 'data' not in artifact:
            artifact['data'] = {}
        if 'greyhat' not in artifact['data']:
            artifact['data']['greyhat'] = {}
            
        # Store the command response in its own key
        artifact['data']['greyhat'][command] = data

        print(f"[*] MODE: {command}")
        print("[+] Bucket lookup complete")
        
        print(f"[+] Output: {json.dumps(data, indent=2)}")

        return artifact

    except requests.exceptions.RequestException as e:
        if e.response.status_code == 401:
            print("[!] Unauthorized: Please verify your API key")
        elif e.response.status_code == 429:
            print("[!] Rate limit exceeded. Please try again later")
        else:
            print(f"[!] HTTP Error: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return None