#!/usr/bin/env python3
"""Common utility functions for Omnibus"""

def is_btc_address(artifact: str) -> bool:
    """Check if artifact is a Bitcoin address"""
    return len(artifact) in [34, 42] and artifact[0] in ['1', '3', 'b']

def is_ip(artifact: str) -> bool:
    """Check if artifact is an IP address"""
    parts = artifact.split('.')
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_domain(artifact: str) -> bool:
    """Check if artifact is a domain name"""
    return '.' in artifact and not '@' in artifact

def is_hash(artifact: str) -> bool:
    """Check if artifact is a hash"""
    return all(c in '0123456789abcdefABCDEF' for c in artifact) and len(artifact) in [32, 40, 64]

def is_keyword(artifact: str) -> bool:
    """Check if artifact is a keyword search term"""
    return True  # All strings can be keywords

def detect_type(artifact: str) -> str:
    """Detect artifact type based on its characteristics"""
    if is_btc_address(artifact):
        return 'btc'
    elif is_ip(artifact):
        return 'ipv4'
    elif is_domain(artifact):
        return 'fqdn'
    elif is_hash(artifact):
        return 'hash'
    return 'keyword'  # Default to keyword if no other type matches
