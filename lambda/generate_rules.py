"""
Script to generate Suricata rules without AWS dependencies
"""

import json
import os
from datetime import datetime

def generate_dlp_rules(config):
    """
    Generate Data Loss Prevention (DLP) rules to detect and prevent data exfiltration
    
    Parameters:
    - config: Configuration dictionary
    
    Returns:
    - List of Suricata DLP rules
    """
    dlp_rules = []
    sid = config['dlp_sid_start']
    
    # Common sensitive data patterns
    patterns = {
        'credit_card': r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})',
        'ssn': r'\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-]?)(?!00)\d\d\3(?!0000)\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }
    
    # Add rules for credit card data exfiltration
    dlp_rules.append(f'alert http any any -> any any (msg:"DLP - Credit Card Number Detected"; flow:established,to_server; pcre:"/{patterns["credit_card"]}/"; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    sid += 1
    
    # Add rules for SSN data exfiltration
    dlp_rules.append(f'alert http any any -> any any (msg:"DLP - Social Security Number Detected"; flow:established,to_server; pcre:"/{patterns["ssn"]}/"; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    sid += 1
    
    # Add rules for sensitive keywords in HTTP POST requests
    for keyword in config['sensitive_keywords']:
        dlp_rules.append(f'alert http any any -> any any (msg:"DLP - Sensitive Keyword: {keyword}"; flow:established,to_server; http.method:"POST"; content:"{keyword}"; nocase; classtype:data-exfiltration; sid:{sid}; rev:1;)')
        sid += 1
    
    # Add rules for detecting large data transfers to non-standard ports
    dlp_rules.append(f'alert tcp any any -> any !80 (msg:"DLP - Large Data Transfer on Non-Standard Port"; flow:established,to_server; dsize:>10000; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    sid += 1
    
    # Add rules for detecting base64 encoded data exfiltration
    dlp_rules.append(f'alert http any any -> any any (msg:"DLP - Base64 Encoded Data in Request"; flow:established,to_server; http.method:"POST"; pcre:"/[A-Za-z0-9+\/]{100,}={0,2}/"; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    sid += 1
    
    # Add rules for detecting data exfiltration to non-corporate domains
    dlp_rules.append(f'alert http any any -> !$HOME_NET any (msg:"DLP - Potential Data Exfiltration to External Domain"; flow:established,to_server; http.method:"POST"; dsize:>5000; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    sid += 1
    
    # Add rules for detecting potential data exfiltration via DNS
    dlp_rules.append(f'alert udp any any -> any 53 (msg:"DLP - Potential Data Exfiltration via DNS"; flow:to_server; dsize:>150; classtype:data-exfiltration; sid:{sid}; rev:1;)')
    
    return dlp_rules
def generate_ips_rules(config):
    """
    Generate Intrusion Prevention System (IPS) rules to protect against common threats
    
    Parameters:
    - config: Configuration dictionary
    
    Returns:
    - List of Suricata IPS rules
    """
    ips_rules = []
    sid = config['ips_sid_start']
    
    # SQL Injection protection
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - SQL Injection Attempt"; flow:established,to_server; http.uri; content:"SELECT"; nocase; pcre:"/SELECT.+(FROM|WHERE|UNION|INSERT|UPDATE|DELETE|DROP)/i"; classtype:web-application-attack; sid:{sid}; rev:1;)')
    sid += 1
    
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - SQL Injection Attempt - UNION"; flow:established,to_server; http.uri; content:"UNION"; nocase; pcre:"/UNION.+SELECT/i"; classtype:web-application-attack; sid:{sid}; rev:1;)')
    sid += 1
    
    # XSS protection
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - XSS Attempt"; flow:established,to_server; http.uri; content:"<script>"; nocase; classtype:web-application-attack; sid:{sid}; rev:1;)')
    sid += 1
    
    # Command injection protection
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - Command Injection Attempt"; flow:established,to_server; http.uri; pcre:"/[;&|`\\\'\\\\]\\s*(?:ls|cat|chmod|cd|cp|rm|mv|touch|wget|curl|bash|sh|python|perl|nc|ncat|netcat)/i"; classtype:attempted-admin; sid:{sid}; rev:1;)')
    sid += 1
    
    # Path traversal protection
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - Path Traversal Attempt"; flow:established,to_server; http.uri; content:"../"; classtype:web-application-attack; sid:{sid}; rev:1;)')
    sid += 1
    
    # Malware and C2 traffic detection
    ips_rules.append(f'alert http any any -> any any (msg:"IPS - Potential Malware User-Agent"; flow:established,to_server; http.user_agent; pcre:"/(?:bot|crawl|scan|nmap|exploit|vulnerability|attack|payloads)/i"; classtype:trojan-activity; sid:{sid}; rev:1;)')
    sid += 1
    
    # Detect potential DNS tunneling
    ips_rules.append(f'alert udp any any -> any 53 (msg:"IPS - Potential DNS Tunneling"; flow:to_server; dsize:>100; classtype:bad-unknown; sid:{sid}; rev:1;)')
    sid += 1
    
    # Detect unusual protocols on standard ports
    ips_rules.append(f'alert tcp any any -> any 80 (msg:"IPS - Non-HTTP Traffic on Port 80"; flow:established,to_server; app-layer-protocol:!http; classtype:policy-violation; sid:{sid}; rev:1;)')
    sid += 1
    
    # Detect potential SSH brute force
    ips_rules.append(f'alert tcp any any -> any 22 (msg:"IPS - Potential SSH Brute Force"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 30; classtype:attempted-admin; sid:{sid}; rev:1;)')
    sid += 1
    
    # Detect potential port scanning
    ips_rules.append(f'alert tcp any any -> any any (msg:"IPS - Potential Port Scan"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 30, seconds 60; classtype:attempted-recon; sid:{sid}; rev:1;)')
    
    return ips_rules

def main():
    # Configuration
    config = {
        'sensitive_keywords': ['confidential', 'secret', 'restricted', 'internal-only', 'proprietary'],
        'organization_domains': ['example.com', 'example.org', 'example.net'],
        'dlp_sid_start': 1000000,
        'ips_sid_start': 2000000
    }
    
    # Generate rules
    dlp_rules = generate_dlp_rules(config)
    ips_rules = generate_ips_rules(config)
    all_rules = dlp_rules + ips_rules
    
    # Print summary
    print(f"Generated {len(dlp_rules)} DLP rules and {len(ips_rules)} IPS rules")
    
    # Save rules to file
    output_file = 'generated_suricata_rules.rules'
    with open(output_file, 'w') as f:
        f.write("# DLP (Data Loss Prevention) Rules\n")
        f.write("# ============================\n\n")
        for rule in dlp_rules:
            f.write(rule + "\n")
        
        f.write("\n\n# IPS (Intrusion Prevention System) Rules\n")
        f.write("# ====================================\n\n")
        for rule in ips_rules:
            f.write(rule + "\n")
    
    print(f"Rules saved to '{output_file}'")
    
    # Return the path to the generated file
    return os.path.abspath(output_file)

if __name__ == "__main__":
    main()
