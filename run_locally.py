"""
Script to run the Suricata rule generator locally and save the output to a file
"""

import json
from suricata_rule_generator import lambda_handler, generate_dlp_rules, generate_ips_rules

def main():
    # Create a test event with configuration
    test_event = {
        'update_firewall': False,  # Don't update the actual firewall
        'sensitive_keywords': ['confidential', 'secret', 'restricted', 'internal-only', 'proprietary'],
        'organization_domains': ['example.com', 'example.org', 'example.net'],
        'dlp_sid_start': 1000000,
        'ips_sid_start': 2000000
    }
    
    # Get configuration from the event
    config = {
        'rule_group_name': 'suricata-managed-rules',
        'rule_group_capacity': 1000,
        'update_firewall': False,
        'organization_domains': test_event.get('organization_domains', ['example.com', 'example.org']),
        'sensitive_keywords': test_event.get('sensitive_keywords', ['confidential', 'secret', 'restricted']),
        'firewall_policy_arn': '',
        'dlp_sid_start': test_event.get('dlp_sid_start', 1000000),
        'ips_sid_start': test_event.get('ips_sid_start', 2000000)
    }
    
    # Generate rules
    dlp_rules = generate_dlp_rules(config)
    ips_rules = generate_ips_rules(config)
    all_rules = dlp_rules + ips_rules
    
    # Print summary
    print(f"Generated {len(dlp_rules)} DLP rules and {len(ips_rules)} IPS rules")
    
    # Save rules to file
    with open('generated_suricata_rules.rules', 'w') as f:
        f.write("# DLP (Data Loss Prevention) Rules\n")
        f.write("# ============================\n\n")
        for rule in dlp_rules:
            f.write(rule + "\n")
        
        f.write("\n\n# IPS (Intrusion Prevention System) Rules\n")
        f.write("# ====================================\n\n")
        for rule in ips_rules:
            f.write(rule + "\n")
    
    print("Rules saved to 'generated_suricata_rules.rules'")

if __name__ == "__main__":
    main()
