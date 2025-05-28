"""
AWS Lambda function to generate Suricata rules for AWS Network Firewall
- DLP data exfiltration protection
- Comprehensive intrusion prevention

This function can be used to dynamically generate and update Suricata rules
for AWS Network Firewall based on current threats and organizational requirements.
"""

import boto3
import json
import logging
import os
import uuid
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
network_firewall = boto3.client('network-firewall')
ssm = boto3.client('ssm')

def lambda_handler(event, context):
    """
    Main Lambda handler function that generates and updates Suricata rules
    
    Parameters:
    - event: Lambda event data
    - context: Lambda context
    
    Returns:
    - Dictionary with execution results
    """
    try:
        logger.info("Starting Suricata rule generation")
        
        # Get configuration from event or environment variables
        config = get_configuration(event)
        
        # Generate rule sets
        dlp_rules = generate_dlp_rules(config)
        ips_rules = generate_ips_rules(config)
        
        # Combine all rules
        all_rules = dlp_rules + ips_rules
        
        # Update Network Firewall rule group
        if config.get('update_firewall', False):
            update_result = update_firewall_rules(config, all_rules)
            logger.info(f"Firewall update result: {update_result}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully generated Suricata rules',
                'ruleCount': len(all_rules),
                'dlpRuleCount': len(dlp_rules),
                'ipsRuleCount': len(ips_rules),
                'timestamp': datetime.now().isoformat()
            })
        }
    
    except Exception as e:
        logger.error(f"Error generating rules: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Error generating rules: {str(e)}',
                'timestamp': datetime.now().isoformat()
            })
        }

def get_configuration(event):
    """
    Get configuration from event or environment variables
    
    Parameters:
    - event: Lambda event data
    
    Returns:
    - Configuration dictionary
    """
    config = {
        'rule_group_name': os.environ.get('RULE_GROUP_NAME', 'suricata-managed-rules'),
        'rule_group_capacity': int(os.environ.get('RULE_GROUP_CAPACITY', 1000)),
        'update_firewall': os.environ.get('UPDATE_FIREWALL', 'false').lower() == 'true',
        'organization_domains': os.environ.get('ORGANIZATION_DOMAINS', 'example.com,example.org').split(','),
        'sensitive_keywords': os.environ.get('SENSITIVE_KEYWORDS', 'confidential,secret,restricted').split(','),
        'firewall_policy_arn': os.environ.get('FIREWALL_POLICY_ARN', ''),
        'dlp_sid_start': int(os.environ.get('DLP_SID_START', 1000000)),
        'ips_sid_start': int(os.environ.get('IPS_SID_START', 2000000))
    }
    
    # Override with event values if provided
    if event and isinstance(event, dict):
        for key in config:
            if key in event:
                config[key] = event[key]
    
    return config

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

def update_firewall_rules(config, rules):
    """
    Update AWS Network Firewall rule group with generated Suricata rules
    
    Parameters:
    - config: Configuration dictionary
    - rules: List of Suricata rules to apply
    
    Returns:
    - Update operation result
    """
    try:
        # Format rules as a single string with newlines
        rules_string = '\n'.join(rules)
        
        # Check if rule group exists
        try:
            response = network_firewall.describe_rule_group(
                RuleGroupName=config['rule_group_name'],
                Type='STATEFUL'
            )
            # Rule group exists, update it
            update_token = response.get('UpdateToken')
            
            response = network_firewall.update_rule_group(
                RuleGroupName=config['rule_group_name'],
                Type='STATEFUL',
                Rules=rules_string,
                UpdateToken=update_token
            )
            
            return {
                'status': 'updated',
                'rule_group_arn': response.get('RuleGroupResponse', {}).get('RuleGroupArn')
            }
            
        except network_firewall.exceptions.ResourceNotFoundException:
            # Rule group doesn't exist, create it
            response = network_firewall.create_rule_group(
                RuleGroupName=config['rule_group_name'],
                Type='STATEFUL',
                Capacity=config['rule_group_capacity'],
                Rules=rules_string,
                Description='Managed Suricata rules for DLP and IPS protection'
            )
            
            # If firewall policy ARN is provided, update the policy to reference this rule group
            if config.get('firewall_policy_arn'):
                update_firewall_policy(config, response.get('RuleGroupResponse', {}).get('RuleGroupArn'))
            
            return {
                'status': 'created',
                'rule_group_arn': response.get('RuleGroupResponse', {}).get('RuleGroupArn')
            }
    
    except Exception as e:
        logger.error(f"Error updating firewall rules: {str(e)}")
        raise e

def update_firewall_policy(config, rule_group_arn):
    """
    Update AWS Network Firewall policy to reference the rule group
    
    Parameters:
    - config: Configuration dictionary
    - rule_group_arn: ARN of the rule group to reference
    
    Returns:
    - None
    """
    try:
        # Get current policy
        response = network_firewall.describe_firewall_policy(
            FirewallPolicyArn=config['firewall_policy_arn']
        )
        
        policy = response.get('FirewallPolicy', {})
        update_token = response.get('UpdateToken')
        
        # Add rule group reference if not already present
        stateful_rule_groups = policy.get('StatefulRuleGroupReferences', [])
        
        # Check if rule group is already referenced
        rule_group_exists = False
        for group in stateful_rule_groups:
            if group.get('ResourceArn') == rule_group_arn:
                rule_group_exists = True
                break
        
        if not rule_group_exists:
            stateful_rule_groups.append({
                'ResourceArn': rule_group_arn
            })
            
            policy['StatefulRuleGroupReferences'] = stateful_rule_groups
            
            # Update policy
            network_firewall.update_firewall_policy(
                FirewallPolicyArn=config['firewall_policy_arn'],
                FirewallPolicy=policy,
                UpdateToken=update_token
            )
            
            logger.info(f"Added rule group {rule_group_arn} to firewall policy {config['firewall_policy_arn']}")
    
    except Exception as e:
        logger.error(f"Error updating firewall policy: {str(e)}")
        raise e

# Execute the function if run directly
if __name__ == "__main__":
    # Test event for local execution
    test_event = {
        'update_firewall': False  # Set to True to update the firewall when testing
    }
    
    # Simulate Lambda execution
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
