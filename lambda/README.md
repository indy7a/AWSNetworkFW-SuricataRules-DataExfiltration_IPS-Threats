# Suricata Rule Generator Lambda

This Lambda function automatically generates and updates Suricata rules for AWS Network Firewall to protect against data exfiltration (DLP) and common intrusion threats.

## Features

- **DLP Protection**: Detects and prevents sensitive data exfiltration
  - Credit card numbers
  - Social Security Numbers
  - Sensitive keywords in HTTP requests
  - Large data transfers on non-standard ports
  - Base64 encoded data exfiltration

- **Intrusion Prevention**: Protects against common attack vectors
  - SQL injection attempts
  - Cross-site scripting (XSS)
  - Command injection
  - Path traversal
  - Malware and C2 traffic detection
  - DNS tunneling
  - Protocol anomalies
  - Brute force attempts
  - Port scanning

## Configuration

The Lambda function can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `RULE_GROUP_NAME` | Name of the Network Firewall rule group | `suricata-managed-rules` |
| `RULE_GROUP_CAPACITY` | Capacity of the rule group | `1000` |
| `UPDATE_FIREWALL` | Whether to update the firewall | `false` |
| `ORGANIZATION_DOMAINS` | Comma-separated list of organization domains | `example.com,example.org` |
| `SENSITIVE_KEYWORDS` | Comma-separated list of sensitive keywords | `confidential,secret,restricted` |
| `FIREWALL_POLICY_ARN` | ARN of the firewall policy to update | `` |
| `DLP_SID_START` | Starting SID for DLP rules | `1000000` |
| `IPS_SID_START` | Starting SID for IPS rules | `2000000` |

## Local Rule Generation

To generate rules locally without AWS dependencies:

```bash
python3 generate_rules.py
```

This will create a file named `generated_suricata_rules.rules` with all the Suricata rules.

## Deployment

### Prerequisites

- AWS CLI configured with appropriate permissions
- AWS Network Firewall deployed in your VPC

### Deployment Steps

1. Package the Lambda function:
   ```bash
   pip install -r requirements.txt -t .
   zip -r suricata_rule_generator.zip .
   ```

2. Create the Lambda function:
   ```bash
   aws lambda create-function \
     --function-name suricata-rule-generator \
     --runtime python3.9 \
     --handler suricata_rule_generator.lambda_handler \
     --zip-file fileb://suricata_rule_generator.zip \
     --role arn:aws:iam::<account-id>:role/lambda-network-firewall-role
   ```

3. Set up environment variables:
   ```bash
   aws lambda update-function-configuration \
     --function-name suricata-rule-generator \
     --environment "Variables={RULE_GROUP_NAME=suricata-managed-rules,UPDATE_FIREWALL=true,FIREWALL_POLICY_ARN=arn:aws:network-firewall:<region>:<account-id>:firewall-policy/<policy-name>}"
   ```

4. Set up a scheduled trigger (optional):
   ```bash
   aws events put-rule \
     --name daily-suricata-rule-update \
     --schedule-expression "rate(1 day)"
   
   aws events put-targets \
     --rule daily-suricata-rule-update \
     --targets "Id"="1","Arn"="arn:aws:lambda:<region>:<account-id>:function:suricata-rule-generator"
   ```

## Integration with AWS Network Firewall

This Lambda function can:

1. Create a new stateful rule group with generated Suricata rules
2. Update an existing rule group with new rules
3. Add the rule group to a firewall policy if not already present

## IAM Permissions

The Lambda function requires the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "network-firewall:CreateRuleGroup",
        "network-firewall:UpdateRuleGroup",
        "network-firewall:DescribeRuleGroup",
        "network-firewall:DescribeFirewallPolicy",
        "network-firewall:UpdateFirewallPolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

## Applying Rules to HTTPS Traffic

The default rules primarily target unencrypted HTTP traffic. To apply DLP and IPS protection to encrypted HTTPS traffic, additional configuration is required:

### TLS Inspection Approaches

#### 1. Full TLS Inspection (SSL Termination)

For comprehensive inspection of encrypted traffic:

```
alert tls any any -> any any (msg:"TLS Inspection Enabled"; flow:established; tls.cert_subject; content:"example.com"; nocase; sid:3000000; rev:1;)
```

**Implementation Requirements:**
- Configure AWS Network Firewall with TLS inspection capabilities
- Deploy trusted certificates to clients
- Set up certificate management infrastructure

**AWS Implementation:**
```yaml
# CloudFormation snippet for TLS inspection configuration
TLSInspectionConfiguration:
  Type: AWS::NetworkFirewall::TLSInspectionConfiguration
  Properties:
    TLSInspectionConfigurationName: tls-inspection-config
    CertificateAuthority:
      CertificateArn: !Ref CertificateArn
```

#### 2. SNI-Based Filtering

For basic filtering without decryption:

```
alert tls any any -> any any (msg:"Suspicious TLS SNI"; flow:established,to_server; tls.sni; pcre:"/suspicious-domain\.com/i"; sid:3000001; rev:1;)
```

**Benefits:**
- No decryption required
- Preserves privacy
- Lower performance impact

**Limitations:**
- Cannot inspect encrypted payload
- Limited to domain-based filtering

#### 3. Certificate Validation

Monitor for suspicious certificates:

```
alert tls any any -> any any (msg:"Self-signed Certificate"; flow:established; tls.cert_issuer; content:!"Trusted CA"; nocase; sid:3000002; rev:1;)
```

### Implementation Architecture

To implement HTTPS inspection with AWS Network Firewall:

1. **Deployment Architecture:**
   ```
   Internet Gateway → Network Firewall (TLS Inspection) → Application Load Balancer → EC2/ECS
   ```

2. **AWS Service Integration:**
   - AWS Certificate Manager for certificate management
   - AWS Secrets Manager for private key storage
   - CloudWatch for monitoring inspection events

### Best Practices

1. **Privacy and Compliance:**
   - Document TLS inspection policies
   - Ensure compliance with relevant regulations (GDPR, HIPAA, etc.)
   - Consider data residency requirements

2. **Performance Considerations:**
   - TLS inspection adds processing overhead
   - Consider selective decryption for sensitive traffic only
   - Monitor Network Firewall performance metrics

3. **Security Measures:**
   - Secure private keys used for decryption
   - Implement certificate rotation policies
   - Restrict access to TLS inspection configuration

4. **Monitoring:**
   - Enable detailed logging for Network Firewall
   - Create CloudWatch alarms for critical events
   - Implement automated response for high-severity alerts

By implementing these approaches, you can extend DLP and IPS protection to encrypted HTTPS traffic while balancing security, performance, and compliance requirements.
