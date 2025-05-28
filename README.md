# AWS Network Firewall Deployment

## Overview

This project provides automated deployment of AWS Network Firewall with a comprehensive set of security rules and monitoring capabilities. It enables centralized network protection for your VPCs with minimal setup and maintenance.

![Architecture Diagram](images/aws-netfw-architecture.png)

## Key Components

- **AWS Network Firewall**: Managed network firewall service for VPC protection
- **Stateful Rule Groups**: Deep packet inspection and filtering
- **Stateless Rule Groups**: Basic packet filtering based on 5-tuple information
- **CloudWatch Logs**: Logging and monitoring of network traffic
- **CloudWatch Alarms**: Automated alerting for security events
- **Custom Dashboards**: Visualization of security metrics and events

## Features

- Centralized network security management
- Protection against common network threats
- Customizable rule sets for specific security requirements
- Automated deployment via CloudFormation
- Comprehensive logging and monitoring
- Integration with existing security tools

## Deployment

### Prerequisites

- AWS CLI installed and configured
- A VPC with at least two subnets in different Availability Zones
- Appropriate IAM permissions to create Network Firewall resources

### Deploy using CloudFormation

```bash
aws cloudformation deploy \
  --template-file templates/network-firewall.yaml \
  --stack-name aws-network-firewall \
  --parameter-overrides \
      VpcId=vpc-xxxxxxxx \
      SubnetIds=subnet-xxxxxxxx,subnet-yyyyyyyy \
  --capabilities CAPABILITY_IAM
```

### Manual Deployment

1. Open AWS CloudFormation console
2. Create new stack with `templates/network-firewall.yaml`
3. Enter required parameters
4. Create stack

## Post-Deployment Steps

1. Verify Network Firewall deployment in the AWS Console
2. Update route tables to direct traffic through the firewall endpoints
3. Test firewall rules with sample traffic
4. Subscribe to SNS topics for alerts

## Parameters

- `VpcId`: VPC where the Network Firewall will be deployed
- `SubnetIds`: Subnets for Network Firewall endpoints (at least one per AZ)
- `LogRetentionDays`: Number of days to retain logs (default: 30)
- `AlertEmail`: Email address for security alerts

## Architecture Details

The AWS Network Firewall is deployed with endpoints in multiple subnets across availability zones. Traffic is routed through these endpoints using VPC route tables. The firewall applies both stateful and stateless rules to inspect and filter traffic based on configured policies.

## Security Considerations

- Network Firewall uses least-privilege IAM permissions
- All traffic logs are encrypted at rest
- Firewall rules follow security best practices
- Regular rule updates are recommended to address new threats

## Troubleshooting

- Check CloudWatch Logs for firewall activity
- Verify route tables are correctly configured
- Ensure security groups allow necessary traffic
- Review Network Firewall rule evaluation order

## License

This solution is licensed under the MIT License. See the LICENSE file for details.
## Suricata Rules for Network Protection

This project includes a Lambda function that generates comprehensive Suricata rules for AWS Network Firewall:

- **DLP Protection**: Prevents sensitive data exfiltration
  - Credit card numbers
  - Social Security Numbers
  - Sensitive keywords
  - Large data transfers
  - Base64 encoded data

- **Intrusion Prevention**: Protects against common attacks
  - SQL injection
  - Cross-site scripting (XSS)
  - Command injection
  - Path traversal
  - Malware detection
  - DNS tunneling
  - Brute force attempts
  - Port scanning

### Applying Rules to HTTPS Traffic

For encrypted traffic protection, the following approaches are available:

1. **TLS Inspection**: Full decryption and inspection of HTTPS traffic
2. **SNI-Based Filtering**: Domain filtering without decryption
3. **Certificate Validation**: Monitoring for suspicious certificates

See the [Lambda README](lambda/README.md) for detailed implementation guidance.

### Generating Rules

To generate Suricata rules locally:

```bash
cd lambda
python3 generate_rules.py
```

This creates a `generated_suricata_rules.rules` file that can be imported into AWS Network Firewall.
