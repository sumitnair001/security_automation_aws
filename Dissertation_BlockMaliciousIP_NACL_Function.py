import boto3
import logging

# Initialize clients
ec2 = boto3.client('ec2')
sns = boto3.client('sns')  # Initialize SNS client

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Extract the malicious IP and instance ID from the event payload
    malicious_ip = event['ipAddress']
    instance_id = event['instanceId']
    vpc_id = None
    subnet_id = None
    existing_nacl_id = None

    # Define the SNS Topic ARN (replace with your actual SNS Topic ARN)
    sns_topic_arn = 'arn:aws:sns:us-east-1:xxxxxxxxx:SecurityIncidentNotification'  # Replace with your SNS topic ARN

    try:
        # Log the action
        logger.info(f"Identified malicious IP: {malicious_ip} for instance {instance_id}")

        # Describe the instance to get its subnet and VPC information
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        subnet_id = instance_info['Reservations'][0]['Instances'][0]['SubnetId']
        vpc_id = instance_info['Reservations'][0]['Instances'][0]['VpcId']

        logger.info(f"Instance {instance_id} is in subnet {subnet_id} and VPC {vpc_id}")

        # Check if a NACL is already associated with the subnet
        nacls = ec2.describe_network_acls(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )

        # Check if any of the NACLs are already associated with the subnet
        for nacl in nacls['NetworkAcls']:
            for association in nacl['Associations']:
                if association['SubnetId'] == subnet_id:
                    existing_nacl_id = nacl['NetworkAclId']
                    logger.info(f"Found existing NACL {existing_nacl_id} associated with subnet {subnet_id}")
                    break
            if existing_nacl_id:
                break

        # If an existing NACL is found, reuse it; otherwise, create a new NACL
        if existing_nacl_id:
            nacl_id = existing_nacl_id
        else:
            nacl = ec2.create_network_acl(VpcId=vpc_id)
            nacl_id = nacl['NetworkAcl']['NetworkAclId']
            logger.info(f"Created new NACL with ID {nacl_id} in VPC {vpc_id}")

            # Associate the new NACL with the subnet
            ec2.associate_network_acl(
                SubnetId=subnet_id,
                NetworkAclId=nacl_id
            )
            logger.info(f"Associated NACL {nacl_id} with subnet {subnet_id}")

        # Describe the NACL to find existing rules
        nacl_info = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
        current_rules = nacl_info['NetworkAcls'][0]['Entries']

        # Find the rule that allows traffic from 0.0.0.0/0
        rule_number_for_allow_0_0_0_0 = None
        for entry in current_rules:
            if entry['CidrBlock'] == '0.0.0.0/0' and entry['RuleAction'] == 'allow':
                rule_number_for_allow_0_0_0_0 = entry['RuleNumber']
                logger.info(f"Found allow rule for 0.0.0.0/0 with rule number {rule_number_for_allow_0_0_0_0}")

        # If there's a rule allowing all traffic from 0.0.0.0/0, place the deny rule above it
        if rule_number_for_allow_0_0_0_0:
            rule_number = rule_number_for_allow_0_0_0_0 - 1
        else:
            # Otherwise, find the next available rule number starting from 100
            rule_number = 100
            existing_rule_numbers = {entry['RuleNumber'] for entry in current_rules}
            while rule_number in existing_rule_numbers:
                rule_number += 1
                if rule_number > 32766:
                    rule_number = 100  # Loop back to 100 if we exceed the max allowed rule number

        # Add the deny rule for the malicious IP above the allow rule
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number,  # Use the rule number right before the allow rule for 0.0.0.0/0
            Protocol='-1',  # "-1" means all protocols
            RuleAction='deny',  # Deny traffic
            Egress=False,  # This is for inbound traffic
            CidrBlock=f'{malicious_ip}/32'  # Ensure that only the specific IP is denied
        )

        logger.info(f"Added deny rule for IP {malicious_ip} in NACL {nacl_id} using rule number {rule_number}")

        # Prepare the notification message
        notification_message = (
            f"Security Alert: The malicious IP {malicious_ip} has been blocked at the NACL level in subnet {subnet_id}. "
            f"The NACL {nacl_id} has been updated with a deny rule."
        )

        # Send an SNS notification to the security team
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=notification_message,
            Subject=f"Security Alert: Malicious IP {malicious_ip} Blocked in NACL {nacl_id}"
        )

        logger.info(f"Notification sent to security team for blocking IP {malicious_ip} in NACL {nacl_id}")

        return {
            'statusCode': 200,
            'body': f'Successfully blocked IP {malicious_ip} by using NACL {nacl_id} in subnet {subnet_id} with rule number {rule_number}, and notified the security team.'
        }

    except Exception as e:
        logger.error(f"Error blocking IP {malicious_ip}: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'Error blocking IP {malicious_ip}: {str(e)}'
        }
