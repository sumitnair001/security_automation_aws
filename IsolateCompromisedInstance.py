import boto3
import logging

# Initialize EC2 client and SNS client
ec2 = boto3.client('ec2')
sns = boto3.client('sns')  # Initialize SNS client

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def IsolateCompromisedInstance(event, context):
    # Extract the instance ID from the event payload
    instance_id = event['instanceId']
    
    # Define the isolated security group (replace with your actual security group ID)
    isolated_security_group_id = 'sg-0521e703c00a4da49'  # Replace this with your isolated SG ID
    
    # Define the SNS Topic ARN (replace with your actual SNS Topic ARN)
    sns_topic_arn = 'arn:aws:sns:us-east-1:563169521797:SecurityIncidentNotification'  # Replace with your SNS topic ARN

    try:
        # Log the instance isolation attempt
        logger.info(f'Isolating instance {instance_id}')
        
        # Modify the instance's security groups to only the isolated security group
        response = ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolated_security_group_id]
        )
        
        logger.info(f'Instance {instance_id} has been successfully isolated.')

        # Prepare the notification message
        notification_message = (
            f"Security Incident: Instance {instance_id} has been isolated due to malicious activity. "
            f"Security group has been updated for isolation."
        )
        
        # Send an SNS notification to the security team
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=notification_message,
            Subject=f"Security Alert: Instance {instance_id} Isolated"
        )

        logger.info(f'Notification sent to security team for instance {instance_id}')

        return {
            'statusCode': 200,
            'body': f'Instance {instance_id} has been isolated successfully, and the security team has been notified.'
        }
    
    except Exception as e:
        logger.error(f'Error isolating instance {instance_id}: {str(e)}')
        return {
            'statusCode': 500,
            'body': f'Error isolating instance {instance_id}: {str(e)}'
        }
