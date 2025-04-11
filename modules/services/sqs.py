import os
import argparse
import boto3
import json
from botocore.exceptions import ClientError
from botocore.config import Config


def get_sqs_resource_based_policies(profile_name, regions):
    results = {}

    for region in regions:
        try:
            # Use boto3.Session to set the profile name
            custom_user_agent = "dAWShund/enumeration"
            config = Config(user_agent=custom_user_agent)
            session = boto3.Session(profile_name=profile_name, region_name=region)
            sqs_client = session.client('sqs', config=config)

            # List all SQS queues in the region
            queues = sqs_client.list_queues()
            if 'QueueUrls' in queues:
                for queue_url in queues['QueueUrls']:
                    try:
                        # Get the ARN of the queue
                        queue_attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
                        queue_arn = queue_attributes['Attributes']['QueueArn']

                        # Get the resource-based policy of the queue
                        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
                        policy = json.loads(attributes['Attributes']['Policy']) if 'Policy' in attributes['Attributes'] else {}

                        # Get the RedrivePolicy and Redrive-Allow-Policy
                        redrive_policy = json.loads(policy.get('RedrivePolicy', '{}'))
                        redrive_allow_policy = json.loads(policy.get('Redrive-Allow-Policy', '{}'))

                        # Store the results
                        if queue_arn not in results:
                            results[queue_arn] = []
                        results[queue_arn].append({
                            'Name': queue_url.split('/')[-1],
                            'QueueUrl': queue_url,
                            'Region': region,
                            'Policy': policy,
                            'RedrivePolicy': redrive_policy,
                            'Redrive-Allow-Policy': redrive_allow_policy
                        })
                    except ClientError as e:
                        continue
        except ClientError as e:
            continue
            
    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'sqs.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(results, f, indent=4)
    
    print('\033[92m' + f'SQS enumerated' + '\033[0m')

def main():
    parser = argparse.ArgumentParser(description='Retrieve SQS resource-based policies for all regions.')
    parser.add_argument('--profile', required=True, help='AWS CLI named profile for the session')
    parser.add_argument('--regions', default='', help='Comma-separated list of AWS regions (optional)')

    args = parser.parse_args()
    profile_name = args.profile
    regions = args.regions.split(',') if args.regions else boto3.Session().get_available_regions('sqs')

    # Get and save results
    results = get_sqs_resource_based_policies(profile_name, regions)

if __name__ == '__main__':
    main()
