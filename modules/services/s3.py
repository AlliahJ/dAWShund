import os
import argparse
import boto3
import json
from botocore.exceptions import ClientError
from botocore.config import Config

def get_s3_bucket_policies(profile_name):
    # Create an S3 client using the specified profile
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile_name)
    s3_client = session.client('s3',config=config)

    # Get a list of all S3 buckets
    buckets = s3_client.list_buckets()['Buckets']

    result_data = {}

    for bucket in buckets:
        bucket_name = bucket['Name']
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        # Get the bucket policy
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(response['Policy'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy_document = 'No Bucket Policy'
            else:
                raise

        # Get the bucket region
        bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
        region_name = bucket_location.get('LocationConstraint', 'us-east-1')

        # Collect data for the result only if the bucket has a policy
        if policy_document != 'No Bucket Policy':
            result_data[bucket_arn] = {
                'Region': region_name,
                'Policy': policy_document
            }

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 's3.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(result_data, f, indent=4)

    print('\033[92m' + f'S3 buckets enumerated' + '\033[0m')

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Retrieve and store S3 bucket policies.')
    parser.add_argument('--profile', required=True, help='AWS CLI named profile for the session')
    args = parser.parse_args()

    # Get S3 bucket policies
    get_s3_bucket_policies(args.profile)

if __name__ == "__main__":
    main()