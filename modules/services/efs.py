import boto3
import json
import os
import argparse
from datetime import datetime
from botocore.config import Config

def datetime_converter(o):
    if isinstance(o, datetime):
        return o.isoformat()
    raise TypeError(f'Object of type {o.__class__.__name__} is not JSON serializable')

def get_efs_policies(profile):
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    efs_client = session.client('efs',config=config)
    
    fs_dict = {}
    
    # Describe all EFS filesystems
    response = efs_client.describe_file_systems()
    
    for fs in response['FileSystems']:
        fs_arn = fs['FileSystemArn']
        fs_id = fs['FileSystemId']
        
        # Save the filesystem details with FileSystemArn as the primary key
        fs_dict[fs_arn] = fs
        
        # Describe the file system policy
        try:
            policy_response = efs_client.describe_file_system_policy(FileSystemId=fs_id)
            # Parse the policy JSON string into a dictionary
            policy_json = policy_response['Policy']
            policy_dict = json.loads(policy_json)
            fs_dict[fs_arn]['Policy'] = policy_dict
        except efs_client.exceptions.FileSystemPolicyNotFound:
            fs_dict[fs_arn]['Policy'] = None

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'efs.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(fs_dict, f, indent=4, default=datetime_converter)
        
    print('\033[92m' + f'Elastic File System enumerated' + '\033[0m')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Retrieve AWS EFS policies and save to a JSON file.")
    parser.add_argument('--profile', required=True, help='The AWS profile for the session.')
    
    args = parser.parse_args()
    get_efs_policies(args.profile)
