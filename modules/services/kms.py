import boto3
import json
import os
import argparse
from botocore.config import Config

def main(profile):
    # Set up the boto3 session with the specified profile
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    kms_client = session.client('kms',config=config)

    # Dictionary to store the keys and their policies
    keys_dict = {}

    # List all KMS keys
    keys_response = kms_client.list_keys()
    keys = keys_response['Keys']

    for key in keys:
        key_id = key['KeyId']
        key_arn = key['KeyArn']

        # Initialize dictionary for this key
        keys_dict[key_arn] = {
            'KeyId': key_id,
            'PolicyNames': [],
            'Policies': {}
        }

        # List key policies
        policies_response = kms_client.list_key_policies(KeyId=key_id)
        policy_names = policies_response['PolicyNames']
        keys_dict[key_arn]['PolicyNames'] = policy_names

        for policy_name in policy_names:
            # Get key policy
            policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName=policy_name)
            policy_json = policy_response['Policy']
            
            # Parse the JSON string and convert it to a dictionary
            try:
                policy_dict = json.loads(policy_json)
            except json.JSONDecodeError:
                policy_dict = {"error": "Policy is not valid JSON"}
            
            keys_dict[key_arn]['Policies'][policy_name] = policy_dict

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'kms.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(keys_dict, f, indent=4)

    print('\033[92m' + f'Key Management Service (KMS) enumerated' + '\033[0m')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enumerate KMS key policies')
    parser.add_argument('--profile', required=True, help='The AWS profile to use for the session')
    args = parser.parse_args()
    main(args.profile)
