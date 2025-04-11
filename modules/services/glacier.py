import boto3
import json
import argparse
import os
from botocore.config import Config

def parse_policy_string(policy_str):
    # Parse the policy string into a Python dictionary
    try:
        return json.loads(policy_str)
    except json.JSONDecodeError:
        # Return an empty dictionary if parsing fails
        return {}

def main(profile):
    # Create a session using the provided profile
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    
    # Get the account ID using STS get-caller-identity
    sts_client = session.client('sts',config=config)
    account_id = sts_client.get_caller_identity().get('Account')

    # Create Glacier client
    client = session.client('glacier',config=config)

    # List all vaults
    response = client.list_vaults(accountId=account_id)
    vault_list = response.get('VaultList', [])
    
    glacier_vaults_dict = {}

    for vault in vault_list:
        vault_arn = vault['VaultARN']
        vault_name = vault['VaultName']
        
        # Initialize the dictionary entry for the vault
        glacier_vaults_dict[vault_arn] = vault
        
        # Get vault access policy
        try:
            access_policy_response = client.get_vault_access_policy(accountId=account_id, vaultName=vault_name)
            access_policy = access_policy_response.get('policy', {}).get('Policy', '')
            glacier_vaults_dict[vault_arn]['Policy'] = parse_policy_string(access_policy)
        except client.exceptions.ResourceNotFoundException:
            glacier_vaults_dict[vault_arn]['Policy'] = {}

        # Get vault lock policy
        try:
            lock_policy_response = client.get_vault_lock(accountId=account_id, vaultName=vault_name)
            lock_policy = lock_policy_response.get('Policy', '')
            glacier_vaults_dict[vault_arn]['LockPolicy'] = parse_policy_string(lock_policy)
        except client.exceptions.ResourceNotFoundException:
            glacier_vaults_dict[vault_arn]['LockPolicy'] = {}

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'glacier.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(glacier_vaults_dict, f, indent=4)

    print('\033[92m' + f'S3 glacier enumerated' + '\033[0m')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enumerate AWS Glacier vaults and their policies.')
    parser.add_argument('--profile', required=True, help='The AWS profile for the session')

    args = parser.parse_args()
    main(args.profile)

