import boto3
import json
import argparse
import os
from botocore.config import Config

def main(profile):
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    backup_client = session.client('backup',config=config)
    
    # Dictionary to store vault information
    vault_dict = {}
    
    # List backup vaults
    vaults = backup_client.list_backup_vaults()
    
    for vault in vaults['BackupVaultList']:
        vault_arn = vault['BackupVaultArn']
        vault_name = vault['BackupVaultName']
        
        # Initialize the vault dictionary entry
        vault_dict[vault_arn] = {
            'BackupVaultName': vault_name,
            'ProtectedResources': [],
            'RecoveryPoints': [],
            'Policy': None
        }
        
        # List protected resources by backup vault
        protected_resources = backup_client.list_protected_resources_by_backup_vault(BackupVaultName=vault_name)
        vault_dict[vault_arn]['ProtectedResources'] = protected_resources.get('Results', [])
        
        # List recovery points by backup vault
        recovery_points = backup_client.list_recovery_points_by_backup_vault(BackupVaultName=vault_name)
        vault_dict[vault_arn]['RecoveryPoints'] = recovery_points.get('RecoveryPoints', [])
        
        # Get backup vault access policy
        try:
            policy_response = backup_client.get_backup_vault_access_policy(BackupVaultName=vault_name)
            policy = policy_response.get('Policy', None)
            if policy:
                # Parse the policy JSON string
                vault_dict[vault_arn]['Policy'] = json.loads(policy)
            else:
                vault_dict[vault_arn]['Policy'] = None
        except backup_client.exceptions.ResourceNotFoundException:
            vault_dict[vault_arn]['Policy'] = None
    
    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..','enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'backup.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(vault_dict, f, indent=4)
    
    print('\033[92m' + f'AWS Backup enumerated' + '\033[0m')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AWS Backup vault enumeration script.')
    parser.add_argument('--profile', required=True, help='The AWS profile for the session')
    args = parser.parse_args()
    
    main(args.profile)
