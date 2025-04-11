import boto3
import argparse
import json
import os
from botocore.config import Config

def get_secrets(profile):
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    client = session.client('secretsmanager',config=config)

    # List all secrets
    secrets_response = client.list_secrets()

    secrets_dict = {}

    for secret in secrets_response['SecretList']:
        arn = secret['ARN']
        
        try:
            # Get resource policy for each secret
            policy_response = client.get_resource_policy(SecretId=arn)
            
            # Extract the policy document if available
            if 'ResourcePolicy' in policy_response:
                resource_policy = policy_response['ResourcePolicy']
                secret_details = {
                    'Policy': json.loads(resource_policy)
                }
            else:
                secret_details = {
                    'Policy': {}
                }
        except client.exceptions.ResourceNotFoundException as e:
            print(f"ResourceNotFoundException: {e}")
            secret_details = {
                'Policy': {}
            }
        except Exception as e:
            print(f"Exception: {e}")
            secret_details = {
                'Policy': {}
            }

        # Store in dictionary using ARN as key
        secrets_dict[arn] = secret_details

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'secretmanager.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(secrets_dict, f, indent=4)
    
    print('\033[92m' + f'Secrets Manager enumerated' + '\033[0m')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enumerate AWS Secrets Manager secrets and resource policies.")
    parser.add_argument("--profile", required=True, help="AWS profile to use for the session.")
    args = parser.parse_args()

    profile = args.profile

    # Get secrets and their resource policies
    secrets_dict = get_secrets(profile)
