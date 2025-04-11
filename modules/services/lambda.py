import boto3
import json
import os
import argparse
from botocore.config import Config

def main(profile):
    # Create a session using the specified profile
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    lambda_client = session.client('lambda',config=config)
    
    # Dictionary to hold the function details and policies
    functions_dict = {}
    
    # List all Lambda functions
    response = lambda_client.list_functions()
    functions = response['Functions']
    
    # Iterate over each function and get its policy
    for function in functions:
        function_arn = function['FunctionArn']
        functions_dict[function_arn] = function
        
        try:
            policy_response = lambda_client.get_policy(FunctionName=function_arn)
            functions_dict[function_arn]['Policy'] = json.loads(policy_response['Policy'])
        except lambda_client.exceptions.ResourceNotFoundException:
            # If there is no policy, just skip
            functions_dict[function_arn]['Policy'] = None
    
    # Define the output path
    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..','enumeration', 'policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'lambda.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(functions_dict, f, indent=4)
    
    print('\033[92m' + f'Lambda functions enumerated' + '\033[0m')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch Lambda function policies")
    parser.add_argument('--profile', required=True, help="AWS profile name")
    args = parser.parse_args()
    main(args.profile)
