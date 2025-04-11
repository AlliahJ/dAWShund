import os
import sys
import re
import json
import argparse
import boto3
from botocore.config import Config
from modules.chop import principals as principals_data

banner = """
 _   _   _____ _____ ____   ___  _   _____ _   _  ____
| | | | |  ___)  ___)  _ \ / _ \| | / (   ) \ | |/ _  \\
| |_| | | |   | |_  | |_) ) |_| | |/ / | ||  \| | |_| |
|  _  | | |   |  _) |  __/|  _  |   <  | ||     |  _  |
| | | | | |   | |___| |   | | | | |\ \ | || |\  | | | |
|_| |_| |_|   |_____)_|   |_| |_|_| \_(___)_| \_|_| |_|
              The  best canteen in town                           
     Stand in the line to evaluate your permissions
                    @falconforceteam
"""

# Create a custom configuration object
custom_user_agent = "dAWShund/evaluation"
config = Config(user_agent=custom_user_agent)

def import_chop_module():
    print(f"[*] Chopping resources and permissions")
    try:
        # Import the chop module from the /modules folder
        from modules.chop import load_json
        principals_file = os.path.join('enumeration', 'principals.json')
        if not os.path.exists(principals_file):
            print(f"Error: {principals_file} not found.")
            sys.exit(1)

        # Load the principals data from principals.json
        principals_data = load_json(principals_file)
        return principals_data

    except ImportError as e:
        print(f"Error importing chop module: {e}")
        sys.exit(1)

def flatten_actions(actions):
    """
    Flatten nested lists of actions into a single list of strings.
    """
    flat_actions = []
    for action in actions:
        if isinstance(action, list):
            flat_actions.extend(flatten_actions(action))
        else:
            flat_actions.append(action)
    return flat_actions

def validate_action_names(actions):
    """
    Validate action names to ensure each has a minimum length of 3 characters.
    """
    for action in actions:
        if isinstance(action, str) and len(action) < 3:
            return False
        elif isinstance(action, list):
            if not validate_action_names(action):
                return False
    return True

def simulate_principal_policy(profile_name, principals_data):
    print(f"[*] Initiating Actions simulation.")
   
    # Initialize boto3 session with specified profile
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam', config=config)

    # Dictionary to store effective permissions
    effective_permissions = {}

    # Process each user's IAM details
    for user_arn, details in principals_data.items():
        # root arn cannot be evaluated by simulate-principal-policy
        if re.match(r'^arn:aws:iam::\d+:root$', user_arn):
            # print(f"Skipping root user ARN: {user_arn}")
            continue
        
        statements = details.pop('Statements', [])

        # Process each statement
        for statement in statements:
            actions = statement[0]
            resources = statement[1]

            # Flatten actions into a list of action names
            action_names = flatten_actions(actions)

            # Validate action names except for * (must be 3 char long. For future historians: Apparently "*" is not considered as 3 char long)
            if not validate_action_names(action_names):
                # print(f"Invalid action names in statement for {user_arn}: {action_names}")
                continue

            # Convert resources to a list of resource ARNs
            resource_arns = []
            for resource in resources:
                if isinstance(resource, str):
                    if resource != "*":
                        resource_arns.append(resource)
                elif isinstance(resource, list):
                    flattened_resources = flatten_actions(resource)
                    resource_arns.extend(flattened_resources)

            # Simulate policy using boto3
            try:
                response = iam_client.simulate_principal_policy(
                    PolicySourceArn=user_arn,
                    ActionNames=action_names,
                    ResourceArns=resource_arns
                )

                # Extract results from response
                eval_results = response['EvaluationResults']
                for result in eval_results:
                    eval_action_name = result['EvalActionName']
                    eval_resource_name = result.get('EvalResourceName', '')

                    eval_decision = result['EvalDecision']

                    # Initialize keys in effective_permissions if not exists
                    if user_arn not in effective_permissions:
                        effective_permissions[user_arn] = {
                            'allowed': [],
                            'explicitDeny': [],
                            'implicitDeny': []
                        }

                    # Append to appropriate list based on EvalDecision
                    if eval_decision == 'allowed':
                        effective_permissions[user_arn]['allowed'].append((eval_action_name, eval_resource_name))
                    elif eval_decision == 'explicitDeny':
                        effective_permissions[user_arn]['explicitDeny'].append((eval_action_name, eval_resource_name))
                    elif eval_decision == 'implicitDeny':
                        effective_permissions[user_arn]['implicitDeny'].append((eval_action_name, eval_resource_name))

            except iam_client.exceptions.InvalidInputException as e:
                # print(f"Error simulating policy for {user_arn}: {e}")
                continue

    return effective_permissions, principals_data

def main():
    print(banner)
    parser = argparse.ArgumentParser(description='Simulate IAM policies from JSON file.')
    parser.add_argument('--profile', required=True, help='AWS profile name for session')
    args = parser.parse_args()
    profile_name = args.profile

    # Use the import_chop_module to load principals_data
    principals_data = import_chop_module()

    effective_permissions, _ = simulate_principal_policy(profile_name, principals_data)

    # Add effective permissions to the data under "Permissions"
    for user_arn, permissions in effective_permissions.items():
        principals_data[user_arn]['Permissions'] = permissions

    # Save sorted_sawsage_dict to JSON file
    output_folder = os.path.join(os.path.dirname(__file__))
    output_file_path = os.path.join(output_folder, 'effective_permissions.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(output_file_path, 'w') as f:
        json.dump(principals_data, f, indent=4)

    print(f'[*] ' + '\033[92m' + f'Order {os.getpid()} is ready for pick-up' + '\033[0m')
    print(f"[+] Effective permissions exported to {output_file_path}")

if __name__ == '__main__':
    main()