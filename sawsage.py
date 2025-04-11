import os
import json
import argparse
import boto3
import subprocess 
from modules import credentials_report

banner = """
         ___ _       _______                
   _____/   | |     / / ___/____ _____ ____ 
  / ___/ /| | | /| / /\__ \/ __ `/ __ `/ _ \\
 (__  ) ___ | |/ |/ /___/ / /_/ / /_/ /  __/
/____/_/  |_|__/|__//____/\__,_/\__, /\___/ 
                               /____/       
  Enumerating policies one bite at a time
       Grilled with love in Athens
            @falconforceteam
"""

def statement_parsing(statement):
    actions = statement.get('Action') or statement.get('NotAction')
    resources = statement.get('Resource') or statement.get('NotResource')
    if isinstance(actions, str):
        actions = [actions]

    if isinstance(resources, str):
        resources = [resources]

    return actions, resources

def group_enumeration(profile_name):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')

    groups_dict = {}

    response = iam_client.list_groups()
    for group in response['Groups']:
        arn = group['Arn']
        group_name = group['GroupName']
        
        groups_dict[arn] = {
            'FriendlyName': group_name,
            'AttachedPolicies': {
                'InlinePolicies': [],
                'ManagedPolicies': []
            },
            'Statements': []
        }
        
        policy_response = iam_client.list_group_policies(GroupName=group_name)
        if 'PolicyNames' in policy_response:
            groups_dict[arn]['AttachedPolicies']['InlinePolicies'] = policy_response['PolicyNames']
        
        # Get group policy documents
        for policy_name in groups_dict[arn]['AttachedPolicies']['InlinePolicies']:
            policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            statements = []
            for statement in policy_document['Statement']:
                parsed_statement = statement_parsing(statement)
                statements.append(parsed_statement)
            
            groups_dict[arn]['Statements'].extend(statements)
    
    return groups_dict

def role_enumeration(profile_name):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')

    roles_dict = {}

    response = iam_client.list_roles()
    for role in response['Roles']:
        arn = role['Arn']
        role_name = role['RoleName']
        
        roles_dict[arn] = {
            'FriendlyName': role_name,
            'AssumedBy': [],
            'MaxSessionDuration': role['MaxSessionDuration'],
            'AttachedPolicies': {
                'InlinePolicies': [],
                'ManagedPolicies': []
            },
            'Statements': []
        }
        
        assume_role_policy = role['AssumeRolePolicyDocument']
        if 'Statement' in assume_role_policy:
            for statement in assume_role_policy['Statement']:
                if statement.get('Effect') == 'Allow' and statement.get('Principal') and 'AWS' in statement['Principal']:
                    principals = statement['Principal']['AWS']
                    if isinstance(principals, list):
                        roles_dict[arn]['AssumedBy'].extend(principals)
                    else:
                        roles_dict[arn]['AssumedBy'].append(principals)
        
        # List role policies
        policy_response = iam_client.list_role_policies(RoleName=role_name)
        if 'PolicyNames' in policy_response:
            roles_dict[arn]['AttachedPolicies']['InlinePolicies'] = policy_response['PolicyNames']
        
        for policy_name in roles_dict[arn]['AttachedPolicies']['InlinePolicies']:
            policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            statements = []
            for statement in policy_document['Statement']:
                parsed_statement = statement_parsing(statement)
                statements.append(parsed_statement)
            
            roles_dict[arn]['Statements'].extend(statements)
        
        attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
        if 'AttachedPolicies' in attached_policies_response:
            managed_policies = [policy['PolicyArn'] for policy in attached_policies_response['AttachedPolicies']]
            roles_dict[arn]['AttachedPolicies']['ManagedPolicies'] = managed_policies
    
    return roles_dict

def user_enumeration(profile_name, groups_dict):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')
    users_dict = {}

    response = iam_client.list_users()
    for user in response['Users']:
        arn = user['Arn']
        user_name = user['UserName']
        
        users_dict[arn] = {
            'FriendlyName': user_name,
            'MemberOf': [],
            'AttachedPolicies': {
                'InlinePolicies': [],
                'ManagedPolicies': []
            },
            'Statements': []
        }
        
        policy_response = iam_client.list_user_policies(UserName=user_name)
        if 'PolicyNames' in policy_response:
            users_dict[arn]['AttachedPolicies']['InlinePolicies'] = policy_response['PolicyNames']
 
        for policy_name in users_dict[arn]['AttachedPolicies']['InlinePolicies']:
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            statements = []
            for statement in policy_document['Statement']:
                parsed_statement = statement_parsing(statement)
                statements.append(parsed_statement)
            
            users_dict[arn]['Statements'].extend(statements)
        
        # List groups for user
        groups_statements = []
        groups_managed_policies = []
        groups_inline_policies = []
        groups_response = iam_client.list_groups_for_user(UserName=user_name)
        if 'Groups' in groups_response:
            member_of = [group['Arn'] for group in groups_response['Groups']]
            users_dict[arn]['MemberOf'] = member_of
            
            # Fetch group policies and statements
            for group_arn in member_of:
                if group_arn in groups_dict:
                    groups_inline_policies.extend(groups_dict[group_arn]['AttachedPolicies']['InlinePolicies'])
                    groups_managed_policies.extend(groups_dict[group_arn]['AttachedPolicies']['ManagedPolicies'])
                    groups_statements.extend(groups_dict[group_arn]['Statements'])
            
            users_dict[arn]['AttachedPolicies']['InlinePolicies'].extend(groups_inline_policies)
            users_dict[arn]['AttachedPolicies']['ManagedPolicies'].extend(groups_managed_policies)
            users_dict[arn]['Statements'].extend(groups_statements)
        
        # List attached user policies (managed policies)
        attached_policies_response = iam_client.list_attached_user_policies(UserName=user_name)
        if 'AttachedPolicies' in attached_policies_response:
            managed_policies = [policy['PolicyArn'] for policy in attached_policies_response['AttachedPolicies']]
            users_dict[arn]['AttachedPolicies']['ManagedPolicies'] = managed_policies
    
    return users_dict

def principal_inlines(groups_dict, roles_dict, users_dict):
    principal_inline_dict = {}
    principal_inline_dict.update(roles_dict)
    principal_inline_dict.update(groups_dict)
    principal_inline_dict.update(users_dict)

    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)),'enumeration','policies', 'IbP')
    output_file_path = os.path.join(output_folder, 'red.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(output_file_path, 'w') as f:
        json.dump(principal_inline_dict, f, indent=4)
    print('\033[31m' + f"IAM Principals & inline policies enumerated" + '\033[0m')

    return principal_inline_dict

def fetch_policy_document(policy_arn, version_id, session):
    iam_client = session.client('iam')

    try:
        response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        policy_document = response['PolicyVersion']['Document']
        parsed_statements = []

        for statement in policy_document['Statement']:
            parsed_statement = statement_parsing(statement)
            parsed_statements.append(parsed_statement)

        return {
            'Statements': parsed_statements
        }
    except Exception as e:
        print(f"Error fetching policy document for {policy_arn}: {str(e)}")
        return None

def list_managed_policies(profile_name):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')
    managed_policies = {}

    response = iam_client.list_policies(Scope='All')
    for policy in response['Policies']:
        arn = policy['Arn']
        if policy['IsAttachable'] and not policy['Path'].startswith('/aws-service'):
            managed_policies[arn] = policy['DefaultVersionId']
    
    # Fetch policy documents for managed policies
    managed_policy_document_dict = {}
    for policy_arn, version_id in managed_policies.items():
        policy_document = fetch_policy_document(policy_arn, version_id, session)
        if policy_document:
            managed_policy_document_dict[policy_arn] = policy_document

    # Save managed_policy_document_dict into orange.json
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'enumeration','policies', 'IbP')
    output_file_path = os.path.join(output_folder, 'orange.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(output_file_path, 'w') as f:
        json.dump(managed_policy_document_dict, f, indent=4)
    print('\033[38;5;208m' + f'Managed policies enumerated' + '\033[0m')
    
    return managed_policy_document_dict

def fetch_account_id(profile_name):
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts')

    try:
        response = sts_client.get_caller_identity()
        return response['Account']
    except Exception as e:
        print(f"Error fetching account ID: {str(e)}")
        return None

def identity_policies(principal_inline_dict, managed_policy_document_dict):
    ibp_arn_dict = principal_inline_dict.copy()

    for arn, policies in ibp_arn_dict.items():
        for managed_policy_arn in policies['AttachedPolicies']['ManagedPolicies']:
            if managed_policy_arn in managed_policy_document_dict:
                statements = managed_policy_document_dict[managed_policy_arn]['Statements']
                ibp_arn_dict[arn]['Statements'].extend(statements)


    # Save managed_policy_document_dict into identity_based_policies.json
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'enumeration', 'policies', 'IbP')
    output_file_path = os.path.join(output_folder, 'identity_based_policies.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(output_file_path, 'w') as f:
        json.dump(ibp_arn_dict, f, indent=4)
    print("[+] Identity-based policies saved")
    
    return ibp_arn_dict

def resource_enumeration(profile, regions=None):
    services_folder = os.path.join(os.path.dirname(__file__), "modules", "services")
    if not os.path.isdir(services_folder):
        print("Error: The services folder does not exist.")
        return

    files = os.listdir(services_folder)
    python_files = [file for file in files if file.endswith(".py")]

    # List of modules that require --region
    region_aware_modules = ['sqs.py', 'sns.py']

    for file in python_files:
        script_path = os.path.join(services_folder, file)
        args = ["python3", script_path, "--profile", profile]
        if regions and file in region_aware_modules:
            args += ["--regions", ",".join(regions)]
        subprocess.run(args)

def canonical_rbp():
    rbp_arn_dict = {}
    rbp_folder = os.path.join(os.path.dirname(__file__), 'enumeration','policies','RbP')

    if not os.path.exists(rbp_folder):
        print(f"[*] The RBP folder does not exist: {rbp_folder}")
        return {}

    for filename in os.listdir(rbp_folder):
        if filename.endswith('.json'):
            file_path = os.path.join(rbp_folder, filename)

            with open(file_path, 'r') as file:
                try:
                    data = json.load(file)

                    for arn, details in data.items():
                        if isinstance(details, list):
                            # Special handling for SQS
                            for item in details:
                                statements = []
                                queue_url = item.get("QueueUrl", None)
                                name = item.get("Name", None)

                                if 'Policy' in item and isinstance(item['Policy'], dict):
                                    statements.extend(item['Policy'].get("Statement", []))
                                if 'Policies' in item and isinstance(item['Policies'], dict):
                                    for _, policy in item['Policies'].items():
                                        if isinstance(policy, dict):
                                            statements.extend(policy.get("Statement", []))


                                if statements:
                                    rbp_arn_dict[arn] = {
                                        "Statements": statements
                                    }
                                    if queue_url:
                                        rbp_arn_dict[arn]["QueueUrl"] = queue_url
                                    if name:
                                        rbp_arn_dict[arn]["Name"] = name
                        elif isinstance(details, dict):
                            statements = []

                            if 'Policy' in details and isinstance(details['Policy'], dict):
                                statements.extend(details['Policy'].get("Statement", []))
                            if 'Policies' in details and isinstance(details['Policies'], dict):
                                for _, policy in details['Policies'].items():
                                    if isinstance(policy, dict):
                                        statements.extend(policy.get("Statement", []))

                            if statements:
                                rbp_arn_dict[arn] = {
                                    "Statements": statements
                                }
                        else:
                            print(f"[!] Skipping {filename} for ARN {arn}: Unexpected data structure.")

                except json.JSONDecodeError:
                    print(f"[!] Error decoding JSON in file: {file_path}")
                except KeyError as e:
                    print(f"[!] Missing key in the JSON structure of file {file_path}: {e}")

    # Move wildcard "*" statements to all ARNs and remove it
    if '*' in rbp_arn_dict:
        wildcard_statements = rbp_arn_dict['*']['Statements']
        for arn in rbp_arn_dict:
            if arn != '*':
                rbp_arn_dict[arn]['Statements'].extend(wildcard_statements)
        del rbp_arn_dict['*']

    output_folder = os.path.join(os.path.dirname(__file__), 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'resource_based_policies.json')

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    with open(output_file_path, 'w') as f:
        json.dump(rbp_arn_dict, f, indent=4)

    print(f"[+] Resource-based policies saved")
    
    return rbp_arn_dict

def merge_policies(ibp_arn_dict, rbp_arn_dict):
    for principal_key, rbp_details in rbp_arn_dict.items():
        if principal_key in ibp_arn_dict:
            ibp_arn_dict[principal_key]['Statements'].extend(rbp_details['Statements'])
        else:
            # If the key is not in ibp_arn_dict, create a new entry with Statements from rbp_arn_dict
            ibp_arn_dict[principal_key] = {'Statements': rbp_details['Statements']}
    
    # Check if "*" is a primary key
    if '*' in ibp_arn_dict:
        wildcard_statements = ibp_arn_dict['*']['Statements']
        for arn, details in ibp_arn_dict.items():
            if arn != '*':
                details['Statements'].extend(wildcard_statements)
        # Remove "*" from the dictionary
        del ibp_arn_dict['*']
    
    # Sort the primary keys (ARNs) of ibp_arn_dict
    sorted_arns = sorted(ibp_arn_dict.keys())
    sorted_ibp_arn_dict = {arn: ibp_arn_dict[arn] for arn in sorted_arns}
    
    # Save sorted_ibp_arn_dict to JSON file
    output_folder = os.path.join(os.path.dirname(__file__))
    output_file_path = os.path.join(output_folder, 'enumeration','sawsage.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(output_file_path, 'w') as f:
        json.dump(sorted_ibp_arn_dict, f, indent=4)

    print(f"[*] Enumeration results exported to {output_file_path}")
    
    return sorted_ibp_arn_dict

def main(profile_name, regions, run_cr):
    print(banner)

    os.makedirs('enumeration/policies', exist_ok=True)
    session = boto3.Session(profile_name=profile_name)

    # Enumerate principals
    groups_dict = group_enumeration(profile_name)
    roles_dict = role_enumeration(profile_name)
    users_dict = user_enumeration(profile_name, groups_dict)

    # Save inline policies
    principal_inline_dict = principal_inlines(groups_dict, roles_dict, users_dict)

    # Save managed policies
    managed_policy_document_dict = list_managed_policies(profile_name)

    if any(['account_id' in f.__code__.co_varnames for f in [resource_enumeration]]):
        account_id = fetch_account_id(profile_name)
        if account_id:
            print(f"Fetched AWS Account ID: {account_id}")
        else:
            print("Failed to fetch AWS Account ID.")

    # Consolidate red and orange into IbP
    ibp_arn_dict = identity_policies(principal_inline_dict, managed_policy_document_dict)

    # Enumerate services
    resource_enumeration(profile_name, regions)

    # Consolidate and canonicalize RbP
    rbp_arn_dict = canonical_rbp()

    # Merge policies into sawsage.json for later use in kantina.py
    sawsage_dict = merge_policies(ibp_arn_dict, rbp_arn_dict)

    if run_cr:
        credentials_report.save_credential_report(profile_name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AWS IAM and Resource Enumeration')
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--regions', default=None, nargs='+', help='AWS regions to enumerate resources. Separate with comma')
    parser.add_argument('--cr', action='store_true', help='Get IAM credential report')
    args = parser.parse_args()
    main(args.profile, args.regions, args.cr)