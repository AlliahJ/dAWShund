import argparse
import boto3
import json
import os
from botocore.config import Config

def get_dynamodb_tables(profile, regions):
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    dynamodb = session.client('dynamodb',config=config)

    dynamodb_tables = {}

    for region in regions:
        try:
            tables_response = dynamodb.list_tables()
            table_names = tables_response['TableNames']

            for table_name in table_names:
                try:
                    table_description = dynamodb.describe_table(TableName=table_name)
                    table_arn = table_description['Table']['TableArn']
                    resource_policy = dynamodb.get_resource_policy(TableName=table_name)

                    dynamodb_tables[table_arn] = {
                        'response': table_description,
                        'region': region,
                        'resource_policy': resource_policy
                    }
                except Exception as e:
                    print(f"Error processing table {table_name}: {e}")
        except Exception as e:
            print(f"Error listing tables in {region}: {e}")

    return dynamodb_tables

def main():
    parser = argparse.ArgumentParser(description='Fetch DynamoDB tables and their resource policies')
    parser.add_argument('--profile', type=str, required=True, help='AWS profile name')
    parser.add_argument('--regions', type=str, default=None, help='Comma separated list of regions')

    args = parser.parse_args()

    regions = args.regions.split(',') if args.regions else boto3.Session().get_available_regions('dynamodb')

    dynamodb_tables = get_dynamodb_tables(args.profile, regions)

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration', 'policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'dynamodb.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(dynamodb_tables, f, indent=4)

    #print(f"Successfully saved DynamoDB tables and resource policies to {output_file}")
    print('\033[92m' + f'DynamoDB enumerated' + '\033[0m')

if __name__ == "__main__":
    main()
