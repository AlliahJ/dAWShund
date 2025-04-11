import os
import argparse
import boto3
import json
from botocore.config import Config

def clean_policy(policy):
    # Function to clean up policy strings by removing escape characters and formatting nicely
    if isinstance(policy, str):
        return json.loads(policy.replace('\\', ''))
    else:
        return policy

def list_topics(profile, regions):
    custom_user_agent = "dAWShund/enumeration"
    config = Config(user_agent=custom_user_agent)
    session = boto3.Session(profile_name=profile)
    sns_client = session.client('sns',config=config)
    topics = []

    if regions:
        available_regions = regions.split(',')
    else:
        available_regions = session.get_available_regions('sns')

    for region in available_regions:
        try:
            response = sns_client.list_topics()
            topics.extend(response['Topics'])
        except Exception as e:
            print(f"Error listing topics in region {region}: {str(e)}")
            continue

    topic_arns = [topic['TopicArn'] for topic in topics]

    SNS_topics = {}

    for topic_arn in topic_arns:
        topic_region = topic_arn.split(':')[3]

        try:
            response = sns_client.get_topic_attributes(TopicArn=topic_arn)
            topic_attributes = response['Attributes']
        except Exception as e:
            print(f"Error getting attributes for topic {topic_arn}: {str(e)}")
            continue

        # Clean up Policy and EffectiveDeliveryPolicy values
        topic_attributes['Policy'] = clean_policy(topic_attributes.get('Policy'))
        topic_attributes['EffectiveDeliveryPolicy'] = clean_policy(topic_attributes.get('EffectiveDeliveryPolicy'))

        try:
            response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
            subscriptions = response['Subscriptions']
        except Exception as e:
            print(f"Error listing subscriptions for topic {topic_arn}: {str(e)}")
            subscriptions = []

        SNS_topics[topic_arn] = {
            'region': topic_region,
            'Policy': topic_attributes.get('Policy'),
            'attributes': {
                'EffectiveDeliveryPolicy': topic_attributes.get('EffectiveDeliveryPolicy'),
                # Exclude Policy and EffectiveDeliveryPolicy from attributes
                **{k: v for k, v in topic_attributes.items() if k not in ['Policy', 'EffectiveDeliveryPolicy']}
            },
            'subscriptions': subscriptions
        }

    # Define the path for the JSON file
    output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'enumeration','policies', 'RbP')
    output_file_path = os.path.join(output_folder, 'sns.json')

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Write the dictionary to the JSON file
    with open(output_file_path, 'w') as f:
        json.dump(SNS_topics, f, indent=4)

    print('\033[92m' + f'SNS topics enumerated' + '\033[0m')

def main():
    parser = argparse.ArgumentParser(description='List SNS topics and save their attributes and subscriptions.')
    parser.add_argument('--profile', required=True, help='AWS profile name')
    parser.add_argument('--regions', help='Comma-separated list of AWS regions')
    args = parser.parse_args()

    list_topics(args.profile, args.regions)

if __name__ == "__main__":
    main()
