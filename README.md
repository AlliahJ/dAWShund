[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
![Maintenance](https://img.shields.io/maintenance/yes/2025.svg?style=flat-square)
[![Twitter](https://img.shields.io/twitter/follow/falconforceteam.svg?style=social&label=Follow)](https://twitter.com/falconforceteam)

# dAWShund
<img src="docs/dAWShund-logo.png" alt="Description" width="700">

---

Perhaps the most critical component of an AWS infrastructure is the policy document describing the actions allowed or denied to a resource. IAM can become a messy kitchen as misconfigurations will introduce gaps in resource access. Gordon Ramsey shouting at you would be the least of your problems if threat actors take over your infrastructure. 

For this reason, we created dAWShund (arguably a great pun), a suite of tools to enumerate, evaluate and visualise the access conditions between different resources. Let's put a leash on naughty permissions. 

## Requirements
- Python 3.x
- AWS CLI
- Boto3
- Neo4j

Install the required dependencies by running:
```
apt install python3 aws-cli neo4j python3-neo4j
pip3 install boto3
```

Ensure you have the AWS credentials configured or set up a profile using the AWS CLI:
```
aws configure --profile your_profile_name
```

# sAWSage
Enumerate AWS IAM entities (groups, roles, and users) and resources across specified regions. The goal is to consolidate and organize Identity-Based Policies (IBPs) and Resource-Based Policies (RBPs) into a unified policy structure for easier management and auditing.

## Features
- Enumeration and consolidation of policies attached to IAM entities (groups, roles, users), including both inline and managed policies.
- Identification and canonicalization of policies associated with AWS resources across specified regions.
- Combination of Identity-based Policies (IbPs) and Resource-based Policies (RbPs) into a unified structure, ensuring comprehensive policy coverage.
- Export of Credentials Report to identify interesting metadata such as MFA, access keys.
- Export the consolidated policies into a JSON file (sawsage.json) to use it in the canteen (gerakina.py) and feed the hungry doggy (dAWShund.py).

Currently, resources for the following services are supported:
- AWS Backup
- Elastic File System (EFS)
- Key Management Service (KMS)
- AWS Lambda
- S3
- S3 Glacier
- Secrets Manager
- Simple Notification Service (SNS)
- Simple Queue Service

A complete list of the services supporting Resource-based policies is found [here]( https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html)
You are encouraged to do a pull request for a service enumerator!

## Usage
```
python sawsage.py --profile <aws_profile_name> [--region <aws_region_name>]
```
Optionally:
- specify one or more AWS regions separated by commas using the --region argument.
- download the Credentials Report using the --cr argument.

The script will save the consolidated IAM and resource policies into policies/sawsage.json.
For additional visibility the original arn and policy enumeration is saved inside the policies folders.

# Gerakina
## Script Description
Simulate the policies attached to AWS IAM principals (users, groups, roles) using the `simulate-principal-policy` API from AWS. AWS uses a flowchart [model](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-denyallow) to decide if an action is allowed or denied. The script parses the policy statements from sawsage for each of the enumerated principals and resources and simulates the policies to export the effective permissions into a new JSON file. The food is now ready to be ingested in dAWShund.

## Features
- Reads IAM principal data from a JSON file.
- Simulates IAM policies using AWS `simulate-principal-policy` API.
- Validates and adjusts action names to meet AWS API requirements.
- Outputs effective permissions (allowed, explicit deny, implicit deny) for each principal in a new JSON file.

### Usage Guide
Once the enumeration folder is created after running sawsage.py, run the script using the following command:
```
python3 gerakina.py --profile your_profile_name
```
Wait for the script to evaluate the effective permissions. This process might take a while depending on the number of ARNs and policies.

Gerakina will generate effective_permissions.json that contains the effective permissions for each ARN in JSON format.

# dAWShund
Visualise the effective permissions after running 'gerakina.py' into a Neo4j database and perform cypher queries to find the levels of access within the enumarated AWS environmnet. dAWShund specifically models AWS IAM entities (Users, Roles, and Groups) and Resources and their permissions as nodes and relationships.

After standing in the queue for so long you are now able to feed the doggy by importing the data into your Neo4j database:
```
python3 dawshund.py --file <path_to_your_json_file>
```
After running the script, the neo4j database will be updated and 2 json files will be created:
- permissions4j.json in a format to be used in neo4j browser.
- dawshund.json in a format ready to be ingested into bloodhound

# Contributing
Contributions to improve dAWShund are welcome! Feel free to fork the repository, make changes, and submit a pull request. Please follow existing code style and conventions.

# License
This project is licensed under the BSD3 License - see the LICENSE file for details.
