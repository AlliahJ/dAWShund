import os
import json
import csv

def load_json(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"{filepath} not found.")
    with open(filepath, "r") as file:
        return json.load(file)

def load_csv(filepath):
    with open(filepath, "r") as file:
        reader = csv.reader(file)
        headers = next(reader)
        return {row[1]: {headers[i]: row[i] for i in range(2, len(headers))} for row in reader}

def save_json(filepath, data):
    with open(filepath, "w") as file:
        json.dump(data, file, indent=4)

enumeration_folder = "enumeration"
sawsage_file = os.path.join(enumeration_folder, "sawsage.json")
credential_report_file = os.path.join(enumeration_folder, "credential_report.csv")

if not os.path.exists(sawsage_file):
    raise FileNotFoundError("sawsage.json is required but not found.")

sawsage_data = load_json(sawsage_file)
credential_data = load_csv(credential_report_file) if os.path.exists(credential_report_file) else {}

principals = {}
resources = {}

for arn, details in sawsage_data.items():
    if arn.startswith("arn:aws:iam:"):
        principals[arn] = details
    else:
        resources[arn] = details

canon_resource_dict = {}
for arn, details in resources.items():
    for statement in details.get("Statements", []):
        principal = statement.get("Principal", {}).get("AWS")
        if principal:
            action_resource_tuple = (
                [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"],
                [statement["Resource"]] if isinstance(statement["Resource"], str) else statement["Resource"]
                )
            if principal not in canon_resource_dict:
                canon_resource_dict[principal] = {"Statements": []}
            canon_resource_dict[principal]["Statements"].append(action_resource_tuple)

for arn, data in canon_resource_dict.items():
    if arn in principals:
        for stmt in data["Statements"]:
            if stmt not in principals[arn].setdefault("Statements", []):
                principals[arn]["Statements"].append(stmt)
    else:
        principals[arn] = data

for arn, cred_data in credential_data.items():
    if arn in principals:
        principals[arn]["CredentialsReport"] = cred_data
    else:
        principals[arn] = {"CredentialsReport": cred_data}

save_json(os.path.join(enumeration_folder, "principals.json"), principals)
save_json(os.path.join(enumeration_folder, "resources.json"), resources)
