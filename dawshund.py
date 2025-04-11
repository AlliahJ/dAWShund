import json
import re
import os
from neo4j import GraphDatabase
import argparse


doggo = """
                                    ____
         ,                        ,"0xFF`--o
        ((                       (  | ____,'  
         \\~--------------------' \_;/      
         (                          /
         /) .___________________.  )
        (( (                   (( (
         ``-'                   ``-'

                    dAWShund
      Putting a leash on naughty permissions
                @falconforceteam
"""

# Default config. Change to your existing bloodhound neo4j database
NEO4J_URI = "neo4j://localhost:7687"
NEO4J_AUTH = ("neo4j", "dawshund")
NEO4J_DATABASE_NAME = "neo4j"

def get_neo4j_session():
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        return driver.session(database=NEO4J_DATABASE_NAME)
    except Exception as e:
        print(f"[ERROR] Could not connect to Neo4j: {e}")
        exit(1)

def load_json(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Could not load JSON file {file_path}: {e}")
        exit(1)

GROUP_REGEX = re.compile(r"^arn:aws:iam::\d{12}:group/[\w+=,.@-]+$")
ROLE_REGEX = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$")
USER_REGEX = re.compile(r"^arn:aws:iam::\d{12}:user/[\w+=,.@-]+$")

def safe_serialize(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return value

def flatten_props(details):
    flat = {}
    for key, value in details.items():
        if key == "CredentialsReport" and isinstance(value, dict):
            for subkey, subvalue in value.items():
                if isinstance(subvalue, str):
                    if subvalue.lower() == "true":
                        flat[subkey] = True
                    elif subvalue.lower() == "false":
                        flat[subkey] = False
                    elif subvalue == "N/A":
                        flat[subkey] = None
                    else:
                        flat[subkey] = subvalue
                else:
                    flat[subkey] = subvalue
        else:
            flat[key] = safe_serialize(value)
    return flat

def process_iam_data(data, session):
    group_permissions = {}
    role_permissions = {}
    user_permissions = {}

    for arn, details in data.items():
        if GROUP_REGEX.match(arn):
            group_permissions[arn] = details.get("Permissions", {})
            create_group_node(session, arn, details)
        elif ROLE_REGEX.match(arn):
            role_permissions[arn] = details.get("Permissions", {})
            create_role_node(session, arn, details)
        elif USER_REGEX.match(arn):
            user_permissions[arn] = details.get("Permissions", {})
            create_user_node(session, arn, details)

    create_permission_edges(session, group_permissions, "Group")
    create_permission_edges(session, role_permissions, "Role")
    create_permission_edges(session, user_permissions, "User")
    export_data(data, group_permissions, role_permissions, user_permissions)

def create_group_node(session, arn, details):
    query = """
    MERGE (g:Group {arn: $arn})
    SET g += $props
    """
    props = flatten_props(details)
    session.run(query, arn=arn, props=props)

def create_role_node(session, arn, details):
    query = """
    MERGE (r:Role {arn: $arn})
    SET r += $props
    """
    props = flatten_props(details)
    session.run(query, arn=arn, props=props)

def create_user_node(session, arn, details):
    query = """
    MERGE (u:User {arn: $arn})
    SET u += $props
    """
    props = flatten_props(details)
    session.run(query, arn=arn, props=props)

def create_permission_edges(session, permissions, node_type):
    for arn, perms in permissions.items():
        for perm in perms.get("allowed", []):
            action, resource = perm
            if ":" in action:
                service, action_name = action.split(":", 1)
            else:
                service, action_name = "Unknown", action

            query = f"""
            MATCH (a {{arn: $arn}})
            MERGE (r:Resource {{arn: $resource}})
            MERGE (a)-[:`{action_name}` {{Service: $service}}]->(r)
            """
            session.run(query, arn=arn, service=service, resource=resource)

def export_data(data, group_permissions, role_permissions, user_permissions):
    os.makedirs("export", exist_ok=True)

    with open("export/permissions4j.json", "w") as permissions_file:
        json.dump(data, permissions_file, indent=4)

    bloodhound_data = {"nodes": [], "edges": []}  

    for arn, details in data.items():
        node_type = "Unknown"
        if GROUP_REGEX.match(arn):
            node_type = "Group"
        elif ROLE_REGEX.match(arn):
            node_type = "Role"
        elif USER_REGEX.match(arn):
            node_type = "User"

        bloodhound_data["nodes"].append({"type": node_type, "arn": arn, **details})

    for arn, perms in {**group_permissions, **role_permissions, **user_permissions}.items():
        for perm in perms.get("allowed", []):
            action, resource = perm
            bloodhound_data["edges"].append({"source": arn, "target": resource, "relationship": {"type": action.split(":")[-1], "service": action.split(":")[0]}})

    with open("export/dawshund.json", "w") as dawshund_file:
        json.dump(bloodhound_data, dawshund_file, indent=4)

    print("[+] Data saved in /export")

def main():
    print(doggo)
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="Path to IAM JSON file")
    args = parser.parse_args()

    session = get_neo4j_session()
    data = load_json(args.file)
    process_iam_data(data, session)
    print("[*] Neo4j database updated successfully.")

if __name__ == "__main__":
    main()