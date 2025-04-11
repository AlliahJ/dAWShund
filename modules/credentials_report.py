import os
import boto3
import time

def generate_credential_report(iam):
    iam.generate_credential_report()
    time.sleep(60)  # Wait for the report to be generated

def get_credential_report(iam):
    retries = 3
    while retries > 0:
        try:
            response = iam.get_credential_report()
            return response["Content"]
        except (iam.exceptions.CredentialReportNotPresentException, 
                iam.exceptions.CredentialReportExpiredException):
            print("[-] Credential report is not present or expired. Generating a new one.")
            generate_credential_report(iam)
        except (iam.exceptions.CredentialReportNotReadyException, 
                iam.exceptions.ServiceFailureException):
            print("[!] Credential report is not ready or there was a service failure. Retrying in 60 seconds...")
            time.sleep(60)  # Wait and retry
        retries -= 1
    print("[-] Failed to retrieve credential report after multiple attempts.")
    return None

def save_credential_report(profile_name):
    # Create the 'enumeration' folder if it doesn't exist
    os.makedirs("enumeration", exist_ok=True)

    session = boto3.Session(profile_name=profile_name)
    iam = session.client("iam")

    report_content = get_credential_report(iam)
    
    if report_content:
        file_path = os.path.join("enumeration", "credential_report.csv")
        with open(file_path, "wb") as f:
            f.write(report_content)
        print(f"[+] Credential report saved")
    else:
        print("[-] Failed to retrieve credential report.")