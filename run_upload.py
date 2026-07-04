import os
import requests
import sys
from github_uploader import upload_project

def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        token = input("Enter your GitHub Personal Access Token (PAT): ").strip()
    if not token:
        print("Error: No GITHUB_TOKEN environment variable or input provided.")
        sys.exit(1)
        
    repo_name = "sentinel-cve"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    print("Fetching GitHub username using token...")
    resp = requests.get("https://api.github.com/user", headers=headers)
    if resp.status_code != 200:
        print(f"Error: Failed to fetch user info (HTTP {resp.status_code})")
        print(resp.json())
        sys.exit(1)
        
    username = resp.json().get("login")
    print(f"Authenticated as user: {username}")
    
    upload_project(token, repo_name, username)

if __name__ == "__main__":
    main()
