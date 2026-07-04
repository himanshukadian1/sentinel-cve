import os
import base64
import requests
import sys

# List of files in the project to upload (relative to sentinel-cve folder)
PROJECT_FILES = [
    "requirements.txt",
    "main.py",
    "verify_scanner.py",
    "app/database.py",
    "app/scanner.py",
    "app/matcher.py",
    "app/updater.py",
    "app/server.py",
    "web/index.html",
    "web/style.css",
    "web/app.js",
    "README.md",
    "github_uploader.py",
    "run_upload.py"
]

def upload_project(token, repo_name, username):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # 1. Create Repository on GitHub
    repo_url = "https://api.github.com/user/repos"
    repo_data = {
        "name": repo_name,
        "description": "SentinelCVE - Premium CPE-CVE vulnerability scanner with a modern dark-mode glassmorphic dashboard.",
        "private": False,
        "auto_init": True # Initial commit with a README
    }
    
    print(f"Creating repository '{repo_name}' on GitHub...")
    response = requests.post(repo_url, json=repo_data, headers=headers)
    
    if response.status_code == 201:
        print("Success: Repository created successfully.")
    elif response.status_code == 422:
        print("Notice: Repository already exists. Attempting to upload files directly.")
    else:
        print(f"Error: Failed to create repository: HTTP {response.status_code}")
        print(response.json())
        print("Proceeding to attempt file upload anyway...")

    # 2. Upload each file
    print("\nUploading project files...")
    for rel_path in PROJECT_FILES:
        local_path = os.path.join(base_dir, rel_path)
        if not os.path.exists(local_path):
            print(f"Warning: File {rel_path} does not exist locally. Skipping.")
            continue
            
        with open(local_path, 'rb') as f:
            content_bytes = f.read()
            
        # Base64 encode the file content
        content_b64 = base64.b64encode(content_bytes).decode('utf-8')
        
        # Check if file exists in the repo to get its SHA (required for updating)
        file_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{rel_path}"
        get_resp = requests.get(file_url, headers=headers)
        
        sha = None
        if get_resp.status_code == 200:
            sha = get_resp.json().get('sha')
            
        put_data = {
            "message": f"Add/Update {rel_path} via SentinelCVE Uploader",
            "content": content_b64
        }
        if sha:
            put_data["sha"] = sha
            
        print(f" - Uploading {rel_path}...", end="", flush=True)
        put_resp = requests.put(file_url, json=put_data, headers=headers)
        
        if put_resp.status_code in [200, 201]:
            print(" Done")
        else:
            print(f" FAILED (HTTP {put_resp.status_code})")
            print(put_resp.json())
            
    print(f"\nUpload complete! View your repository here: https://github.com/{(username)}/{repo_name}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python github_uploader.py <token> <repo_name> <username>")
        sys.exit(1)
        
    token = sys.argv[1]
    repo_name = sys.argv[2]
    username = sys.argv[3]
    
    upload_project(token, repo_name, username)
