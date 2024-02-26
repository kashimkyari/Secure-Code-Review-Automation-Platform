import os
import logging
from github import Github
from bandit.core import manager as b_manager
from pylint import epylint as lint

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Retrieve GitHub token from secrets
github_token = os.getenv('GITHUB_TOKEN')
if not github_token:
    logger.error("GitHub token not found in secrets.")
    raise ValueError("GitHub token not found in secrets.")

# Authenticate with GitHub API
try:
    g = Github(github_token)
except Exception as e:
    logger.error(f"Failed to authenticate with GitHub API: {e}")
    raise

# Define function to scan Python code with Bandit
def run_bandit_scan(file_path):
    try:
        manager = b_manager.BanditManager()
        return manager.run([file_path])
    except Exception as e:
        logger.error(f"Error running Bandit scan: {e}")
        return []

# Define function to lint Python code with Pylint
def run_pylint_scan(file_path):
    try:
        (pylint_stdout, _) = lint.py_run(file_path, return_std=True)
        return pylint_stdout.getvalue()
    except Exception as e:
        logger.error(f"Error running Pylint scan: {e}")
        return ""

# Define function to scan GitHub repository for Python files
def scan_github_repository(repo_name):
    vulnerabilities = []
    try:
        repo = g.get_repo(repo_name)
        for file in repo.get_contents("", ref="master"):
            if file.path.endswith(".py"):
                file_content = file.decoded_content.decode('utf-8')
                file_path = f"/tmp/{file.name}"
                with open(file_path, 'w') as f:
                    f.write(file_content)
                bandit_results = run_bandit_scan(file_path)
                pylint_results = run_pylint_scan(file_path)
                vulnerabilities.append({
                    'file_name': file.name,
                    'bandit_results': bandit_results,
                    'pylint_results': pylint_results
                })
                os.remove(file_path)
    except Exception as e:
        logger.error(f"Error scanning GitHub repository: {e}")
    return vulnerabilities

# Example usage: Scan GitHub repository for vulnerabilities
repo_name = 'user/repository'
vulnerabilities = scan_github_repository(repo_name)
for vulnerability in vulnerabilities:
    print(f"File: {vulnerability['file_name']}")
    print("Bandit Results:")
    print(vulnerability['bandit_results'])
    print("Pylint Results:")
    print(vulnerability['pylint_results'])
    print("\n")
