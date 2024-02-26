# Secure-Code-Review-Automation-Platform

This repository contains a script to scan Python code for security vulnerabilities using Bandit and Pylint.
## Example
python main.py user/repository

This will scan the Python files in the user/repository GitHub repository for security vulnerabilities using Bandit and Pylint.

In this README.md, all instructions for installation and usage are provided. You can copy and paste this content into your repository's README.md file.


## Installation

### 1. Clone the repository:

```bash
    git clone https://github.com/kashimkyari/Secure-Code-Review-Automation-Platform.git
    pip install -r requirements.txt
    export GITHUB_TOKEN=<your_github_token>
    python main.py <github_repository>

