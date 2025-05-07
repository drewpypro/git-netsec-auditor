#!/usr/bin/env python3
import os
import csv
import re
import subprocess
import requests
from git import Repo
from datetime import datetime

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BASE_DIR = "cloned_repos"
SECURITY_PATTERN = re.compile(r'aws_security_group|aws_route|gateway|subnet|prefix|endpoint|rule|elastic|load', re.IGNORECASE)
GITHUB_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def clone_or_pull(repo_name):
    """Clone or pull the repository."""
    repo_dir = os.path.join(BASE_DIR, repo_name.split("/")[-1])
    if not os.path.exists(repo_dir):
        print(f"Cloning {repo_name}...")
        Repo.clone_from(f"https://github.com/{repo_name}.git", repo_dir)
    else:
        print(f"Pulling latest from {repo_name}...")
        repo = Repo(repo_dir)
        origin = repo.remotes.origin
        origin.pull()
    return repo_dir

def get_direct_commits_to_main(repo, repo_name):
    """Get commits made directly to main without going through a PR."""
    direct_commits = []
    
    # Get the main branch
    main_branch = 'main' if 'main' in repo.heads else 'master'
    
    try:
        # Run the direct commit discovery command that worked in our tests
        cmd = f'''
        git log --no-merges {main_branch} --format="%H %an %ad %s" | 
        grep -v "$(git log --pretty=format:"%H" $(git log --merges --format="%P" | 
        grep " " | cut -d' ' -f2) 2>/dev/null)" | 
        grep -v "Merge"
        '''
        
        result = subprocess.run(cmd, shell=True, cwd=repo.working_dir, 
                              capture_output=True, text=True)
        
        # Handle potential empty results
        if not result.stdout.strip():
            print(f"No direct commits found for {repo_name}")
            return direct_commits

        direct_commits_raw = [line for line in result.stdout.strip().split('\n') if line.strip()]
        
        # Process each commit
        for line in direct_commits_raw:
            # Skip initial commits if you don't want them
            if "initial commit" in line.lower():
                continue
                
            parts = line.split(' ', 3)  # Split into hash, author, date, message
            if len(parts) >= 4:
                hash_val, author = parts[0], parts[1]
                # Date might have spaces, so need to handle differently
                date_index = line.find(author) + len(author) + 1
                message_start = line.find(parts[3])
                date_str = line[date_index:message_start].strip()
                message = parts[3] if len(parts) > 3 else ""
                
                direct_commits.append({
                    "Repo": repo_name,
                    "Link": f'=HYPERLINK("https://github.com/{repo_name}/commit/{hash_val}", "View Commit")',
                    "Hash": hash_val,
                    "User": author,
                    "Date": date_str,
                    "Message": message.replace('\n', ' | ').strip()
                })
                print(f"Found direct commit: {hash_val[:8]} - {message[:40]}...")
    except Exception as e:
        print(f"Error getting direct commits: {e}")
    
    return direct_commits

def get_security_matches(text):
    """Extract all security-related keywords that match in a text."""
    keywords = [
        'aws_security_group', 'aws_route', 'gateway', 'subnet', 
        'prefix', 'endpoint', 'rule', 'elastic', 'load'
    ]
    
    matches = []
    for keyword in keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            matches.append(keyword)
    
    return matches

def get_merge_commits_with_security_changes(repo, repo_name):
    """Get merge commits that include security-related changes."""
    security_changes = []
    
    try:
        # Get all merge commits
        merge_commits_cmd = ["git", "log", "--merges", "--format=%H"]
        merge_commits_raw = subprocess.run(merge_commits_cmd, cwd=repo.working_dir, 
                                          capture_output=True, text=True).stdout.strip().split('\n')
        
        for commit_hash in merge_commits_raw:
            if not commit_hash.strip():
                continue
                
            # Check if this commit contains security-related changes
            diff_cmd = ["git", "diff", f"{commit_hash}^1", f"{commit_hash}^2"]
            diff_output = subprocess.run(diff_cmd, cwd=repo.working_dir, 
                                        capture_output=True, text=True).stdout
            
            # Find all security-related keywords that match
            security_matches = get_security_matches(diff_output)
            
            if security_matches:
                # Get commit details
                commit_details_cmd = ["git", "log", "-1", "--format=%an %ad %s", commit_hash]
                details_raw = subprocess.run(commit_details_cmd, cwd=repo.working_dir, 
                                           capture_output=True, text=True).stdout.strip()
                
                if details_raw:
                    parts = details_raw.split(' ', 2)
                    author = parts[0]
                    date_index = details_raw.find(author) + len(author) + 1
                    message_start = details_raw.find(parts[2])
                    date_str = details_raw[date_index:message_start].strip()
                    message = parts[2] if len(parts) > 2 else ""
                    
                    # Instead of individual lines, we collect unique matching keywords
                    security_changes.append({
                        "Repo": repo_name,
                        "Link": f'=HYPERLINK("https://github.com/{repo_name}/commit/{commit_hash}", "View Commit")',
                        "Hash": commit_hash,
                        "User": author,
                        "Date": date_str,
                        "Message": message.replace('\n', ' | ').strip(),
                        "matchKeyList": "|".join(security_matches)
                    })
                    print(f"Found security merge commit: {commit_hash[:8]} - matches: {', '.join(security_matches)}")
    except Exception as e:
        print(f"Error getting security merge commits: {e}")
    
    return security_changes

def get_pr_number_from_commit(repo, commit_hash):
    """Extract PR number from a merge commit message."""
    try:
        log_cmd = ["git", "log", "-1", "--format=%s", commit_hash]
        commit_msg = subprocess.run(log_cmd, cwd=repo.working_dir, 
                                   capture_output=True, text=True).stdout.strip()
        
        # Look for PR number in format "#123"
        match = re.search(r'#(\d+)', commit_msg)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"Error extracting PR number: {e}")
    
    return None

def get_pr_approvers(repo_name, pr_number):
    """Get approvers for a PR using GitHub API."""
    approvers = []
    
    if not GITHUB_TOKEN:
        print(f"GitHub token not set. Skipping PR approval check for {repo_name}#{pr_number}.")
        return approvers
    
    try:
        # Use GitHub API to get PR reviews
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
        print(f"Checking approvers for {repo_name}#{pr_number} at URL: {url}")
        
        response = requests.get(url, headers=GITHUB_HEADERS)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            reviews = response.json()
            print(f"Found {len(reviews)} reviews")
            
            for review in reviews:
                reviewer = review.get('user', {}).get('login')
                state = review.get('state')
                print(f"Review by {reviewer}: {state}")
                
                if state == "APPROVED":
                    if reviewer:
                        approvers.append(reviewer)
        else:
            print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Error getting PR approvers: {e}")
    
    return approvers

def get_merge_commits_with_approvers(repo, repo_name):
    """Get merge commits with their PR approvers."""
    merge_approvers = []
    
    try:
        # Get all merge commits
        merge_commits_cmd = ["git", "log", "--merges", "--format=%H"]
        merge_commits_raw = subprocess.run(merge_commits_cmd, cwd=repo.working_dir, 
                                          capture_output=True, text=True).stdout.strip().split('\n')
        
        for commit_hash in merge_commits_raw:
            if not commit_hash.strip():
                continue
                
            # Get commit details
            commit_details_cmd = ["git", "log", "-1", "--format=%an %ad %s", commit_hash]
            details_raw = subprocess.run(commit_details_cmd, cwd=repo.working_dir, 
                                       capture_output=True, text=True).stdout.strip()
            
            if details_raw:
                parts = details_raw.split(' ', 2)
                author = parts[0]
                date_index = details_raw.find(author) + len(author) + 1
                message_start = details_raw.find(parts[2])
                date_str = details_raw[date_index:message_start].strip()
                message = parts[2] if len(parts) > 2 else ""
                
                # Get PR number and approvers
                pr_number = get_pr_number_from_commit(repo, commit_hash)
                approvers = []
                if pr_number:
                    approvers = get_pr_approvers(repo_name, pr_number)
                
                merge_approvers.append({
                    "Repo": repo_name,
                    "Link": f'=HYPERLINK("https://github.com/{repo_name}/commit/{commit_hash}", "View Commit")',
                    "Hash": commit_hash,
                    "User": author,
                    "Date": date_str,
                    "Message": message.replace('\n', ' | ').strip(),
                    "PR-Number": pr_number if pr_number else "N/A",
                    "Approvers": f'"{", ".join(approvers)}"' if approvers else "None"
                })
                print(f"Merge commit: {commit_hash[:8]} - PR #{pr_number} - Approvers: {', '.join(approvers) if approvers else 'None'}")
    except Exception as e:
        print(f"Error getting merge commits with approvers: {e}")
    
    return merge_approvers

def analyze_security_approval_status(security_changes, merge_approvers):
    """Analyze which security changes were approved and which weren't."""
    security_approval_status = []
    
    for sec_change in security_changes:
        # Find corresponding approver info
        approver_info = next((ma for ma in merge_approvers if ma["Hash"] == sec_change["Hash"]), None)
        
        if approver_info:
            approvers = approver_info.get("Approvers", "None")
            has_network_security_approval = "blah" in approvers.lower()
            
            security_approval_status.append({
                "Repo": sec_change["Repo"],
                "Link": sec_change["Link"],
                "Hash": sec_change["Hash"],
                "User": sec_change["User"],
                "Date": sec_change["Date"],
                "Message": sec_change["Message"],
                "SecurityChanges": sec_change["matchKeyList"],
                "Approvers": approvers,
                "HasNetworkSecurityApproval": "Yes" if has_network_security_approval else "No",
                "RequiresAttention": "No" if has_network_security_approval else "Yes"
            })
    
    return security_approval_status

def write_csv(filename, fieldnames, rows):
    """Write data to a CSV file."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def analyze_repo(repo_name):
    """Analyze a repository for all required information."""
    # Clone or pull the repository
    repo_path = clone_or_pull(repo_name)
    repo = Repo(repo_path)
    
    # Goal 1: Find direct commits to main without a PR
    direct_commits = get_direct_commits_to_main(repo, repo_name)
    
    # Goal 2: Find merge commits with security-related changes
    security_merge_commits = get_merge_commits_with_security_changes(repo, repo_name)
    
    # Goal 3: Find merge commits and their approvers
    merge_approvers = get_merge_commits_with_approvers(repo, repo_name)
    
    # Goal 4: Analyze security approval status
    security_approval_status = analyze_security_approval_status(security_merge_commits, merge_approvers)
    
    return direct_commits, security_merge_commits, merge_approvers, security_approval_status

def main():
    """Main function to analyze repositories."""
    os.makedirs(BASE_DIR, exist_ok=True)
    
    # Lists to store results from all repos
    all_direct_commits = []
    all_security_merge_commits = []
    all_merge_approvers = []
    all_security_approval_status = []
    
    # Read repositories from file
    with open("repos.txt") as f:
        repos = [line.strip() for line in f if line.strip()]
    
    # Analyze each repository
    for repo in repos:
        print(f"\n====== Analyzing {repo} ======")
        direct_commits, security_merge_commits, merge_approvers, security_approval = analyze_repo(repo)
        
        all_direct_commits.extend(direct_commits)
        all_security_merge_commits.extend(security_merge_commits)
        all_merge_approvers.extend(merge_approvers)
        all_security_approval_status.extend(security_approval)
    
    # Write results to CSV files
    write_csv("direct_commits.csv", 
              ["Repo", "Link", "Hash", "User", "Date", "Message"], 
              all_direct_commits)
    
    write_csv("security_merge_commits.csv", 
              ["Repo", "Link", "Hash", "User", "Date", "Message", "matchKeyList"], 
              all_security_merge_commits)
    
    write_csv("merge_approvers.csv", 
              ["Repo", "Link", "Hash", "User", "Date", "Message", "PR-Number", "Approvers"], 
              all_merge_approvers)
    
    write_csv("security_approval_status.csv", 
              ["Repo", "Link", "Hash", "User", "Date", "Message", "SecurityChanges", 
               "Approvers", "HasNetworkSecurityApproval", "RequiresAttention"], 
              all_security_approval_status)
    
    print("\nAnalysis complete. CSV files created:")
    print("- direct_commits.csv: All direct commits to main without PR")
    print("- security_merge_commits.csv: Merge commits with security-related changes")
    print("- merge_approvers.csv: Merge commits with their PR approvers")
    print("- security_approval_status.csv: Security changes approval status")

if __name__ == "__main__":
    main()