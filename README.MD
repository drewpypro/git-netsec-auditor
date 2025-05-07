# git-netsec-auditor

# Goal
1. find and list all commits made to main without PR and output to direct_commits.csv with this schema
    - Repo,Link,Hash,User,Date,Message
2. find all merge to main commits that include commit diff with related netsec stuff;
    - MatchCriteria: ('aws_security_group|aws_route|gateway|subnet|network|prefix|endpoint|rule|elastic|load')
    - Instead of full commit content, just put in the matching keys and make a list of keys if a single commit matches multiple. 
    - Schema: Repo,Link,Hash,User,Date,Message,matchKeyList
    - File: merge_commits.csv
3. Find all merge to main commits and the approvers of each PR that prepended the merge commit.
4. Of those commits, which were made without a PR and which were made with a PR

# Notes
- find and list all commits made to main without PR
    - repo,link,hash,user,date,commit-message
    ```
    git log --no-merges main --format="%H %an %ad %s" | grep -v "$(git log --pretty=format:"%H" $(git log --merges --format="%P" | grep " " | cut -d' ' -f2))" | grep -v "Merge"
    ```
- find all merge to main commits that include commit diff with related netsec stuff; 
    - repo,link,hash,user,date,commit-message,change-diff
    ```
    git log --merges --format="%H" | while read commit; do
    # Check if this commit contains security-related terms in the diff content
    if git diff ${commit}^1 ${commit}^2 | grep -E 'aws_security_group|aws_route|gateway|subnet|network|prefix|endpoint|rule|elastic|load' > /dev/null; then
        # Get commit details
        hash=$commit
        user=$(git log -1 --format="%an" $commit)
        date=$(git log -1 --format="%ad" $commit)
        message=$(git log -1 --format="%s" $commit | sed 's/,/|/g') # Replace commas with pipe symbol for CSV
        repo=$(git remote get-url origin | sed 's/.*github.com[:\/]\(.*\)\.git/\1/')
        link="https://github.com/$repo/commit/$hash"
        
        # Get the matching diff content
        change_diff=$(git diff ${commit}^1 ${commit}^2 | grep -E 'aws_security_group|aws_route|gateway|subnet|network|prefix|endpoint|rule|elastic|load' | head -5 | tr '\n' '|' | sed 's/,/|/g')
        
        # Print in CSV format
        echo "$repo,$link,$hash,$user,$date,\"$message\",\"$change_diff\""
    fi
    done
    ```
- find all merge to main commits and the approvers of each PR that prepended the merge commit. (this is hard) 
    - repo,link,hash,user,data,commit-message,approvers
- Now that we know netsec change commits, of those commits, which were made without a PR and which were made with a PR


# drewpypro/no-pr-repo
- Commits in order
    - 1st one (62a77cf0bba5a6c651a2c7c62280a6a8bd80fcbb) is directly to main 
    - 2nd one (8581d47575cdaa7dfe0ad22c6ae05b9312b4752c) was commited to a branch (not main) 
    - 3rd one (2649a94e2677076312b1a22a4b9bbd00c2d14b52) i'm guessing this is specifically a merge commit to main? so when a PR is merged another commit is created ( i did not know that until now)
    - 4th one (a66bda26d04b0fd28da365aae1b3f3dc817794af) this is another commit but directly to main without a PR. 
- This is a commit that was merged to main without PR (special initial commit is ignored)
    ```
    a66bda26d04b0fd28da365aae1b3f3dc817794af
    ```

# drewpypro/no-stakeholder-approval
- drewpypro is platform engineer
- blah is network security
- drewpypro and blah agree on shared accountability model with respect to control owners, I want to find any PR's that were merged without proper approval on items related to network security based on a match; 
- aws_security_group|aws_route|gateway|subnet|network|prefix|endpoint|rule|elastic|load
- Commits in order
    - 63fd7cf79b463bdb4a6380038d535d1c4dc1f069 - initial main commit (don't care about this one)
    - d41bb31e2943a74392461586fb2a6ca602259f6a - commit made in a separate branch (don't care about this one)
    - c8e3c2f39796ed773fedeeb109169a9b4ff4bdf8 - merge commit that includes no match above but includes blah's approval. (doesn't match string so don't care)
    - d277879a6e95e330178c5609450453e87ec7fd62 - commit made in a separate branch (don't care about this one)
    - 0df68998cac445adfca1827c86dee255b13250fb - merge commit that includes "gateway" match in the content (not commit message) and also includes blah's approval (matches string and is approved so should be reported) 
    - ea76d845e75adc1aa0f0e673405b7f0895bff02a - commit made in separate branch (don't care about this one) 
    - 13205c5e5215f47cbc010ba1d9b11b2a64a42b15 - merge commit that includes "gateway" match in the content (not commit message) and DOES NOT include blahs' approval (matches string and no approver and really what i'm looking for)
- These are merge-commits that had network security changes
    ```
    0df68998cac445adfca1827c86dee255b13250fb
    13205c5e5215f47cbc010ba1d9b11b2a64a42b15
    ```



