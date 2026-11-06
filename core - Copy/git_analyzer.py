import os
import re
from typing import Dict, List, Any, Optional

try:
    import git
except ImportError:
    git = None


def parse_diff_hunks(diff_text: str) -> List[Dict[str, Any]]:
    """
    Parses unified diff text to extract:
    - Modified line ranges (old_start, old_count, new_start, new_count)
    - Changed function/section headers (from the @@ line)
    - Added and removed lines
    """
    hunks = []
    # Unified diff hunk header: @@ -old_start,old_count +new_start,new_count @@ [optional function heading]
    hunk_regex = re.compile(r"@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@\s*(.*)")

    current_hunk = None

    for line in diff_text.splitlines():
        match = hunk_regex.match(line)
        if match:
            if current_hunk:
                hunks.append(current_hunk)

            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1
            func_heading = match.group(5).strip()

            current_hunk = {
                "old_start": old_start,
                "old_count": old_count,
                "new_start": new_start,
                "new_count": new_count,
                "function_heading": func_heading,
                "added_lines": [],
                "removed_lines": [],
                "raw_lines": [line]
            }
        elif current_hunk:
            current_hunk["raw_lines"].append(line)
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk["added_lines"].append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk["removed_lines"].append(line[1:])

    if current_hunk:
        hunks.append(current_hunk)

    return hunks


def inspect_git_repository(
    project_dir: str,
    culprit_file: Optional[str] = None,
    target_line: Optional[int] = None,
    target_function: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs deterministic Git history analysis:
    1. Identifies the current active branch.
    2. Retrieves recent repository commits (hash, author, date, message).
    3. Identifies commits that modified the specific culprit file.
    4. Extracts unified diffs and analyzes which line ranges/functions changed.
    5. Correlates changes with the runtime error location (line and function).
    6. Identifies the commit that last touched the failing line via git blame.
    7. Clearly contrasts latest commit vs. the commit that introduced the failing logic.
    """
    git_dir = os.path.join(project_dir, ".git")
    if not os.path.isdir(git_dir) or git is None:
        return {
            "has_git": False,
            "status_message": "No Git repository found in project (.git is missing). Continuing with static code analysis.",
            "current_branch": None,
            "recent_commits": [],
            "file_commits": [],
            "blame_for_target_lines": [],
            "correlated_commits": [],
            "culprit_blame_commit": None,
            "evidence_summary": "Git history unavailable."
        }

    try:
        repo = git.Repo(project_dir)
        branch_name = repo.active_branch.name if not repo.head.is_detached else "detached"

        # 1. Retrieve recent repository commits (up to 10)
        repo_commits = []
        for c in repo.iter_commits(max_count=10):
            repo_commits.append({
                "commit_hash": c.hexsha[:8],
                "full_hash": c.hexsha,
                "author": c.author.name,
                "author_email": c.author.email,
                "date": c.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                "message": c.message.strip(),
                "summary": c.summary
            })

        latest_commit = repo_commits[0] if repo_commits else None

        # 2. File-specific history and diffs
        file_commits = []
        blame_entries = []
        culprit_blame_commit = None
        correlated_commits = []

        if culprit_file:
            # Normalize culprit file relative to repo root
            clean_rel = culprit_file.replace("\\", "/").lstrip("/")
            if os.path.isabs(clean_rel):
                clean_rel = os.path.relpath(clean_rel, project_dir).replace("\\", "/")

            try:
                for c in repo.iter_commits(paths=clean_rel, max_count=10):
                    diff_text = ""
                    try:
                        if c.parents:
                            diff_text = repo.git.diff(f"{c.hexsha}~1", c.hexsha, clean_rel)
                        else:
                            diff_text = repo.git.show(c.hexsha, clean_rel)
                    except Exception:
                        diff_text = "(Diff unavailable)"

                    hunks = parse_diff_hunks(diff_text)

                    # Check if this commit modified lines around target_line or target_function
                    touches_target_line = False
                    touches_target_function = False
                    changed_functions = []

                    for h in hunks:
                        heading = h["function_heading"]
                        if heading:
                            changed_functions.append(heading)
                        if target_function and target_function.lower() in (heading.lower() + "".join(h["added_lines"]).lower()):
                            touches_target_function = True

                        if target_line is not None:
                            # Hunk covers new_start to new_start + new_count
                            if h["new_start"] <= target_line <= (h["new_start"] + max(1, h["new_count"])):
                                touches_target_line = True

                    commit_data = {
                        "commit_hash": c.hexsha[:8],
                        "full_hash": c.hexsha,
                        "author": c.author.name,
                        "date": c.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "message": c.message.strip(),
                        "summary": c.summary,
                        "diff": diff_text[:2500],
                        "hunks_count": len(hunks),
                        "changed_functions": list(set(changed_functions)),
                        "touches_target_line": touches_target_line,
                        "touches_target_function": touches_target_function
                    }

                    file_commits.append(commit_data)

                    if touches_target_line or touches_target_function:
                        correlated_commits.append(commit_data)

            except Exception as e:
                file_commits = [{"error": f"Failed to retrieve file history: {e}"}]

            # 3. Git blame for culprit lines
            try:
                blame_data = repo.blame("HEAD", clean_rel)
                current_line = 1
                target_window = range(max(1, (target_line or 1) - 3), (target_line or 1) + 4) if target_line else range(1, 20)

                for entry in blame_data:
                    b_commit = entry[0]
                    lines = entry[1]
                    for line_str in lines:
                        if current_line in target_window:
                            b_info = {
                                "line_no": current_line,
                                "commit_hash": b_commit.hexsha[:8],
                                "author": b_commit.author.name,
                                "date": b_commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                                "message": b_commit.message.strip(),
                                "code": line_str.rstrip()
                            }
                            blame_entries.append(b_info)
                            if target_line and current_line == target_line and culprit_blame_commit is None:
                                culprit_blame_commit = b_info
                        current_line += 1
            except Exception as e:
                blame_entries = [{"error": f"Git blame failed: {e}"}]

        # 4. Formulate evidence-based summary
        evidence_summary_lines = []
        if culprit_blame_commit:
            evidence_summary_lines.append(
                f"Line {culprit_blame_commit['line_no']} was last modified in commit {culprit_blame_commit['commit_hash']} "
                f"('{culprit_blame_commit['message']}') by {culprit_blame_commit['author']}."
            )
            if latest_commit and latest_commit['commit_hash'] != culprit_blame_commit['commit_hash']:
                evidence_summary_lines.append(
                    f"Notice: The latest repository commit is {latest_commit['commit_hash']} ('{latest_commit['summary']}'), "
                    f"which did NOT modify the failing line."
                )
        elif file_commits:
            evidence_summary_lines.append(
                f"Found {len(file_commits)} commits that modified '{culprit_file}'."
            )
        else:
            evidence_summary_lines.append(
                f"No commits found modifying the specified file '{culprit_file}'."
            )

        return {
            "has_git": True,
            "status_message": f"Git repository active on branch '{branch_name}' ({len(repo_commits)} recent commits found).",
            "current_branch": branch_name,
            "recent_commits": repo_commits,
            "culprit_file": culprit_file,
            "file_commits": file_commits,
            "blame_for_target_lines": blame_entries,
            "correlated_commits": correlated_commits,
            "culprit_blame_commit": culprit_blame_commit,
            "latest_commit": latest_commit,
            "evidence_summary": " ".join(evidence_summary_lines)
        }

    except Exception as e:
        return {
            "has_git": False,
            "status_message": f"Git repository detected but inspection failed: {e}",
            "current_branch": None,
            "recent_commits": [],
            "file_commits": [],
            "blame_for_target_lines": [],
            "correlated_commits": [],
            "culprit_blame_commit": None,
            "evidence_summary": f"Git inspection error: {e}"
        }
