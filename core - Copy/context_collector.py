import os
import re
from typing import Dict, List, Any, Optional

try:
    import git
except ImportError:
    git = None


def parse_stack_trace(trace_text: str) -> Dict[str, Any]:
    """
    Parses a multiline Python stack trace or runtime error.
    Extracts exception type, message, and execution frames.
    Handles Windows and Linux paths, paths with spaces, and partial/malformed inputs.
    """
    if not trace_text or not trace_text.strip():
        return {
            "traceback_parsed": False,
            "has_frames": False,
            "exception_type": "UnknownError",
            "exception_message": "",
            "frames": [],
            "raw_trace": ""
        }

    lines = [line.strip() for line in trace_text.strip().splitlines() if line.strip()]
    frames = []
    exception_type = "UnknownError"
    exception_message = ""

    # Regex for standard Python traceback frame: File "...", line 123, in func
    # Non-greedy capture for filename to safely support paths with spaces
    frame_pattern = re.compile(r'File\s+["\'](.+?)["\'],\s+line\s+(\d+)(?:,\s+in\s+([^\n\r]+))?')

    for i, line in enumerate(lines):
        match = frame_pattern.search(line)
        if match:
            filepath = match.group(1).strip()
            line_no = int(match.group(2))
            func_name = (match.group(3) or "module").strip()
            code_snippet = ""
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if not frame_pattern.search(next_line) and not re.match(r'^[A-Za-z0-9_.]+(?:Error|Exception|Exit|Interrupt):', next_line):
                    code_snippet = next_line
            frames.append({
                "file": filepath,
                "line": line_no,
                "function": func_name,
                "code": code_snippet
            })

    # Find the exception line: typically the last line or one of the trailing lines
    for line in reversed(lines):
        # Match standard exceptions like ZeroDivisionError, TypeError, FileNotFoundError, json.decoder.JSONDecodeError, etc.
        err_match = re.match(r"^([A-Za-z0-9_.]*(?:Error|Exception|Exit|Interrupt|AssertionError)):?\s*(.*)$", line)
        if err_match:
            exception_type = err_match.group(1).strip()
            exception_message = err_match.group(2).strip()
            break
        # Also catch generic Exception or Custom error ending with Error/Exception
        alt_match = re.match(r"^([A-Za-z0-9_]+Error):?\s*(.*)$", line)
        if alt_match:
            exception_type = alt_match.group(1).strip()
            exception_message = alt_match.group(2).strip()
            break

    traceback_parsed = bool(frames or exception_type != "UnknownError")

    return {
        "traceback_parsed": traceback_parsed,
        "has_frames": len(frames) > 0,
        "exception_type": exception_type,
        "exception_message": exception_message,
        "frames": frames,
        "raw_trace": trace_text
    }


def find_file_in_project(project_dir: str, file_ref: str) -> Optional[str]:
    """
    Locates a file referenced in a stack trace within the target project directory.
    - Handles Windows paths (C:\\...), Linux paths (/...), and paths with spaces.
    - Strictly prevents reading files outside project_dir.
    - Matches exact relative paths, path suffixes, or unique basenames.
    """
    if not file_ref or not project_dir:
        return None

    project_abs = os.path.abspath(project_dir)

    # 1. Clean and normalize path string
    clean_ref = file_ref.strip().strip("'\"")
    clean_ref_norm = os.path.normpath(clean_ref)

    # Check if absolute path already points inside project_dir
    if os.path.isabs(clean_ref_norm):
        try:
            abs_target = os.path.abspath(clean_ref_norm)
            if abs_target.startswith(project_abs + os.sep) or abs_target == project_abs:
                if os.path.isfile(abs_target):
                    return abs_target
        except Exception:
            pass

    # Check direct relative path inside project_dir
    direct_path = os.path.abspath(os.path.join(project_abs, clean_ref))
    # Security: Strict boundary check to prevent path traversal
    if (direct_path.startswith(project_abs + os.sep) or direct_path == project_abs) and os.path.isfile(direct_path):
        return direct_path

    # Check by path suffix or basename
    ref_parts = [p for p in clean_ref.replace("\\", "/").split("/") if p]
    if not ref_parts:
        return None
    base_name = ref_parts[-1]

    # Search project files excluding ignored virtual environments and git metadata
    candidate_matches = []
    for root, dirs, files in os.walk(project_abs):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", ".venv", "venv", "site-packages", "node_modules"]]
        if base_name in files:
            full_path = os.path.join(root, base_name)
            # Boundary guard
            if full_path.startswith(project_abs + os.sep) or full_path == project_abs:
                candidate_matches.append(full_path)

    if not candidate_matches:
        return None

    if len(candidate_matches) == 1:
        return candidate_matches[0]

    # Multiple candidates: match by longest matching path suffix
    for match in candidate_matches:
        rel_match = os.path.relpath(match, project_abs).replace("\\", "/").split("/")
        if len(ref_parts) >= 2 and len(rel_match) >= 2:
            if ref_parts[-2:] == rel_match[-2:]:
                return match

    return candidate_matches[0]


def get_source_window(
    file_path: str,
    target_line: int,
    context_lines: int = 5
) -> Dict[str, Any]:
    """
    Reads source code and extracts a window around target_line with crash line marker.
    """
    if not os.path.isfile(file_path):
        return {
            "found": False,
            "error": f"File does not exist: {file_path}",
            "window_code": ""
        }

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as e:
        return {
            "found": False,
            "error": f"Error reading file: {e}",
            "window_code": ""
        }

    total_lines = len(all_lines)
    if total_lines == 0:
        return {
            "found": True,
            "line_valid": False,
            "target_line": target_line,
            "total_lines": 0,
            "window_code": "(Empty file)",
            "message": "Target file is empty."
        }

    line_valid = (1 <= target_line <= total_lines)
    start_idx = max(1, target_line - context_lines)
    end_idx = min(total_lines, target_line + context_lines)

    rendered_lines = []
    for i in range(start_idx, end_idx + 1):
        line_content = all_lines[i - 1].rstrip("\r\n")
        marker = ">> CRASH >>" if i == target_line else "           "
        rendered_lines.append(f"{i:4d}:{marker} {line_content}")

    return {
        "found": True,
        "line_valid": line_valid,
        "target_line": target_line,
        "total_lines": total_lines,
        "start_line": start_idx,
        "end_line": end_idx,
        "window_code": "\n".join(rendered_lines),
        "message": "" if line_valid else f"Line {target_line} is out of bounds (file has {total_lines} lines)."
    }


def analyze_traceback_with_project(project_dir: str, trace_text: str) -> Dict[str, Any]:
    """
    Master error ingestion function:
    1. Parses multiline stack trace.
    2. Identifies all frames, marking which belong to the user's project.
    3. Finds the innermost application frame (deepest frame inside the user's project).
    4. Extracts source code window around the culprit line.
    5. Explains missing files or out-of-bound line numbers clearly.
    """
    parsed = parse_stack_trace(trace_text)
    frames = parsed.get("frames", [])

    annotated_frames = []
    innermost_app_frame = None

    for frame in frames:
        matched_path = find_file_in_project(project_dir, frame["file"]) if project_dir else None
        is_app = bool(matched_path and os.path.isfile(matched_path))
        rel_path = os.path.relpath(matched_path, project_dir).replace("\\", "/") if is_app else None

        frame_info = {
            "file_raw": frame["file"],
            "line": frame["line"],
            "function": frame["function"],
            "code": frame["code"],
            "is_application_frame": is_app,
            "matched_file": rel_path,
            "full_path": matched_path if is_app else None
        }
        annotated_frames.append(frame_info)
        if is_app:
            innermost_app_frame = frame_info

    # Extract source code for the innermost application frame
    culprit_window = None
    source_located = False
    status_explanation = ""

    if innermost_app_frame and innermost_app_frame["full_path"]:
        culprit_window = get_source_window(
            innermost_app_frame["full_path"],
            innermost_app_frame["line"],
            context_lines=5
        )
        source_located = culprit_window["found"]
        if not culprit_window["line_valid"]:
            status_explanation = (
                f"Located file '{innermost_app_frame['matched_file']}', but line "
                f"{innermost_app_frame['line']} is out of bounds (file has {culprit_window['total_lines']} lines)."
            )
        else:
            status_explanation = (
                f"Successfully located innermost application frame in '{innermost_app_frame['matched_file']}' "
                f"at line {innermost_app_frame['line']}."
            )
    else:
        if frames:
            status_explanation = (
                f"Traceback parsed ({len(frames)} frames), but none of the referenced files "
                f"were found inside the ingested project directory."
            )
        elif parsed["traceback_parsed"]:
            status_explanation = (
                f"Detected error '{parsed['exception_type']}', but no stack frames "
                f"(File '...', line X) were present in the error text."
            )
        else:
            status_explanation = "Could not identify a valid Python traceback or exception."

    return {
        "traceback_parsed": parsed["traceback_parsed"],
        "has_frames": parsed["has_frames"],
        "source_located": source_located,
        "exception_type": parsed["exception_type"],
        "exception_message": parsed["exception_message"],
        "frames": annotated_frames,
        "innermost_application_frame": innermost_app_frame,
        "culprit_source_window": culprit_window,
        "status_explanation": status_explanation
    }


def get_source_code_context(project_dir: str, frames: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Reads relevant source code from files mentioned in the stack trace.
    Returns full content or contextual windows with line numbers.
    """
    files_context = {}

    for frame in frames:
        file_ref = frame.get("file") or frame.get("file_raw", "")
        matched_path = find_file_in_project(project_dir, file_ref)
        if matched_path and os.path.isfile(matched_path):
            rel_path = os.path.relpath(matched_path, project_dir).replace("\\", "/")
            if rel_path not in files_context:
                try:
                    with open(matched_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                    files_context[rel_path] = {
                        "full_path": matched_path,
                        "relative_path": rel_path,
                        "total_lines": len(lines),
                        "lines": lines,
                        "failing_lines": [frame["line"]]
                    }
                except Exception as e:
                    files_context[rel_path] = {"error": f"Failed to read file: {e}"}
            else:
                files_context[rel_path]["failing_lines"].append(frame["line"])

    return files_context


def get_git_history(project_dir: str, culprit_files: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts file-specific commit history, git blame, and relevant commit diffs.
    Specifically checks lines around the failing line to find which commit modified them.
    Never assumes the latest commit caused the error.
    """
    git_dir = os.path.join(project_dir, ".git")
    if not os.path.isdir(git_dir) or git is None:
        return {"has_git": False, "message": "No Git repository found in project directory."}

    try:
        repo = git.Repo(project_dir)
        git_findings = {
            "has_git": True,
            "branch": repo.active_branch.name if not repo.head.is_detached else "detached",
            "files": {}
        }

        for rel_path, file_info in culprit_files.items():
            if "error" in file_info:
                continue

            # 1. Commit history for this specific file
            file_commits = []
            try:
                for commit in repo.iter_commits(paths=rel_path, max_count=5):
                    diff_text = ""
                    try:
                        if commit.parents:
                            diff_text = repo.git.diff(f"{commit.hexsha}~1", commit.hexsha, rel_path)
                        else:
                            diff_text = repo.git.show(commit.hexsha, rel_path)
                    except Exception:
                        diff_text = "(Diff unavailable)"

                    file_commits.append({
                        "commit_hash": commit.hexsha[:8],
                        "author": commit.author.name,
                        "date": commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "message": commit.message.strip(),
                        "diff": diff_text[:1500]
                    })
            except Exception as e:
                file_commits = [{"error": f"Failed to get file commit history: {e}"}]

            # 2. Git blame around failing lines
            blame_entries = []
            culprit_commit_candidate = None
            try:
                failing_lines = set(file_info.get("failing_lines", []))
                blame_data = repo.blame("HEAD", rel_path)
                current_line_no = 1
                for entry in blame_data:
                    b_commit = entry[0]
                    lines = entry[1]
                    for line_str in lines:
                        if current_line_no in failing_lines or any(abs(current_line_no - fl) <= 3 for fl in failing_lines):
                            blame_entries.append({
                                "line_no": current_line_no,
                                "commit_hash": b_commit.hexsha[:8],
                                "author": b_commit.author.name,
                                "message": b_commit.message.strip(),
                                "code": line_str.rstrip()
                            })
                            if current_line_no in failing_lines and culprit_commit_candidate is None:
                                culprit_commit_candidate = {
                                    "commit_hash": b_commit.hexsha[:8],
                                    "author": b_commit.author.name,
                                    "message": b_commit.message.strip(),
                                    "line_no": current_line_no
                                }
                        current_line_no += 1
            except Exception as e:
                blame_entries = [{"error": f"Git blame failed: {e}"}]

            git_findings["files"][rel_path] = {
                "recent_commits": file_commits,
                "blame_for_failing_lines": blame_entries,
                "culprit_commit_candidate": culprit_commit_candidate
            }

        return git_findings
    except Exception as e:
        return {"has_git": False, "error": f"Git inspection failed: {e}"}


def get_dependency_info(project_dir: str) -> Dict[str, Any]:
    """
    Extracts dependency declarations from requirements.txt or pyproject.toml.
    """
    deps = {}
    req_file = os.path.join(project_dir, "requirements.txt")
    pyproject_file = os.path.join(project_dir, "pyproject.toml")

    if os.path.isfile(req_file):
        try:
            with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                deps["requirements.txt"] = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            deps["requirements.txt_error"] = str(e)

    if os.path.isfile(pyproject_file):
        try:
            with open(pyproject_file, "r", encoding="utf-8", errors="replace") as f:
                deps["pyproject.toml"] = f.read()[:1000]
        except Exception as e:
            deps["pyproject.toml_error"] = str(e)

    return deps


def collect_incident_context(project_dir: str, error_text: str) -> Dict[str, Any]:
    """
    Master collector function combining stack trace parsing, source code extraction,
    git history & blame inspection, and dependencies.
    """
    stack_data = parse_stack_trace(error_text)
    source_context = get_source_code_context(project_dir, stack_data["frames"])
    git_history = get_git_history(project_dir, source_context)
    dependencies = get_dependency_info(project_dir)

    return {
        "project_dir": project_dir,
        "stack_trace": stack_data,
        "source_context": source_context,
        "git_history": git_history,
        "dependencies": dependencies
    }
