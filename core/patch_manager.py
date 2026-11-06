import os
import sys
import json
import uuid
import difflib
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List


def get_default_storage_dir() -> str:
    """Returns the default directory for storing patch artifacts (.phantom/patches)."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    storage_dir = os.path.join(base_dir, ".phantom", "patches")
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def generate_unified_diff(
    target_file: str,
    original_snippet: str,
    replacement_snippet: str,
    full_file_content: Optional[str] = None,
    context_lines: int = 3
) -> str:
    """
    Generates a deterministic unified diff using Python's difflib.
    Shows removed lines (-), added lines (+), and surrounding context lines.
    
    If full_file_content is provided and contains original_snippet,
    the diff is calculated in the context of the full file.
    Otherwise, the diff is generated directly between the snippets.
    """
    clean_target = os.path.normpath(target_file).replace("\\", "/")
    fromfile = f"a/{clean_target}"
    tofile = f"b/{clean_target}"

    if full_file_content is not None and original_snippet in full_file_content:
        orig_lines = full_file_content.splitlines(keepends=True)
        patched_content = full_file_content.replace(original_snippet, replacement_snippet, 1)
        new_lines = patched_content.splitlines(keepends=True)
    else:
        orig_lines = [line + "\n" for line in original_snippet.splitlines()]
        new_lines = [line + "\n" for line in replacement_snippet.splitlines()]

    diff_lines = list(difflib.unified_diff(
        orig_lines,
        new_lines,
        fromfile=fromfile,
        tofile=tofile,
        n=context_lines
    ))

    if not diff_lines:
        return ""

    return "".join(diff_lines)


def validate_patch_safety(project_dir: str, patch: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Strict safety validation for proposed patches:
    1. Validates structure and required fields.
    2. Rejects empty snippets and malformed types.
    3. Prevents path traversal and checks file location.
    4. Ensures original snippet matches target file exactly.
    5. Rejects ambiguous snippets (matching multiple locations).
    6. Rejects whole-file replacements when localized fix is expected.
    """
    if not isinstance(patch, dict):
        return False, "Patch proposal must be a dictionary."

    target_file = patch.get("target_file")
    if not target_file or not isinstance(target_file, str) or not target_file.strip():
        return False, "Patch missing or empty 'target_file'."

    # Path traversal defense
    clean_target = os.path.normpath(target_file).replace("/", os.sep).replace("\\", os.sep)
    if (
        os.path.isabs(clean_target)
        or clean_target.startswith(".." + os.sep)
        or clean_target == ".."
        or ".." in clean_target.split(os.sep)
    ):
        return False, f"Target file path '{target_file}' is invalid or attempts path traversal."

    project_abs = os.path.abspath(project_dir)
    target_abs = os.path.abspath(os.path.join(project_abs, clean_target))

    try:
        common = os.path.commonpath([project_abs, target_abs])
        if common != project_abs or target_abs == project_abs:
            return False, "Target file resolves outside the project directory."
    except Exception:
        return False, f"Invalid path resolution for '{target_file}'."

    if not os.path.isfile(target_abs):
        return False, f"Target file '{target_file}' does not exist in the project."

    original_snippet = patch.get("original_snippet")
    replacement_snippet = patch.get("replacement_snippet")

    if original_snippet is None or replacement_snippet is None:
        return False, "Patch must specify both 'original_snippet' and 'replacement_snippet'."

    if not isinstance(original_snippet, str) or not original_snippet.strip():
        return False, "'original_snippet' cannot be empty or whitespace-only."

    if not isinstance(replacement_snippet, str) or not replacement_snippet.strip():
        return False, "'replacement_snippet' cannot be empty or whitespace-only."

    try:
        with open(target_abs, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if original_snippet not in content:
            # Check normalized whitespace fallback
            normalized_content = "\n".join(line.rstrip() for line in content.splitlines())
            normalized_snippet = "\n".join(line.rstrip() for line in original_snippet.splitlines())
            if normalized_snippet not in normalized_content:
                return False, f"'original_snippet' was not found in '{target_file}'."

        # Ambiguity check: Reject if original snippet appears more than once
        occurrences = content.count(original_snippet)
        if occurrences > 1:
            return False, (
                f"Ambiguous snippet: 'original_snippet' matches {occurrences} locations in '{target_file}'. "
                "Include more surrounding context to ensure a unique match."
            )

        # Whole-file replacement check
        content_lines = content.splitlines()
        snippet_lines = original_snippet.splitlines()
        if len(content_lines) > 5 and original_snippet.strip() == content.strip():
            return False, (
                "Whole-file replacement rejected: proposed patch replaces the entire file. "
                "Only minimal localized corrections are permitted."
            )
        if len(content_lines) > 10 and len(snippet_lines) >= len(content_lines) * 0.9:
            return False, (
                "Whole-file replacement rejected: proposed patch replaces >= 90% of the file. "
                "Only minimal localized corrections are permitted."
            )

    except Exception as e:
        return False, f"Failed to inspect target file '{target_file}': {e}"

    return True, "Patch is safe and valid."


def sanitize_patch_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Removes sensitive keys (e.g. API keys, secrets, tokens) before serialization."""
    sensitive_substrings = ("api_key", "secret", "token", "password", "auth")
    cleaned = {}
    for k, v in data.items():
        if any(sub in k.lower() for sub in sensitive_substrings):
            continue
        if isinstance(v, dict):
            cleaned[k] = sanitize_patch_data(v)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitize_patch_data(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


def save_patch_artifact(
    patch_data: Dict[str, Any],
    storage_dir: Optional[str] = None,
    full_file_content: Optional[str] = None
) -> str:
    """
    Saves a proposed patch as an isolated JSON artifact outside the target project.
    Generates a unique patch ID, computes the unified diff, and records metadata.
    """
    target_dir = storage_dir or get_default_storage_dir()
    os.makedirs(target_dir, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_suffix = uuid.uuid4().hex[:8]
    patch_id = f"patch_{timestamp_str}_{unique_suffix}"

    target_file = patch_data.get("target_file", "unknown")
    original_snippet = patch_data.get("original_snippet", "")
    replacement_snippet = patch_data.get("replacement_snippet", "")
    explanation = patch_data.get("explanation", "")
    evidence = patch_data.get("evidence", [])

    diff_text = patch_data.get("unified_diff")
    if not diff_text and original_snippet and replacement_snippet:
        diff_text = generate_unified_diff(
            target_file,
            original_snippet,
            replacement_snippet,
            full_file_content=full_file_content
        )

    artifact = {
        "patch_id": patch_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": patch_data.get("status", "proposed"),  # proposed | applied_to_working_copy | rejected
        "target_file": target_file,
        "original_snippet": original_snippet,
        "replacement_snippet": replacement_snippet,
        "explanation": explanation,
        "evidence": evidence,
        "unified_diff": diff_text,
        "label": "AI-GENERATED SUGGESTION — REVIEW REQUIRED",
        "metadata": patch_data.get("metadata", {})
    }

    cleaned_artifact = sanitize_patch_data(artifact)
    file_path = os.path.join(target_dir, f"{patch_id}.json")

    # Path traversal check on patch_id
    if not os.path.abspath(file_path).startswith(os.path.abspath(target_dir)):
        raise ValueError("Invalid patch artifact path resolution.")

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(cleaned_artifact, f, indent=2)

    return patch_id


def load_patch_artifact(patch_id: str, storage_dir: Optional[str] = None) -> Dict[str, Any]:
    """Loads a stored patch artifact by ID."""
    target_dir = storage_dir or get_default_storage_dir()
    # Sanitize patch_id to prevent directory traversal
    clean_id = os.path.basename(patch_id)
    file_path = os.path.join(target_dir, f"{clean_id}.json" if not clean_id.endswith(".json") else clean_id)

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Patch artifact '{clean_id}' not found in '{target_dir}'.")

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_patch_artifacts(storage_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists all stored patch artifacts, newest first."""
    target_dir = storage_dir or get_default_storage_dir()
    if not os.path.exists(target_dir):
        return []

    artifacts = []
    for fname in os.listdir(target_dir):
        if fname.endswith(".json"):
            fpath = os.path.join(target_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    artifacts.append(data)
            except Exception:
                continue

    artifacts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return artifacts


def update_patch_status(
    patch_id: str,
    new_status: str,
    extra_metadata: Optional[Dict[str, Any]] = None,
    storage_dir: Optional[str] = None
) -> bool:
    """Updates the status and metadata of an existing patch artifact."""
    target_dir = storage_dir or get_default_storage_dir()
    clean_id = os.path.basename(patch_id)
    file_path = os.path.join(target_dir, f"{clean_id}.json" if not clean_id.endswith(".json") else clean_id)

    if not os.path.isfile(file_path):
        return False

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        data["status"] = new_status
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        if extra_metadata:
            data.setdefault("metadata", {}).update(extra_metadata)

        cleaned = sanitize_patch_data(data)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(cleaned, f, indent=2)

        return True
    except Exception:
        return False


def create_working_copy(project_dir: str) -> str:
    """
    Creates an isolated temporary working copy of a project directory.
    Guarantees the original project remains untouched.
    Attaches server-side origin metadata if the source is PHANTOM's controlled sample repository.
    """
    project_abs = os.path.abspath(project_dir)
    if not os.path.isdir(project_abs):
        raise ValueError(f"Project directory '{project_dir}' does not exist.")

    temp_working_dir = tempfile.mkdtemp(prefix="phantom_workcopy_")
    shutil.copytree(project_abs, temp_working_dir, dirs_exist_ok=True)

    try:
        from core.sandbox_runner import attach_trusted_origin_manifest
        attach_trusted_origin_manifest(temp_working_dir, project_abs)
    except Exception:
        pass

    return temp_working_dir


def apply_patch_to_working_copy(
    working_copy_dir: str,
    patch: Dict[str, Any],
    patch_id: Optional[str] = None,
    storage_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Applies a verified patch ONLY to a separate working copy:
    1. Validates the target path again in the working copy.
    2. Verifies the original snippet still matches the working-copy source.
    3. Rejects stale patches if working copy source has diverged.
    4. Applies only the localized replacement (1 occurrence).
    5. Preserves all unrelated code.
    6. Updates patch artifact metadata if patch_id is provided.
    7. Guarantees original uploaded project remains completely untouched.
    """
    if not os.path.isdir(working_copy_dir):
        return False, f"Working copy directory '{working_copy_dir}' does not exist."

    # Validate patch against the working copy
    is_safe, msg = validate_patch_safety(working_copy_dir, patch)
    if not is_safe:
        return False, f"Working copy safety validation failed: {msg}"

    clean_target = os.path.normpath(patch["target_file"]).replace("/", os.sep).replace("\\", os.sep)
    file_path = os.path.join(working_copy_dir, clean_target)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        orig = patch["original_snippet"]
        repl = patch["replacement_snippet"]

        # Stale patch verification
        if orig not in content:
            # Check normalized whitespace
            norm_content = "\n".join(l.rstrip() for l in content.splitlines())
            norm_orig = "\n".join(l.rstrip() for l in orig.splitlines())
            if norm_orig not in norm_content:
                return False, f"Stale patch rejected: original snippet no longer matches '{patch['target_file']}'."
            # Fallback exact replacement after line matching
            new_content = content.replace(orig.strip(), repl.strip(), 1)
        else:
            new_content = content.replace(orig, repl, 1)

        # Write to working copy
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        # Record application in patch artifact if patch_id provided
        if patch_id:
            update_patch_status(
                patch_id,
                "applied_to_working_copy",
                extra_metadata={
                    "working_copy_dir": working_copy_dir,
                    "applied_at": datetime.now(timezone.utc).isoformat()
                },
                storage_dir=storage_dir
            )

        return True, f"Successfully applied patch to '{patch['target_file']}' in working copy."

    except Exception as e:
        return False, f"Failed to apply patch to working copy: {e}"
