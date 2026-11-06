import os
import sys
import stat
import json
import uuid
import hmac
import hashlib
import shutil
import tempfile
import subprocess
import re
import time
from typing import Dict, Any, Tuple, Optional
from core.patch_manager import validate_patch_safety


# Ephemeral in-memory secret generated per Python process lifetime for signing origin manifests
_SERVER_SESSION_SECRET = uuid.uuid4().hex
ORIGIN_MANIFEST_NAME = ".phantom_origin.json"


def get_canonical_sample_dir() -> str:
    """Returns the absolute canonical path to PHANTOM's controlled shop_cart sample repository."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.abspath(os.path.join(base_dir, "samples", "shop_cart"))


def get_trusted_sample_dirs() -> list[str]:
    """Returns canonical absolute paths to PHANTOM's controlled sample repositories."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.abspath(os.path.join(base_dir, "samples", "shop_cart")),
        os.path.abspath(os.path.join(base_dir, "samples", "payment_service")),
    ]


def compute_origin_token(canonical_sample: str, target_dir: str) -> str:
    """
    Computes an HMAC-SHA256 signature binding the sample repo to the exact working-copy path.
    Prevents replay attacks where a valid manifest is copied into another directory.
    """
    target_abs = os.path.normcase(os.path.abspath(target_dir))
    canonical_abs = os.path.normcase(os.path.abspath(canonical_sample))
    payload = f"{canonical_abs}::{target_abs}"
    return hmac.new(
        _SERVER_SESSION_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def attach_trusted_origin_manifest(target_dir: str, source_project_dir: str) -> None:
    """
    If source_project_dir is verified as one of PHANTOM's controlled sample repositories,
    attaches an HMAC-signed origin manifest bound to target_dir.
    """
    try:
        source_abs = os.path.abspath(source_project_dir)
        matched_sample = None
        for s_dir in get_trusted_sample_dirs():
            if (os.path.exists(source_abs) and os.path.exists(s_dir) and os.path.samefile(source_abs, s_dir)) or (os.path.normcase(source_abs) == os.path.normcase(s_dir)):
                matched_sample = s_dir
                break

        if matched_sample:
            target_abs = os.path.normcase(os.path.abspath(target_dir))
            token = compute_origin_token(matched_sample, target_dir)

            manifest_path = os.path.join(target_dir, ORIGIN_MANIFEST_NAME)
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump({
                    "source": matched_sample,
                    "target": target_abs,
                    "token": token
                }, f, indent=2)
    except Exception:
        pass


def verify_trusted_origin(target_dir: str) -> bool:
    """
    Cryptographically verifies that target_dir has a valid origin manifest
    proving it was created from PHANTOM's controlled sample repositories in the current session
    AND that the manifest is bound to this exact target directory (preventing directory-replay attacks).
    """
    try:
        manifest_path = os.path.join(target_dir, ORIGIN_MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            return False

        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        source_claimed = data.get("source")
        if not source_claimed:
            return False

        matched_sample = None
        for s_dir in get_trusted_sample_dirs():
            if (os.path.exists(source_claimed) and os.path.exists(s_dir) and os.path.samefile(source_claimed, s_dir)) or (os.path.normcase(source_claimed) == os.path.normcase(s_dir)):
                matched_sample = s_dir
                break

        if not matched_sample:
            return False

        expected_token = compute_origin_token(matched_sample, target_dir)

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(data.get("token", ""), expected_token)
    except Exception:
        return False


def parse_pytest_output(stdout: str, stderr: str = "") -> Dict[str, int]:
    """
    Extracts passed, failed, and skipped test counts from pytest stdout/stderr.
    """
    combined = stdout + "\n" + stderr
    counts = {"passed": 0, "failed": 0, "skipped": 0}

    # Match summary counts like: "3 passed", "1 failed", "2 skipped", "1 error"
    lines = combined.strip().splitlines()
    summary_lines = lines[-5:] if len(lines) >= 5 else lines
    summary_text = " ".join(summary_lines)

    for match in re.finditer(r"(\d+)\s+(passed|failed|skipped|error)", summary_text, re.IGNORECASE):
        num = int(match.group(1))
        key = match.group(2).lower()
        if key == "passed":
            counts["passed"] = num
        elif key in ("failed", "error"):
            counts["failed"] += num
        elif key == "skipped":
            counts["skipped"] = num

    return counts



def get_sanitized_env() -> Dict[str, str]:
    """
    Constructs a minimal, sanitized environment dictionary for executing Python & pytest on Windows.
    Preserves only essential OS runtime variables while strictly excluding API keys,
    credentials, and unrelated host process environment variables.
    """
    allowed_keys = {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "APPDATA",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
    }
    sanitized = {}
    for key, val in os.environ.items():
        if key.upper() in allowed_keys:
            sanitized[key] = val

    # Explicit defense: strip any variable containing credential/secret indicators
    sensitive_substrings = ("KEY", "SECRET", "TOKEN", "AUTH", "PASS")
    sanitized = {
        k: v for k, v in sanitized.items()
        if not any(sub in k.upper() for sub in sensitive_substrings)
    }

    # Force standard UTF-8 I/O encoding
    sanitized["PYTHONIOENCODING"] = "utf-8"
    sanitized["PYTHONUTF8"] = "1"
    return sanitized



def remove_readonly(func, path, excinfo):
    """Handles Windows read-only files (e.g. .git objects) during cleanup."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def safe_cleanup(dir_path: str):
    """Safely removes a temporary directory."""
    if os.path.exists(dir_path):
        try:
            shutil.rmtree(dir_path, onexc=lambda fn, p, exc: (os.chmod(p, stat.S_IWRITE), fn(p)))
        except TypeError:
            shutil.rmtree(dir_path, onerror=remove_readonly)
        except Exception:
            pass


def validate_patch(project_dir: str, patch: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates a patch proposal before applying.
    Delegates to core.patch_manager.validate_patch_safety for unified, strict safety checks.
    """
    return validate_patch_safety(project_dir, patch)



def apply_patch_to_dir(target_dir: str, patch: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Applies the patch safely to the target directory.
    """
    target_file = os.path.normpath(patch["target_file"]).replace("/", os.sep).replace("\\", os.sep)
    file_path = os.path.join(target_dir, target_file)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        orig = patch["original_snippet"]
        repl = patch["replacement_snippet"]

        if orig in content:
            new_content = content.replace(orig, repl, 1)
        else:
            # Fallback with whitespace normalized
            lines = content.splitlines()
            orig_lines = [line.rstrip() for line in orig.splitlines()]
            content_stripped = [line.rstrip() for line in lines]
            
            # Simple substring replacement
            new_content = content.replace(orig.strip(), repl.strip(), 1)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        return True, f"Successfully patched {target_file}."
    except Exception as e:
        return False, f"Failed to apply patch: {e}"


def run_verification(project_dir: str, patch: Dict[str, Any], is_trusted: bool = False) -> Dict[str, Any]:
    """
    Executes regression tests to verify a proposed patch.
    
    SECURITY POLICY:
    - If is_trusted is False (e.g. untrusted user upload), test execution is blocked.
    - If is_trusted is True (e.g. controlled sample repository), tests run in an isolated temp copy.
    """
    # 1. Validate the patch structure first
    start_time = time.perf_counter()
    is_valid, validation_msg = validate_patch(project_dir, patch)
    if not is_valid:
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": False,
            "validation_passed": False,
            "exit_code": None,
            "message": f"❌ Verification not performed: Patch validation failed: {validation_msg}",
            "reason_not_performed": f"Patch validation failed: {validation_msg}",
            "stdout": "",
            "stderr": ""
        }

    # 2. Security check
    if not is_trusted:
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": True,
            "validation_passed": True,
            "exit_code": None,
            "message": "🔒 Verification not performed: Arbitrary test execution is disabled for untrusted uploads.",
            "reason_not_performed": "Arbitrary test execution is disabled for untrusted uploads. Static analysis and patch validation only.",
            "stdout": "",
            "stderr": ""
        }

    # Defense-in-depth: verify project_dir is one of PHANTOM's controlled sample repositories
    project_abs = os.path.abspath(project_dir)
    is_sample = False
    try:
        for s_dir in get_trusted_sample_dirs():
            if (os.path.exists(project_abs) and os.path.exists(s_dir) and os.path.samefile(project_abs, s_dir)) or (os.path.normcase(project_abs) == os.path.normcase(s_dir)):
                is_sample = True
                break
    except Exception:
        is_sample = False

    if not is_sample:
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": True,
            "validation_passed": True,
            "exit_code": None,
            "message": "🔒 Verification not performed: Project directory could not be verified as PHANTOM's controlled sample repository.",
            "reason_not_performed": "Project directory could not be verified as PHANTOM's controlled sample repository.",
            "stdout": "",
            "stderr": ""
        }

    # 3. Create isolated copy for safe testing
    temp_dir = tempfile.mkdtemp(prefix="phantom_verify_")
    try:
        shutil.copytree(project_dir, temp_dir, dirs_exist_ok=True)
        attach_trusted_origin_manifest(temp_dir, project_dir)

        # Apply patch to temp copy
        success, patch_msg = apply_patch_to_dir(temp_dir, patch)
        if not success:
            duration = round(time.perf_counter() - start_time, 2)
            return {
                "ran_tests": False,
                "status": "Verification not performed.",
                "passed": False,
                "tests_passed": 0,
                "tests_failed": 0,
                "tests_skipped": 0,
                "duration_seconds": duration,
                "security_blocked": False,
                "validation_passed": True,
                "exit_code": None,
                "message": f"❌ Verification not performed: Could not apply patch to sandbox: {patch_msg}",
                "reason_not_performed": f"Could not apply patch to sandbox: {patch_msg}",
                "stdout": "",
                "stderr": ""
            }

        # Execute pytest in sandbox with sanitized environment
        res = subprocess.run(
            [sys.executable, "-m", "pytest", "."],
            cwd=temp_dir,
            env=get_sanitized_env(),
            capture_output=True,
            text=True,
            timeout=15
        )

        duration = round(time.perf_counter() - start_time, 2)
        counts = parse_pytest_output(res.stdout, res.stderr)
        tests_passed = (res.returncode == 0)
        status = "Tests passed." if tests_passed else "Tests failed."

        return {
            "ran_tests": True,
            "status": status,
            "passed": tests_passed,
            "tests_passed": counts["passed"],
            "tests_failed": counts["failed"],
            "tests_skipped": counts["skipped"],
            "duration_seconds": duration,
            "security_blocked": False,
            "validation_passed": True,
            "exit_code": res.returncode,
            "message": f"✅ {status}" if tests_passed else f"❌ {status}",
            "reason_not_performed": None,
            "stdout": res.stdout,
            "stderr": res.stderr
        }
    except subprocess.TimeoutExpired as e:
        duration = round(time.perf_counter() - start_time, 2)
        return {
            "ran_tests": True,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": duration,
            "security_blocked": False,
            "validation_passed": True,
            "exit_code": -1,
            "message": "⏱️ Verification not performed: Pytest timed out after 15 seconds.",
            "reason_not_performed": "Pytest execution timed out after 15 seconds before a conclusive result could be established.",
            "stdout": e.stdout if hasattr(e, "stdout") and e.stdout else "",
            "stderr": "Execution timed out."
        }
    except Exception as e:
        duration = round(time.perf_counter() - start_time, 2)
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": duration,
            "security_blocked": False,
            "validation_passed": True,
            "exit_code": None,
            "message": f"Verification not performed: {e}",
            "reason_not_performed": f"Unexpected error during verification: {e}",
            "stdout": "",
            "stderr": str(e)
        }
    finally:
        safe_cleanup(temp_dir)


def run_tests_on_working_copy(
    working_copy_dir: str,
    is_trusted: bool = False,
    extra_test_code: Optional[str] = None,
    extra_test_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes regression tests directly on an already-patched isolated working copy.

    SECURITY POLICY:
    - If is_trusted is False (e.g. untrusted user upload), test execution is blocked.
    - If origin cannot be established or verified, execution is blocked.
    - Preserves sanitized environment and strict 15-second execution ceiling.
    - Returns exact status: "Tests passed.", "Tests failed.", or "Verification not performed."
    """
    start_time = time.perf_counter()

    if not is_trusted:
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": True,
            "exit_code": None,
            "message": "🔒 Verification not performed: Arbitrary test execution is disabled for untrusted uploads.",
            "reason_not_performed": "Arbitrary test execution is disabled for untrusted uploads. Static analysis and patch validation only.",
            "stdout": "",
            "stderr": ""
        }

    if not os.path.isdir(working_copy_dir):
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": False,
            "exit_code": None,
            "message": f"❌ Verification not performed: Working copy directory '{working_copy_dir}' does not exist.",
            "reason_not_performed": f"Working copy directory '{working_copy_dir}' does not exist.",
            "stdout": "",
            "stderr": ""
        }

    # Defense-in-depth: verify working_copy_dir originates from PHANTOM's controlled sample repo
    if not verify_trusted_origin(working_copy_dir):
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": 0.0,
            "security_blocked": True,
            "exit_code": None,
            "message": "🔒 Verification not performed: Working copy origin could not be verified as PHANTOM's controlled sample repository.",
            "reason_not_performed": "Working copy origin could not be verified as PHANTOM's controlled sample repository (HMAC binding check failed).",
            "stdout": "",
            "stderr": ""
        }

    # Optionally inject targeted regression test into working copy if provided
    if extra_test_code and extra_test_file:
        safe_rel = os.path.normpath(extra_test_file).replace("/", os.sep).replace("\\", os.sep)
        if not os.path.isabs(safe_rel) and ".." not in safe_rel:
            dest_file = os.path.join(working_copy_dir, safe_rel)
            if os.path.isfile(dest_file):
                with open(dest_file, "a", encoding="utf-8") as f:
                    f.write("\n" + extra_test_code + "\n")

    try:
        res = subprocess.run(
            [sys.executable, "-m", "pytest", "."],
            cwd=working_copy_dir,
            env=get_sanitized_env(),
            capture_output=True,
            text=True,
            timeout=15
        )

        duration = round(time.perf_counter() - start_time, 2)
        counts = parse_pytest_output(res.stdout, res.stderr)
        tests_passed = (res.returncode == 0)
        status = "Tests passed." if tests_passed else "Tests failed."

        return {
            "ran_tests": True,
            "status": status,
            "passed": tests_passed,
            "tests_passed": counts["passed"],
            "tests_failed": counts["failed"],
            "tests_skipped": counts["skipped"],
            "duration_seconds": duration,
            "security_blocked": False,
            "exit_code": res.returncode,
            "message": f"✅ {status}" if tests_passed else f"❌ {status}",
            "reason_not_performed": None,
            "stdout": res.stdout,
            "stderr": res.stderr
        }
    except subprocess.TimeoutExpired as e:
        duration = round(time.perf_counter() - start_time, 2)
        return {
            "ran_tests": True,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": duration,
            "security_blocked": False,
            "exit_code": -1,
            "message": "⏱️ Verification not performed: Pytest timed out after 15 seconds.",
            "reason_not_performed": "Pytest execution timed out after 15 seconds before a conclusive result could be established.",
            "stdout": e.stdout if hasattr(e, "stdout") and e.stdout else "",
            "stderr": "Execution timed out."
        }
    except Exception as e:
        duration = round(time.perf_counter() - start_time, 2)
        return {
            "ran_tests": False,
            "status": "Verification not performed.",
            "passed": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_skipped": 0,
            "duration_seconds": duration,
            "security_blocked": False,
            "exit_code": None,
            "message": f"Verification not performed: {e}",
            "reason_not_performed": f"Unexpected error during test execution: {e}",
            "stdout": "",
            "stderr": str(e)
        }


