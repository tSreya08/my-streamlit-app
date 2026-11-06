import os
import shutil
import pytest
from core.project_ingestor import extract_project_zip
from core.context_collector import analyze_traceback_with_project, collect_incident_context
from core.git_analyzer import inspect_git_repository
from core.vulnerability_scanner import run_trivy_scan
from core.patch_manager import (
    validate_patch_safety,
    generate_unified_diff,
    create_working_copy,
    apply_patch_to_working_copy,
    save_patch_artifact
)
from core.sandbox_runner import (
    run_tests_on_working_copy,
    safe_cleanup,
    verify_trusted_origin
)

PAYMENT_SAMPLE_DIR = os.path.abspath("samples/payment_service")
PAYMENT_ZIP_PATH = os.path.abspath("samples/payment_service.zip")

SAMPLE_PAYMENT_ERROR = """Traceback (most recent call last):
  File "test_payment.py", line 42, in test_empty_batch_reconciliation
    summary = processor.reconcile_batch(batch_id="batch_empty", transactions=[])
  File "payment.py", line 114, in reconcile_batch
    avg_ticket = total_volume / len(settled)
ZeroDivisionError: division by zero"""

PROPOSED_PAYMENT_PATCH = {
    "target_file": "payment.py",
    "original_snippet": "        # Calculate average transaction amount (average ticket)\n        avg_ticket = total_volume / len(settled)",
    "replacement_snippet": "        # Calculate average transaction amount (average ticket)\n        avg_ticket = (total_volume / len(settled)) if settled else 0.0"
}


def test_payment_sample_zip_ingestion():
    """STEP 1 & 2: Ingest payment sample via ZIP upload without executing code."""
    assert os.path.isfile(PAYMENT_ZIP_PATH), "payment_service.zip must exist"

    ingested = extract_project_zip(PAYMENT_ZIP_PATH)
    try:
        assert os.path.isdir(ingested.project_dir)
        assert "payment.py" in ingested.python_files
        assert "test_payment.py" in ingested.python_files
        assert "requirements.txt" in ingested.dependency_files
        assert ingested.has_git is True
    finally:
        ingested.cleanup()


def test_payment_sample_source_code_localization():
    """STEP 3 & 4: Traceback parsing and culprit source code localization."""
    analysis = analyze_traceback_with_project(PAYMENT_SAMPLE_DIR, SAMPLE_PAYMENT_ERROR)
    assert analysis["exception_type"] == "ZeroDivisionError"
    assert "division by zero" in analysis["exception_message"]
    assert analysis["source_located"] is True

    innermost = analysis["innermost_application_frame"]
    assert innermost["matched_file"] == "payment.py"
    assert innermost["line"] == 114
    assert innermost["function"] == "reconcile_batch"

    window = analysis["culprit_source_window"]
    assert window is not None
    assert "avg_ticket = total_volume / len(settled)" in window["window_code"]


def test_payment_sample_git_blame_identifies_culprit_not_latest():
    """STEP 5: Git blame analysis isolates culprit commit c3ab04e, not latest commit e4296c5."""
    git_res = inspect_git_repository(
        PAYMENT_SAMPLE_DIR,
        culprit_file="payment.py",
        target_line=114,
        target_function="reconcile_batch"
    )
    assert git_res["has_git"] is True
    assert git_res["current_branch"] == "master"
    assert len(git_res["recent_commits"]) >= 4

    # Verify line 114 blame identifies commit c3ab04e
    blame_lines = git_res["blame_for_target_lines"]
    target_blame = next((b for b in blame_lines if b["line_no"] == 114), None)
    assert target_blame is not None
    assert target_blame["commit_hash"].startswith("c3ab04e")
    assert "Marcus Ray" in target_blame["author"]

    # Verify latest commit is e4296c5 and did NOT touch the culprit line
    latest_commit = git_res["recent_commits"][0]
    assert latest_commit["commit_hash"].startswith("e4296c5")
    assert not latest_commit.get("touches_target_line", False)

    # Verify evidence summary explains the distinction
    assert "c3ab04e" in git_res["evidence_summary"]
    assert "did NOT modify" in git_res["evidence_summary"]


def test_payment_sample_trivy_dependency_scan():
    """STEP 6: Trivy dependency scan against payment service requirements."""
    scan_res = run_trivy_scan(PAYMENT_SAMPLE_DIR)
    assert scan_res["status"] == "success"
    assert scan_res["is_clean"] is True
    assert scan_res["total_findings"] == 0
    assert scan_res["report_path"] is not None
    assert not scan_res["report_path"].startswith(PAYMENT_SAMPLE_DIR)


def test_payment_sample_patch_validation_and_working_copy_verification():
    """STEP 9 & 10: Patch validation, isolated application, and trusted verification."""
    # 1. Validate patch safety against original project
    is_safe, msg = validate_patch_safety(PAYMENT_SAMPLE_DIR, PROPOSED_PAYMENT_PATCH)
    assert is_safe is True, f"Patch should be safe: {msg}"

    # 2. Generate unified diff
    diff = generate_unified_diff("payment.py", PROPOSED_PAYMENT_PATCH["original_snippet"], PROPOSED_PAYMENT_PATCH["replacement_snippet"])
    assert "-        avg_ticket = total_volume / len(settled)" in diff
    assert "+        avg_ticket = (total_volume / len(settled)) if settled else 0.0" in diff

    # 3. Read original payment.py content to verify immutability later
    with open(os.path.join(PAYMENT_SAMPLE_DIR, "payment.py"), "r", encoding="utf-8") as f:
        original_payment_content = f.read()

    # 4. Create isolated working copy
    wc_dir = create_working_copy(PAYMENT_SAMPLE_DIR)
    try:
        assert verify_trusted_origin(wc_dir) is True

        # 5. Apply patch to working copy
        applied, app_msg = apply_patch_to_working_copy(wc_dir, PROPOSED_PAYMENT_PATCH)
        assert applied is True, f"Patch application failed: {app_msg}"

        # 6. Verify working copy content has patch
        with open(os.path.join(wc_dir, "payment.py"), "r", encoding="utf-8") as f:
            patched_wc_content = f.read()
        assert "avg_ticket = (total_volume / len(settled)) if settled else 0.0" in patched_wc_content

        # 7. Run regression verification on patched working copy
        verif = run_tests_on_working_copy(wc_dir, is_trusted=True)
        assert verif["status"] == "Tests passed."
        assert verif["passed"] is True
        assert verif["tests_passed"] == 5
        assert verif["tests_failed"] == 0
        assert verif["exit_code"] == 0
    finally:
        safe_cleanup(wc_dir)

    # 8. Verify original payment.py was NEVER modified
    with open(os.path.join(PAYMENT_SAMPLE_DIR, "payment.py"), "r", encoding="utf-8") as f:
        after_content = f.read()
    assert original_payment_content == after_content


def test_untrusted_uploaded_payment_sample_blocks_execution(tmp_path):
    """Untrusted project uploads must strictly block test execution."""
    ingested = extract_project_zip(PAYMENT_ZIP_PATH)
    try:
        # Working copy created from untrusted upload does NOT have trusted origin manifest
        untrusted_wc = create_working_copy(ingested.project_dir)
        try:
            assert verify_trusted_origin(untrusted_wc) is False

            verif = run_tests_on_working_copy(untrusted_wc, is_trusted=False)
            assert verif["status"] == "Verification not performed."
            assert verif["ran_tests"] is False
            assert verif["security_blocked"] is True
            assert "Arbitrary test execution is disabled" in verif["message"]
        finally:
            safe_cleanup(untrusted_wc)
    finally:
        ingested.cleanup()


def test_payment_sample_downloadable_report_generation():
    """PHASE 6: Verify downloadable report generation for payment service incident."""
    import json
    from core.report_generator import format_markdown_report, format_json_report

    trace_analysis = analyze_traceback_with_project(PAYMENT_SAMPLE_DIR, SAMPLE_PAYMENT_ERROR)
    git_res = inspect_git_repository(PAYMENT_SAMPLE_DIR, culprit_file="payment.py", target_line=114, target_function="reconcile_batch")
    scan_res = run_trivy_scan(PAYMENT_SAMPLE_DIR)

    inv_res = {
        "incident_summary": "Empty settlement batch causes ZeroDivisionError.",
        "likely_root_cause": "reconcile_batch divides total_volume by len(settled) without guarding against zero length.",
        "affected_file": "payment.py",
        "affected_function": "reconcile_batch",
        "confidence": "High",
        "suggested_fix": PROPOSED_PAYMENT_PATCH,
        "is_ai_generated": False,
        "investigation_mode": "Deterministic Demonstration Baseline (Non-AI)"
    }
    verif_res = {
        "status": "Tests passed.",
        "passed": True,
        "tests_passed": 5,
        "tests_failed": 0,
        "tests_skipped": 0,
        "duration_seconds": 0.32,
        "exit_code": 0,
        "stdout": "5 passed in 0.32s"
    }
    diff = generate_unified_diff("payment.py", PROPOSED_PAYMENT_PATCH["original_snippet"], PROPOSED_PAYMENT_PATCH["replacement_snippet"])

    # 1. Generate Markdown Report
    md = format_markdown_report(
        project_name="payment_service",
        project_source="Built-in Sample",
        investigation_mode="Deterministic Demonstration Baseline (Non-AI)",
        error_text=SAMPLE_PAYMENT_ERROR,
        trace_analysis=trace_analysis,
        git_analysis=git_res,
        scan_result=scan_res,
        investigation_results=inv_res,
        unified_diff=diff,
        verification_result=verif_res
    )
    assert "# 🕵️ PHANTOM Incident Investigation Report" in md
    assert "ZeroDivisionError" in md
    assert "payment.py" in md
    assert "reconcile_batch" in md
    assert "c3ab04e" in md
    assert "e4296c5" in md
    assert "Tests passed." in md
    assert "AIza" not in md
    assert "GEMINI_API_KEY" not in md

    # 2. Generate JSON Report
    json_str = format_json_report(
        project_name="payment_service",
        project_source="Built-in Sample",
        investigation_mode="Deterministic Demonstration Baseline (Non-AI)",
        error_text=SAMPLE_PAYMENT_ERROR,
        trace_analysis=trace_analysis,
        git_analysis=git_res,
        scan_result=scan_res,
        investigation_results=inv_res,
        unified_diff=diff,
        verification_result=verif_res
    )
    data = json.loads(json_str)
    assert data["report_metadata"]["target_project"] == "payment_service"
    assert data["runtime_error"]["parsed_exception"]["type"] == "ZeroDivisionError"
    assert data["verification_outcome"]["status"] == "Tests passed."
    assert data["verification_outcome"]["tests_passed"] == 5
    assert len(data["limitations"]) > 0

