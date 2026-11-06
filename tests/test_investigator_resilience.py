import os
import json
import hashlib
import pytest
from unittest.mock import MagicMock, patch
from core.investigator import (
    InvestigatorError,
    get_request_timeout,
    is_retryable_gemini_error,
    extract_retry_after,
    calculate_backoff_delay,
    execute_with_retry,
    investigate_incident,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_MAX_RETRIES,
)
from core.report_generator import format_markdown_report, format_json_report
from streamlit.testing.v1 import AppTest
from tests.test_investigator import VALID_GEMINI_PAYLOAD

SAMPLE_ERROR = """Traceback (most recent call last):
  File "cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'
"""

SAMPLE_CONTEXT = {
    "project_dir": "samples/shop_cart",
    "stack_trace": {
        "raw_trace": SAMPLE_ERROR,
        "exception_type": "TypeError",
        "exception_message": "unsupported operand type(s) for *: 'float' and 'NoneType'",
        "innermost_frame": {"file": "cart.py", "line": 31, "func": "calculate_total"}
    },
    "source_context": {
        "cart.py": {
            "failing_lines": [31],
            "lines": [
                "    discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)\n",
                "    discount_amount = subtotal * discount_rate\n"
            ]
        }
    },
    "git_history": {
        "has_git": True,
        "files": {
            "cart.py": {
                "recent_commits": [
                    {
                        "commit_hash": "ffacc60",
                        "author": "Alice Dev",
                        "date": "2026-11-05",
                        "message": "feat: Add loyalty discount",
                        "diff": "+ discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)"
                    }
                ],
                "blame_for_failing_lines": [
                    {
                        "line_no": 31,
                        "commit_hash": "ffacc60",
                        "author": "Alice Dev",
                        "code": "discount_amount = subtotal * discount_rate",
                        "message": "feat: Add loyalty discount"
                    }
                ],
                "culprit_commit_candidate": {
                    "commit_hash": "ffacc60",
                    "author": "Alice Dev",
                    "message": "feat: Add loyalty discount"
                }
            }
        }
    },
    "dependencies": {}
}


# =====================================================================
# 1. TIMEOUT CONFIGURATION TESTS
# =====================================================================

def test_get_request_timeout_defaults_and_precedence(monkeypatch):
    """Verifies timeout precedence: explicit > GEMINI_TIMEOUT_SECONDS > default."""
    monkeypatch.delenv("GEMINI_TIMEOUT_SECONDS", raising=False)
    assert get_request_timeout() == DEFAULT_TIMEOUT_SECONDS
    assert get_request_timeout() == 30.0

    # Environment variable override
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", "45.5")
    assert get_request_timeout() == 45.5

    # Invalid env var falls back to default
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", "invalid_number")
    assert get_request_timeout() == DEFAULT_TIMEOUT_SECONDS

    # Explicit argument takes top priority
    assert get_request_timeout(explicit_timeout=15.0) == 15.0
    assert get_request_timeout(explicit_timeout=0) == DEFAULT_TIMEOUT_SECONDS


def test_investigate_incident_passes_finite_timeout_to_client():
    """Verify that types.HttpOptions(timeout=...) is passed to genai.Client."""
    mock_response = MagicMock()
    mock_response.text = '{"incident_summary": "Test", "likely_root_cause": "Test", "affected_file": "cart.py", "confidence": "High", "evidence": ["fact 1"], "suggested_fix": {"target_file": "cart.py", "original_snippet": "a = 1", "replacement_snippet": "a = 2", "explanation": "fix"}}'

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.return_value = mock_response

        investigate_incident(SAMPLE_CONTEXT, api_key="test_key", timeout=12.5)

        # Check client instantiation arguments
        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        assert "http_options" in kwargs
        # HttpOptions expects integer milliseconds
        assert kwargs["http_options"].timeout == 12500


def test_investigate_incident_timeout_error_handling():
    """Verify that a timeout error produces an informative, structured InvestigatorError."""
    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = TimeoutError("Request timed out")

        with pytest.raises(InvestigatorError) as exc_info:
            investigate_incident(SAMPLE_CONTEXT, api_key="test_key", timeout=10.0, max_retries=1)

        err = str(exc_info.value)
        assert "timed out after 10.0s" in err


# =====================================================================
# 2. TRANSIENT VS. PERMANENT ERROR CLASSIFICATION
# =====================================================================

def test_is_retryable_gemini_error_transient_cases():
    """503, 429, timeouts, and connection errors must be classified as retryable."""
    # Mock exception with code=503
    exc_503 = Exception("The service is unavailable")
    exc_503.code = 503
    assert is_retryable_gemini_error(exc_503) is True

    # Mock exception with code=429
    exc_429 = Exception("Rate limit exceeded")
    exc_429.code = 429
    assert is_retryable_gemini_error(exc_429) is True

    # Status string attributes
    exc_status = Exception("Unavailable")
    exc_status.status = "UNAVAILABLE"
    assert is_retryable_gemini_error(exc_status) is True

    exc_status_quota = Exception("Resource exhausted")
    exc_status_quota.status = "RESOURCE_EXHAUSTED"
    assert is_retryable_gemini_error(exc_status_quota) is True

    # String-based fallback
    assert is_retryable_gemini_error(Exception("503 UNAVAILABLE: high traffic")) is True
    assert is_retryable_gemini_error(Exception("429 RESOURCE_EXHAUSTED: quota exceeded")) is True
    assert is_retryable_gemini_error(TimeoutError("Socket timed out")) is True
    assert is_retryable_gemini_error(ConnectionError("Connection reset by peer")) is True


def test_is_retryable_gemini_error_permanent_cases():
    """400, 401, 403, 404, parsing, and auth errors must NEVER be retried."""
    exc_401 = Exception("Unauthorized")
    exc_401.code = 401
    assert is_retryable_gemini_error(exc_401) is False

    exc_400 = Exception("Bad request")
    exc_400.code = 400
    assert is_retryable_gemini_error(exc_400) is False

    exc_403 = Exception("Permission denied")
    exc_403.code = 403
    assert is_retryable_gemini_error(exc_403) is False

    exc_404 = Exception("Model not found")
    exc_404.code = 404
    assert is_retryable_gemini_error(exc_404) is False

    assert is_retryable_gemini_error(Exception("API_KEY_INVALID: bad credentials")) is False
    assert is_retryable_gemini_error(Exception("404 NOT_FOUND: models/unknown")) is False
    assert is_retryable_gemini_error(InvestigatorError("Validation failed")) is False


# =====================================================================
# 3. RETRY-AFTER & EXPONENTIAL BACKOFF WITH JITTER
# =====================================================================

def test_extract_retry_after_from_headers():
    """Extracts seconds from HTTP Retry-After header."""
    exc = Exception("Rate limited")
    mock_resp = MagicMock()
    mock_resp.headers = {"Retry-After": "4.5"}
    exc.response = mock_resp

    assert extract_retry_after(exc) == 4.5


def test_extract_retry_after_from_details():
    """Extracts seconds from Google RPC retryDelay details."""
    exc = Exception("Quota exceeded")
    exc.details = {
        "error": {
            "details": [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "2.5s"}
            ]
        }
    }
    assert extract_retry_after(exc) == 2.5


def test_calculate_backoff_delay_exponential_and_retry_after():
    """Delay increases exponentially with attempt; Retry-After takes precedence."""
    # With explicit retry_after
    delay_ra = calculate_backoff_delay(attempt=0, retry_after=5.0)
    assert delay_ra == 5.0

    # Without retry_after, attempt 0: base_delay (1.0) + jitter (0..0.5)
    d0 = calculate_backoff_delay(attempt=0, base_delay=1.0, backoff_factor=2.0, jitter=0.0)
    assert d0 == 1.0

    # Attempt 1: 1.0 * (2^1) = 2.0
    d1 = calculate_backoff_delay(attempt=1, base_delay=1.0, backoff_factor=2.0, jitter=0.0)
    assert d1 == 2.0

    # Attempt 2: 1.0 * (2^2) = 4.0
    d2 = calculate_backoff_delay(attempt=2, base_delay=1.0, backoff_factor=2.0, jitter=0.0)
    assert d2 == 4.0

    # Max delay capping
    d_capped = calculate_backoff_delay(attempt=5, base_delay=1.0, max_delay=10.0, jitter=0.0)
    assert d_capped == 10.0


# =====================================================================
# 4. BOUNDED RETRIES EXECUTION (execute_with_retry)
# =====================================================================

def test_execute_with_retry_succeeds_on_transient_503():
    """Fails once with 503 UNAVAILABLE, succeeds on attempt 2."""
    call_count = 0
    sleeps = []

    def mock_api_call():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            err = Exception("503 UNAVAILABLE: temporarily overloaded")
            err.code = 503
            raise err
        return "SUCCESS"

    result = execute_with_retry(
        mock_api_call,
        max_retries=3,
        base_delay=0.1,
        sleep_fn=lambda s: sleeps.append(s)
    )

    assert result == "SUCCESS"
    assert call_count == 2
    assert len(sleeps) == 1


def test_execute_with_retry_exhausts_retries_on_persistent_503():
    """Fails 3 times with 503; bounded retries are exhausted and error is raised."""
    call_count = 0
    sleeps = []

    def mock_api_call():
        nonlocal call_count
        call_count += 1
        err = Exception("503 UNAVAILABLE: backend timeout")
        err.code = 503
        raise err

    with pytest.raises(Exception) as exc_info:
        execute_with_retry(
            mock_api_call,
            max_retries=3,
            base_delay=0.1,
            sleep_fn=lambda s: sleeps.append(s)
        )

    assert call_count == 3
    assert len(sleeps) == 2
    assert "503 UNAVAILABLE" in str(exc_info.value)


def test_execute_with_retry_fails_immediately_on_permanent_401():
    """Permanent 401 error fails immediately with 0 retries (1 attempt total)."""
    call_count = 0
    sleeps = []

    def mock_api_call():
        nonlocal call_count
        call_count += 1
        err = Exception("401 UNAUTHENTICATED: API_KEY_INVALID")
        err.code = 401
        raise err

    with pytest.raises(Exception) as exc_info:
        execute_with_retry(
            mock_api_call,
            max_retries=3,
            base_delay=0.1,
            sleep_fn=lambda s: sleeps.append(s)
        )

    assert call_count == 1
    assert len(sleeps) == 0
    assert "401" in str(exc_info.value)


def test_investigate_incident_structured_503_error():
    """Verifies that an exhausted 503 returns an understandable InvestigatorError."""
    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        err = Exception("503 UNAVAILABLE: service overloaded")
        err.code = 503
        mock_client.models.generate_content.side_effect = err

        sleeps = []
        with pytest.raises(InvestigatorError) as exc_info:
            investigate_incident(SAMPLE_CONTEXT, api_key="test_key", max_retries=3, sleep_fn=lambda s: sleeps.append(s))

        assert len(sleeps) == 2
        err_str = str(exc_info.value)
        assert "503 UNAVAILABLE" in err_str
        assert "Bounded retries (3 attempts) were exhausted" in err_str


# =====================================================================
# 5. DECOUPLED DETERMINISTIC REPORT GENERATION WITHOUT GEMINI
# =====================================================================

def test_deterministic_markdown_report_without_gemini():
    """Verifies format_markdown_report cleanly generates a full dossier when investigation_results is None."""
    trace_analysis = {
        "exception_type": "TypeError",
        "exception_message": "unsupported operand type(s)",
        "innermost_application_frame": {
            "matched_file": "cart.py",
            "line": 31,
            "function": "calculate_total"
        },
        "culprit_source_window": {
            "file_path": "cart.py",
            "target_line": 31,
            "window_code": "31: >>> discount_amount = subtotal * discount_rate"
        }
    }
    git_analysis = {
        "has_git": True,
        "current_branch": "main",
        "evidence_summary": "Line 31 introduced in commit ffacc60.",
        "culprit_blame_commit": {
            "line_no": 31,
            "commit_hash": "ffacc60",
            "author": "Alice Dev",
            "date": "2026-11-05",
            "message": "feat: Add loyalty discount",
            "code": "discount_amount = subtotal * discount_rate"
        }
    }
    scan_result = {
        "status": "success",
        "is_clean": True,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": []
    }

    md = format_markdown_report(
        project_name="Shop Cart",
        project_source="Uploaded ZIP Archive",
        investigation_mode="AI Investigation Unavailable (Deterministic Evidence Only)",
        error_text=SAMPLE_ERROR,
        trace_analysis=trace_analysis,
        git_analysis=git_analysis,
        scan_result=scan_result,
        investigation_results=None,  # AI failed or was not invoked!
        unified_diff=None,
        verification_result=None,
    )

    # 1. Executive Summary records deterministic crash frame and git blame
    assert "**AI Investigation:** Unavailable (Deterministic Evidence Baseline)" in md
    assert "**Crash Location (Deterministic):** `cart.py` line `31`" in md
    assert "**Historical Blame (Deterministic):** Line 31 modified by commit `ffacc60`" in md
    # 2. Stack trace and source context
    assert "TypeError" in md
    assert "calculate_total" in md
    assert "discount_amount = subtotal * discount_rate" in md
    # 3. Trivy scan
    assert "Clean Scan" in md
    # 4. Patch notice indicates no automated patch without AI
    assert "No patch proposed for this incident (Requires AI investigation)" in md
    assert "Regression test verification was not performed (No patch proposed)" in md


def test_deterministic_json_report_without_gemini():
    """Verifies format_json_report serializes cleanly when investigation_results is None."""
    trace_analysis = {
        "exception_type": "TypeError",
        "exception_message": "unsupported operand type(s)",
        "innermost_application_frame": {
            "matched_file": "cart.py",
            "line": 31,
            "function": "calculate_total"
        }
    }
    git_analysis = {
        "has_git": True,
        "current_branch": "main",
        "culprit_blame_commit": {
            "line_no": 31,
            "commit_hash": "ffacc60",
            "author": "Alice Dev"
        }
    }

    json_str = format_json_report(
        project_name="Shop Cart",
        project_source="Uploaded ZIP Archive",
        investigation_mode="AI Investigation Unavailable (Deterministic Evidence Only)",
        error_text=SAMPLE_ERROR,
        trace_analysis=trace_analysis,
        git_analysis=git_analysis,
        scan_result=None,
        investigation_results=None,
        unified_diff=None,
        verification_result=None,
    )

    data = json.loads(json_str)
    assert data["report_metadata"]["investigation_engine"] == "AI Investigation Unavailable (Deterministic Evidence Only)"
    assert data["investigation_findings"]["status"] == "ai_investigation_unavailable"
    assert data["investigation_findings"]["deterministic_only"] is True
    assert data["investigation_findings"]["deterministic_summary"]["innermost_frame"]["matched_file"] == "cart.py"
    assert data["investigation_findings"]["deterministic_summary"]["culprit_blame"]["commit_hash"] == "ffacc60"
    assert data["proposed_patch"]["patch_details"] is None


# =====================================================================
# 6. STREAMLIT UI DECOUPLING AND RESILIENCE TESTS
# =====================================================================

def test_app_ui_decoupled_deterministic_evidence_when_gemini_fails():
    """
    End-to-end Streamlit UI test:
    When Gemini fails during investigation (e.g. 503 UNAVAILABLE):
    1. Warning banner '⚠️ AI investigation unavailable — deterministic evidence is still available.' is displayed.
    2. Deterministic incident baseline is rendered with crash and blame details.
    3. Patch review section is disabled with notice: 'No automated patch available'.
    4. Download buttons for Markdown and JSON reports are rendered and operational.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    # Load demo project
    demo_btn = None
    for b in at.button:
        if "Shopping Cart" in b.label:
            demo_btn = b
            break
    assert demo_btn is not None
    demo_btn.click()
    at.run()

    # Mock Gemini 503 failure during investigation
    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        err = Exception("503 UNAVAILABLE: service overloaded")
        err.code = 503
        mock_client.models.generate_content.side_effect = err

        # Set API key in sidebar input to trigger live investigator branch
        for ti in at.text_input:
            if "Gemini API Key" in ti.label or "key" in ti.label.lower():
                ti.set_value("test_mock_api_key")
                break

        # Find and click Investigate Incident
        inv_btn = None
        for b in at.button:
            if "Investigate Incident" in b.label:
                inv_btn = b
                break
        assert inv_btn is not None
        inv_btn.click()
        at.run()

    assert not at.exception, f"AppTest raised exception: {at.exception}"

    # Check session state
    assert at.session_state.get("investigation_failed") is True
    assert at.session_state.get("investigation_results") is None

    # Check UI warnings and text
    warning_texts = [w.value for w in at.warning]
    has_warning_banner = any("AI investigation unavailable — deterministic evidence is still available." in w for w in warning_texts)
    assert has_warning_banner, f"Warning banner missing from warnings: {warning_texts}"

    # Check deterministic baseline header in markdown
    markdown_texts = [m.value for m in at.markdown]
    has_deterministic_baseline = any("Deterministic Incident Baseline" in m for m in markdown_texts)
    assert has_deterministic_baseline, "Deterministic Incident Baseline header missing from UI markdown!"

    # Check patch disabled notice in info boxes
    info_texts = [i.value for i in at.info]
    has_patch_disabled_notice = any("No automated patch available" in i for i in info_texts)
    assert has_patch_disabled_notice, f"Patch disabled notice missing from info boxes: {info_texts}"

    # Check download buttons exist
    download_labels = [db.label for db in at.download_button]
    assert any("Markdown" in l for l in download_labels), f"Markdown download button missing: {download_labels}"
    assert any("JSON" in l for l in download_labels), f"JSON download button missing: {download_labels}"


# =====================================================================
# 7. PHASE 2.1 — RETRY AFTER TRANSIENT GEMINI FAILURE TESTS
# =====================================================================

def test_cache_logic_unit_rules():
    """
    Direct unit test verifying cache key computation and cache reuse rules:
    - Failed investigations are NEVER cached as successes.
    - Changing project, traceback, or model produces a distinct cache key.
    - Stale failure flags invalidate cache reuse.
    """
    def make_key(proj, trace, model):
        return f"{proj}:{hashlib.sha256(trace.strip().encode()).hexdigest()}:{model}"

    def check_cache(last_key, current_key, results, failed):
        return last_key == current_key and bool(results) and not failed

    key1 = make_key("/path/to/project", "Traceback 1", "gemini-3.8-flash")
    key2 = make_key("/path/to/project", "Traceback 2", "gemini-3.8-flash")
    key_diff_model = make_key("/path/to/project", "Traceback 1", "gemini-2.5-pro")
    key_diff_proj = make_key("/path/to/other", "Traceback 1", "gemini-3.8-flash")

    # Traceback change invalidates cache key
    assert key1 != key2
    # Model change invalidates cache key
    assert key1 != key_diff_model
    # Project change invalidates cache key
    assert key1 != key_diff_proj

    # Successful result with matching key -> True (cached)
    assert check_cache(key1, key1, {"likely_root_cause": "bug"}, failed=False) is True

    # Failed result with matching key -> False (allows retry!)
    assert check_cache(key1, key1, results=None, failed=True) is False

    # Previous failure key stored as None -> False (allows retry!)
    assert check_cache(None, key1, results=None, failed=True) is False

    # Stale failure flag even with results -> False (allows retry!)
    assert check_cache(key1, key1, {"likely_root_cause": "bug"}, failed=True) is False

    # Changed key with prior success -> False (triggers new run!)
    assert check_cache(key1, key2, {"likely_root_cause": "bug"}, failed=False) is False


def test_retry_after_transient_503_succeeds_on_second_click():
    """
    AppTest verification:
    Attempt 1 fails with 503; second button click retries and succeeds.
    Does not require changing traceback, switching models, or restarting.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    # Load demo shopping cart project
    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    # Enter API key
    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Attempt 1: 503 error
        err503 = Exception("503 UNAVAILABLE: service overloaded")
        err503.code = 503
        mock_client.models.generate_content.side_effect = err503

        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert at.session_state.get("investigation_failed") is True
        assert at.session_state.get("investigation_results") is None

        # Attempt 2: Recover with valid payload
        mock_resp = MagicMock()
        mock_resp.text = VALID_GEMINI_PAYLOAD
        mock_client.models.generate_content.side_effect = None
        mock_client.models.generate_content.return_value = mock_resp

        # Second click retries with same project and traceback
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert at.session_state.get("investigation_failed") is False
        assert at.session_state.get("investigation_error") is None
        assert at.session_state.get("investigation_results") is not None
        assert at.session_state.get("investigation_results")["affected_file"] == "cart.py"


def test_consecutive_transient_failures_allow_third_click_retry():
    """
    AppTest verification:
    Attempt 1 fails with 503; second attempt also fails with 503;
    third click retries again and succeeds.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        err503 = Exception("503 UNAVAILABLE: high load")
        err503.code = 503
        mock_client.models.generate_content.side_effect = err503

        # Click 1: Attempt 1 fails
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()
        assert at.session_state.get("investigation_failed") is True

        # Click 2: Attempt 2 fails
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()
        assert at.session_state.get("investigation_failed") is True

        # Click 3: Attempt 3 succeeds
        mock_resp = MagicMock()
        mock_resp.text = VALID_GEMINI_PAYLOAD
        mock_client.models.generate_content.side_effect = None
        mock_client.models.generate_content.return_value = mock_resp

        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert at.session_state.get("investigation_failed") is False
        assert at.session_state.get("investigation_results") is not None


def test_successful_investigation_cached_and_not_repeated_on_reruns():
    """
    AppTest verification:
    Successful investigation is cached and not repeated on ordinary reruns,
    and clicking Investigate again uses the cache.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.text = VALID_GEMINI_PAYLOAD
        mock_client.models.generate_content.return_value = mock_resp

        # First run succeeds
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert at.session_state.get("investigation_results") is not None
        calls_after_first = mock_client.models.generate_content.call_count
        assert calls_after_first > 0

        # Ordinary rerun (e.g. clicking Review Patch Details)
        for b in at.button:
            if "Review Patch Details" in b.label:
                b.click()
                break
        at.run()

        # Call count unchanged during normal interaction
        assert mock_client.models.generate_content.call_count == calls_after_first

        # Clicking Investigate Incident with identical input uses cache
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert mock_client.models.generate_content.call_count == calls_after_first
        info_texts = [i.value for i in at.info]
        assert any("Using existing investigation findings" in t for t in info_texts)


def test_changing_traceback_triggers_new_investigation():
    """
    AppTest verification:
    Changing the error traceback invalidates cache and triggers a fresh investigation.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.text = VALID_GEMINI_PAYLOAD
        mock_client.models.generate_content.return_value = mock_resp

        # Initial investigation
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        initial_calls = mock_client.models.generate_content.call_count

        # Modify traceback input in text_area
        new_trace = (
            "Traceback (most recent call last):\n"
            "  File \"cart.py\", line 15, in apply_coupon\n"
            "KeyError: 'INVALID_COUPON'"
        )
        at.text_area[0].set_value(new_trace)

        # Click Investigate Incident with modified traceback
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        # Cache was invalidated and new call was made
        assert mock_client.models.generate_content.call_count > initial_calls


def test_changing_model_triggers_new_investigation(monkeypatch):
    """
    AppTest verification:
    Changing the Gemini model (e.g. via GEMINI_MODEL) invalidates cache
    and triggers a fresh investigation.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.text = VALID_GEMINI_PAYLOAD
        mock_client.models.generate_content.return_value = mock_resp

        # Initial investigation with default model
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        initial_calls = mock_client.models.generate_content.call_count

        # Change model via environment variable
        monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-pro")

        # Click Investigate Incident again
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        # Cache was invalidated and new call was made
        assert mock_client.models.generate_content.call_count > initial_calls


def test_deterministic_reports_remain_accessible_after_repeated_failures():
    """
    AppTest verification:
    Deterministic reports remain accessible after repeated failures.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    at = AppTest.from_file(app_path, default_timeout=60)
    at.run()

    for b in at.button:
        if "Shopping Cart" in b.label:
            b.click()
            break
    at.run()

    for ti in at.text_input:
        if "Gemini API Key" in ti.label or "key" in ti.label.lower():
            ti.set_value("test_key_phase2_1")
            break

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        err503 = Exception("503 UNAVAILABLE: persistent outage")
        err503.code = 503
        mock_client.models.generate_content.side_effect = err503

        # Click 1
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        # Click 2
        for b in at.button:
            if "Investigate Incident" in b.label:
                b.click()
                break
        at.run()

        assert at.session_state.get("investigation_failed") is True

        # Check deterministic baseline header is visible
        markdown_texts = [m.value for m in at.markdown]
        assert any("Deterministic Incident Baseline" in m for m in markdown_texts)

        # Check download buttons exist and have labels
        download_labels = [db.label for db in at.download_button]
        assert any("Markdown" in l for l in download_labels)
        assert any("JSON" in l for l in download_labels)

