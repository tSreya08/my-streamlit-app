import os
import pytest
from unittest.mock import MagicMock, patch
from core.context_collector import collect_incident_context
from core.sandbox_runner import validate_patch, run_verification
from core.investigator import (
    InvestigatorError,
    get_api_key,
    build_investigation_prompt,
    parse_and_validate_response,
    investigate_incident,
    get_model_name,
    DEFAULT_MODEL
)

SAMPLE_ERROR = """Traceback (most recent call last):
  File "samples/shop_cart/test_cart.py", line 19, in test_standard_user_checkout
    assert cart.calculate_total(tax_rate=0.05) == 52.50
  File "samples/shop_cart/cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'
"""

VALID_GEMINI_PAYLOAD = """{
  "root_cause": "Missing default fallback in LOYALTY_DISCOUNTS dictionary lookup when user_tier is 'standard', causing discount_rate to evaluate to None.",
  "confidence": "High",
  "error_explanation": "In calculate_total (cart.py), line 30 looks up self.user_tier in LOYALTY_DISCOUNTS. Because 'standard' is not in the dictionary and no default fallback was provided to .get(), discount_rate becomes None. On line 31, multiplying subtotal * discount_rate raises TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'.",
  "evidence": [
    "cart.py:31 raises TypeError during subtotal * discount_rate",
    "cart.py:30 assigns discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier) which yields None for 'standard'",
    "Git diff for commit ffacc60 shows discount_rate calculation was introduced without a default 0.0 value"
  ],
  "historical_context": "Commit ffacc60 ('feat: Add loyalty discount calculation') introduced the loyalty discount lookup and total calculation. Subsequent commits added docstrings and receipt formatting without fixing the missing fallback.",
  "likely_introducing_commit": {
    "commit_hash": "ffacc60",
    "message": "feat: Add loyalty discount calculation",
    "author": "Alice Dev",
    "reasoning": "Commit ffacc60 introduced LOYALTY_DISCOUNTS and the calculate_total method where discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier) was written without default 0.0."
  },
  "proposed_patch": {
    "target_file": "cart.py",
    "original_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)",
    "replacement_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)",
    "explanation": "Provides a 0.0 default discount rate for non-loyalty or standard users, preventing discount_rate from becoming None."
  },
  "reasoning_summary": "1. Stack trace locates crash at cart.py line 31 on multiplication. 2. Variable analysis shows discount_rate is None because line 30 lacks a default. 3. Git blame and diff reveal commit ffacc60 introduced this pattern. 4. Adding 0.0 fallback resolves the issue.",
  "limitations": [
    "Assumes non-loyalty users should receive zero discount."
  ]
}"""


def test_missing_api_key_raises_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(InvestigatorError) as exc_info:
        get_api_key(None)
    assert "GEMINI_API_KEY is not configured" in str(exc_info.value)


def test_parse_and_validate_valid_response():
    result = parse_and_validate_response(VALID_GEMINI_PAYLOAD)
    assert result["root_cause"] != ""
    assert result["confidence"] == "High"
    assert result["likely_introducing_commit"]["commit_hash"] == "ffacc60"
    assert result["proposed_patch"]["target_file"] == "cart.py"
    assert "0.0" in result["proposed_patch"]["replacement_snippet"]


def test_parse_and_validate_markdown_wrapped_response():
    wrapped = f"```json\n{VALID_GEMINI_PAYLOAD}\n```"
    result = parse_and_validate_response(wrapped)
    assert result["likely_introducing_commit"]["commit_hash"] == "ffacc60"


def test_malformed_json_raises_error():
    with pytest.raises(InvestigatorError) as exc_info:
        parse_and_validate_response("This is definitely not valid json")
    assert "Failed to decode Gemini response as JSON" in str(exc_info.value)


def test_missing_required_keys_raises_error():
    incomplete = '{"root_cause": "A bug", "confidence": "Low"}'
    with pytest.raises(InvestigatorError) as exc_info:
        parse_and_validate_response(incomplete)
    assert "Response missing required keys" in str(exc_info.value)


def test_missing_patch_fields_raises_error():
    invalid_patch = """{
      "root_cause": "test",
      "confidence": "High",
      "error_explanation": "test",
      "evidence": ["e1"],
      "historical_context": "test",
      "likely_introducing_commit": {"commit_hash": "abc", "message": "m", "author": "a", "reasoning": "r"},
      "proposed_patch": {"target_file": "cart.py"},
      "reasoning_summary": "test",
      "limitations": ["none"]
    }"""
    with pytest.raises(InvestigatorError) as exc_info:
        parse_and_validate_response(invalid_patch)
    assert "'proposed_patch' missing required keys" in str(exc_info.value)


def test_build_investigation_prompt_includes_evidence():
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)
    prompt = build_investigation_prompt(context)

    # Check that prompt contains stack trace details
    assert "TypeError" in prompt
    assert "unsupported operand type" in prompt

    # Check source code inclusion
    assert "cart.py" in prompt
    assert "discount_amount = subtotal * discount_rate" in prompt

    # Check git history and blame inclusion
    assert "Commit:" in prompt
    assert "ffacc60" in prompt
    assert "feat: Add loyalty discount calculation" in prompt

    # Check distinction instruction
    assert "DISTINGUISH CRASH LINE VS. ROOT CAUSE LINE" in prompt
    assert "GROUNDING & EVIDENCE" in prompt


def test_end_to_end_mocked_investigation_and_sandbox_verification():
    """
    Tests the complete pipeline:
    1. Collect incident context from buggy sample.
    2. Run investigator with mocked Gemini response.
    3. Validate findings structure and attributes (commit ffacc60, fallback 0.0).
    4. Pass the proposed patch into sandbox_runner.
    5. Verify the patch passes validation and genuinely fixes the regression in pytest!
    """
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)

    mock_response = MagicMock()
    mock_response.text = VALID_GEMINI_PAYLOAD

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.return_value = mock_response

        findings = investigate_incident(context, api_key="mock_key_for_test")

    # 1. Verify investigator results
    assert findings["likely_introducing_commit"]["commit_hash"] == "ffacc60"
    assert "feat: Add loyalty discount calculation" in findings["likely_introducing_commit"]["message"]
    patch_proposal = findings["proposed_patch"]
    assert patch_proposal["target_file"] == "cart.py"
    assert "0.0" in patch_proposal["replacement_snippet"]

    # 2. Verify patch validation passes on the actual project
    valid, v_msg = validate_patch("samples/shop_cart", patch_proposal)
    assert valid is True, f"Patch validation failed: {v_msg}"

    # 3. Verify execution in sandbox produces REAL passing pytest result
    verify_result = run_verification("samples/shop_cart", patch_proposal, is_trusted=True)
    assert verify_result["ran_tests"] is True
    assert verify_result["passed"] is True
    assert verify_result["exit_code"] == 0
    assert "3 passed" in verify_result["stdout"]


@pytest.mark.skipif(not os.getenv("GEMINI_API_KEY"), reason="Live test requires GEMINI_API_KEY in environment")
def test_live_gemini_api_call():
    """
    Optional live integration test if user has configured GEMINI_API_KEY in .env.
    Uses gemini-3.8-flash model.
    """
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)
    findings = investigate_incident(context)
    assert findings["likely_introducing_commit"]["commit_hash"] != ""
    assert findings["proposed_patch"]["target_file"] == "cart.py"


def test_default_model_is_gemini_3_8_flash(monkeypatch):
    """DEFAULT_MODEL must be gemini-3.8-flash and get_model_name must return it by default."""
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert DEFAULT_MODEL == "gemini-3.8-flash"
    assert get_model_name() == "gemini-3.8-flash"


def test_get_model_name_precedence(monkeypatch):
    """Explicit model argument takes highest priority, then GEMINI_MODEL env var."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-pro")
    assert get_model_name() == "gemini-3.8-pro"
    assert get_model_name("custom-model-x") == "custom-model-x"


def test_deprecated_model_auto_migrated_to_3_8(monkeypatch):
    """Deprecated gemini-2.5-flash must automatically migrate to gemini-3.8-flash."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    assert get_model_name() == "gemini-3.8-flash"

    monkeypatch.setenv("GEMINI_MODEL", "models/gemini-2.5-flash")
    assert get_model_name() == "gemini-3.8-flash"

    # Explicit argument deprecated model also migrates
    assert get_model_name("gemini-2.5-flash") == "gemini-3.8-flash"


def test_investigate_incident_generation_config_sampling_params_removed():
    """
    Gemini 3.8 migration verification:
    GenerateContentConfig must NOT pass temperature, top_p, or top_k,
    and must pass response_mime_type='application/json'.
    """
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)
    mock_response = MagicMock()
    mock_response.text = VALID_GEMINI_PAYLOAD

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.return_value = mock_response

        findings = investigate_incident(context, api_key="test_key")

        # Verify call arguments
        call_kwargs = mock_client.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-3.8-flash"
        cfg = call_kwargs["config"]
        assert cfg.response_mime_type == "application/json"
        assert cfg.temperature is None
        assert cfg.top_p is None
        assert cfg.top_k is None


def test_investigate_incident_interactions_api_path(monkeypatch):
    """
    Evaluates and verifies Google's recommended Interactions API path
    when GEMINI_USE_INTERACTIONS_API is enabled.
    """
    monkeypatch.setenv("GEMINI_USE_INTERACTIONS_API", "true")
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)

    mock_interaction = MagicMock()
    mock_interaction.output_text = VALID_GEMINI_PAYLOAD

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.interactions.create.return_value = mock_interaction

        findings = investigate_incident(context, api_key="test_key")

        # Verify interactions.create was called
        mock_client.interactions.create.assert_called_once()
        call_kwargs = mock_client.interactions.create.call_args.kwargs
        assert call_kwargs["model"] == "gemini-3.8-flash"
        assert call_kwargs["response_mime_type"] == "application/json"
        assert findings["proposed_patch"]["target_file"] == "cart.py"


def test_investigate_incident_404_error_formatting():
    """Verify that a 404 NOT_FOUND error produces an informative, actionable message."""
    context = collect_incident_context("samples/shop_cart", SAMPLE_ERROR)

    with patch("core.investigator.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = Exception("404 NOT_FOUND: models/unknown is no longer available")

        with pytest.raises(InvestigatorError) as exc_info:
            investigate_incident(context, api_key="test_key", model="unknown")

        err = str(exc_info.value)
        assert "was not found or is unavailable" in err
        assert "gemini-3.8-flash" in err

