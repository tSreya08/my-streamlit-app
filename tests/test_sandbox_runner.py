import os
import json
import pytest
from core.sandbox_runner import (
    validate_patch,
    run_verification,
    run_tests_on_working_copy,
    safe_cleanup,
    get_sanitized_env,
    verify_trusted_origin,
    ORIGIN_MANIFEST_NAME
)
from core.patch_manager import create_working_copy, apply_patch_to_working_copy

VALID_PATCH = {
    "target_file": "cart.py",
    "original_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)",
    "replacement_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)"
}

INVALID_SNIPPET_PATCH = {
    "target_file": "cart.py",
    "original_snippet": "non_existent_code_line_here = 12345",
    "replacement_snippet": "x = 1"
}

PATH_TRAVERSAL_PATCH = {
    "target_file": "../outside.py",
    "original_snippet": "a = 1",
    "replacement_snippet": "a = 2"
}

def test_validate_patch():
    # Valid patch
    ok, msg = validate_patch("samples/shop_cart", VALID_PATCH)
    assert ok is True

    # Non-existent snippet
    ok, msg = validate_patch("samples/shop_cart", INVALID_SNIPPET_PATCH)
    assert ok is False
    assert "not found" in msg

    # Path traversal
    ok, msg = validate_patch("samples/shop_cart", PATH_TRAVERSAL_PATCH)
    assert ok is False
    assert "traversal" in msg or "outside" in msg

def test_security_blocking_for_untrusted():
    # Untrusted should be blocked from executing
    res = run_verification("samples/shop_cart", VALID_PATCH, is_trusted=False)
    assert res["ran_tests"] is False
    assert res["passed"] is False
    assert res["security_blocked"] is True
    assert "Arbitrary test execution is disabled" in res["message"]

def test_trusted_verification_passes_and_preserves_original():
    # Read original cart.py content
    with open("samples/shop_cart/cart.py", "r", encoding="utf-8") as f:
        orig_content = f.read()

    # Run verification on trusted sample
    res = run_verification("samples/shop_cart", VALID_PATCH, is_trusted=True)
    assert res["ran_tests"] is True
    assert res["passed"] is True
    assert res["exit_code"] == 0
    assert "3 passed" in res["stdout"]

    # Verify original file was NEVER mutated
    with open("samples/shop_cart/cart.py", "r", encoding="utf-8") as f:
        after_content = f.read()
    assert orig_content == after_content


def test_run_tests_on_working_copy_untrusted_blocked():
    res = run_tests_on_working_copy("samples/shop_cart", is_trusted=False)
    assert res["ran_tests"] is False
    assert res["passed"] is False
    assert res["status"] == "Verification not performed."
    assert res["security_blocked"] is True
    assert "Verification not performed" in res["message"]


def test_run_tests_on_working_copy_success_and_failure():
    # 1. Test failing run on unpatched working copy
    wc_failing = create_working_copy("samples/shop_cart")
    try:
        res_fail = run_tests_on_working_copy(wc_failing, is_trusted=True)
        assert res_fail["ran_tests"] is True
        assert res_fail["status"] == "Tests failed."
        assert res_fail["passed"] is False
        assert res_fail["exit_code"] != 0
        assert res_fail["tests_failed"] >= 1
        assert "FAILED" in res_fail["stdout"]
    finally:
        safe_cleanup(wc_failing)

    # 2. Test passing run on patched working copy
    wc_passing = create_working_copy("samples/shop_cart")
    try:
        ok, msg = apply_patch_to_working_copy(wc_passing, VALID_PATCH)
        assert ok is True
        res_pass = run_tests_on_working_copy(wc_passing, is_trusted=True)
        assert res_pass["ran_tests"] is True
        assert res_pass["status"] == "Tests passed."
        assert res_pass["passed"] is True
        assert res_pass["exit_code"] == 0
        assert res_pass["tests_passed"] == 3
        assert res_pass["tests_failed"] == 0
        assert res_pass["duration_seconds"] >= 0.0
        assert "3 passed" in res_pass["stdout"]
    finally:
        safe_cleanup(wc_passing)


def test_replayed_hmac_manifest_fails_authorization(tmp_path):
    # 1. Create a genuine working copy from samples/shop_cart
    genuine_wc = create_working_copy("samples/shop_cart")
    try:
        assert verify_trusted_origin(genuine_wc) is True

        # 2. Create another unrelated directory with some tests
        unrelated_dir = tmp_path / "unrelated_dir"
        unrelated_dir.mkdir()
        (unrelated_dir / "test_rogue.py").write_text("def test_rogue(): assert True\n", encoding="utf-8")

        # 3. Attempt replay attack: copy .phantom_origin.json from genuine_wc to unrelated_dir
        manifest_src = os.path.join(genuine_wc, ORIGIN_MANIFEST_NAME)
        manifest_dst = unrelated_dir / ORIGIN_MANIFEST_NAME
        manifest_dst.write_text(open(manifest_src, "r", encoding="utf-8").read(), encoding="utf-8")

        # 4. Verify that unrelated_dir fails origin verification despite having the genuine manifest
        assert verify_trusted_origin(str(unrelated_dir)) is False
        res = run_tests_on_working_copy(str(unrelated_dir), is_trusted=True)
        assert res["ran_tests"] is False
        assert res["status"] == "Verification not performed."
        assert res["security_blocked"] is True
        assert "Verification not performed" in res["message"]
    finally:
        safe_cleanup(genuine_wc)


def test_targeted_regression_test_injection():
    wc = create_working_copy("samples/shop_cart")
    try:
        ok, msg = apply_patch_to_working_copy(wc, VALID_PATCH)
        assert ok is True

        extra_test = "def test_extra_custom_rule():\n    assert ShoppingCart('standard').user_tier == 'standard'\n"
        res = run_tests_on_working_copy(wc, is_trusted=True, extra_test_code=extra_test, extra_test_file="test_cart.py")
        assert res["ran_tests"] is True
        assert res["status"] == "Tests passed."
        assert res["tests_passed"] == 4  # 3 base + 1 targeted
    finally:
        safe_cleanup(wc)



def test_sanitized_environment_excludes_secrets(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "SECRET_KEY_12345")
    monkeypatch.setenv("GITHUB_TOKEN", "SECRET_TOKEN_ABCDE")
    monkeypatch.setenv("DB_PASSWORD", "SECRET_PASSWORD_999")
    monkeypatch.setenv("CUSTOM_HOST_VAR", "HOST_VAL")

    env = get_sanitized_env()

    # Secrets must NEVER be exposed
    assert "GEMINI_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "DB_PASSWORD" not in env
    assert "CUSTOM_HOST_VAR" not in env

    # Necessary OS variables must be preserved on Windows
    assert "PATH" in env
    assert "SYSTEMROOT" in env
    assert env.get("PYTHONUTF8") == "1"


def test_defense_in_depth_blocks_untrusted_even_if_flagged_trusted(tmp_path):
    # Setup untrusted directory with test file
    untrusted_dir = tmp_path / "fake_repo"
    untrusted_dir.mkdir()
    (untrusted_dir / "test_fake.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

    # Even if is_trusted=True is passed, origin verification must reject it
    res = run_tests_on_working_copy(str(untrusted_dir), is_trusted=True)
    assert res["ran_tests"] is False
    assert res["security_blocked"] is True
    assert "Verification not performed" in res["message"]


def test_tampered_origin_manifest_is_rejected(tmp_path):
    # Attempt to spoof origin manifest
    spoofed_dir = tmp_path / "spoofed_repo"
    spoofed_dir.mkdir()
    manifest = spoofed_dir / ORIGIN_MANIFEST_NAME
    manifest.write_text(json.dumps({"source": "samples/shop_cart", "token": "FORGED_TOKEN"}), encoding="utf-8")

    assert verify_trusted_origin(str(spoofed_dir)) is False
    res = run_tests_on_working_copy(str(spoofed_dir), is_trusted=True)
    assert res["ran_tests"] is False
    assert res["security_blocked"] is True
    assert "Verification not performed" in res["message"]


def test_run_verification_blocks_untrusted_project_even_if_flagged_trusted(tmp_path):
    untrusted_dir = tmp_path / "untrusted_proj"
    untrusted_dir.mkdir()
    (untrusted_dir / "cart.py").write_text("x = 1\n", encoding="utf-8")

    fake_patch = {
        "target_file": "cart.py",
        "original_snippet": "x = 1",
        "replacement_snippet": "x = 2"
    }
    # Even if caller passes is_trusted=True on untrusted dir, it must be blocked
    res = run_verification(str(untrusted_dir), fake_patch, is_trusted=True)
    assert res["ran_tests"] is False
    assert res["security_blocked"] is True
    assert "Verification not performed" in res["message"]


