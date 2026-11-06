import os
import sys
import json
import pytest
import tempfile
import subprocess
from core.patch_manager import (
    generate_unified_diff,
    validate_patch_safety,
    save_patch_artifact,
    load_patch_artifact,
    list_patch_artifacts,
    update_patch_status,
    create_working_copy,
    apply_patch_to_working_copy,
    sanitize_patch_data
)
from core.sandbox_runner import safe_cleanup

SAMPLE_DIR = "samples/shop_cart"

VALID_DEMO_PATCH = {
    "target_file": "cart.py",
    "original_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)",
    "replacement_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)",
    "explanation": "Provides a safe fallback default of 0.0 for unknown tiers instead of returning None."
}


def test_valid_minimal_correction():
    ok, msg = validate_patch_safety(SAMPLE_DIR, VALID_DEMO_PATCH)
    assert ok is True
    assert "safe and valid" in msg.lower()


def test_unified_diff_generation():
    orig = "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)"
    repl = "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)"
    diff = generate_unified_diff("cart.py", orig, repl)

    assert "--- a/cart.py" in diff
    assert "+++ b/cart.py" in diff
    assert "-discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)" in diff
    assert "+discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)" in diff


def test_missing_original_snippet():
    bad_patch = {
        "target_file": "cart.py",
        "original_snippet": "non_existent_function_call_xyz(42)",
        "replacement_snippet": "pass"
    }
    ok, msg = validate_patch_safety(SAMPLE_DIR, bad_patch)
    assert ok is False
    assert "not found" in msg


def test_ambiguous_original_snippet(tmp_path):
    # Create file with duplicate lines
    p = tmp_path / "dup.py"
    p.write_text("x = 1\nx = 1\ny = 2\n", encoding="utf-8")

    ambiguous_patch = {
        "target_file": "dup.py",
        "original_snippet": "x = 1",
        "replacement_snippet": "x = 10"
    }
    ok, msg = validate_patch_safety(str(tmp_path), ambiguous_patch)
    assert ok is False
    assert "Ambiguous snippet" in msg or "matches 2 locations" in msg


def test_invalid_target_path():
    bad_patch = {
        "target_file": "non_existent_dir/nowhere.py",
        "original_snippet": "x = 1",
        "replacement_snippet": "x = 2"
    }
    ok, msg = validate_patch_safety(SAMPLE_DIR, bad_patch)
    assert ok is False
    assert "does not exist" in msg or "invalid" in msg.lower()


def test_path_traversal_attempts():
    traversal_patch = {
        "target_file": "../../etc/passwd",
        "original_snippet": "root",
        "replacement_snippet": "admin"
    }
    ok, msg = validate_patch_safety(SAMPLE_DIR, traversal_patch)
    assert ok is False
    assert "path traversal" in msg.lower() or "outside" in msg.lower()


def test_empty_replacement():
    empty_repl_patch = {
        "target_file": "cart.py",
        "original_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)",
        "replacement_snippet": "   \n  "
    }
    ok, msg = validate_patch_safety(SAMPLE_DIR, empty_repl_patch)
    assert ok is False
    assert "replacement_snippet" in msg and "empty" in msg.lower()


def test_malformed_patch():
    # Not a dict
    ok, msg = validate_patch_safety(SAMPLE_DIR, "not a patch")
    assert ok is False
    assert "dictionary" in msg

    # Missing target_file
    ok, msg = validate_patch_safety(SAMPLE_DIR, {"original_snippet": "a", "replacement_snippet": "b"})
    assert ok is False
    assert "target_file" in msg

    # Missing snippets
    ok, msg = validate_patch_safety(SAMPLE_DIR, {"target_file": "cart.py"})
    assert ok is False
    assert "must specify both" in msg


def test_whole_file_replacement_rejected(tmp_path):
    code = "\n".join([f"line_{i} = {i}" for i in range(20)])
    p = tmp_path / "long_module.py"
    p.write_text(code, encoding="utf-8")

    # Full file replacement
    whole_file_patch = {
        "target_file": "long_module.py",
        "original_snippet": code,
        "replacement_snippet": "# completely new code"
    }
    ok, msg = validate_patch_safety(str(tmp_path), whole_file_patch)
    assert ok is False
    assert "Whole-file replacement rejected" in msg


def test_stale_patch(tmp_path):
    p = tmp_path / "service.py"
    p.write_text("status = 'pending'\n", encoding="utf-8")

    stale_patch = {
        "target_file": "service.py",
        "original_snippet": "status = 'ready'",
        "replacement_snippet": "status = 'complete'"
    }

    ok, msg = apply_patch_to_working_copy(str(tmp_path), stale_patch)
    assert ok is False
    assert "stale" in msg.lower() or "not found" in msg.lower() or "validation failed" in msg.lower()


def test_patch_storage_and_retrieval(tmp_path):
    storage_dir = str(tmp_path / "test_patches")
    patch_data = {
        "target_file": "cart.py",
        "original_snippet": "x = 1",
        "replacement_snippet": "x = 2",
        "explanation": "Fix off-by-one",
        "evidence": ["Traced from line 10"],
        "secret_api_key": "SUPER_SECRET_VALUE_NEVER_PERSIST"
    }

    patch_id = save_patch_artifact(patch_data, storage_dir=storage_dir)
    assert patch_id.startswith("patch_")

    loaded = load_patch_artifact(patch_id, storage_dir=storage_dir)
    assert loaded["patch_id"] == patch_id
    assert loaded["target_file"] == "cart.py"
    assert loaded["label"] == "AI-GENERATED SUGGESTION — REVIEW REQUIRED"
    assert "secret_api_key" not in loaded  # Secrets must be sanitized

    # List artifacts
    all_patches = list_patch_artifacts(storage_dir=storage_dir)
    assert len(all_patches) == 1
    assert all_patches[0]["patch_id"] == patch_id

    # Update status
    updated = update_patch_status(patch_id, "rejected", storage_dir=storage_dir)
    assert updated is True
    reloaded = load_patch_artifact(patch_id, storage_dir=storage_dir)
    assert reloaded["status"] == "rejected"


def test_apply_patch_to_working_copy_preserves_original(tmp_path):
    # Setup source project
    source_dir = tmp_path / "original_project"
    source_dir.mkdir()
    f = source_dir / "calc.py"
    initial_code = "def calculate(a, b):\n    return a - b\n"
    f.write_text(initial_code, encoding="utf-8")

    # Create working copy
    working_copy = create_working_copy(str(source_dir))
    try:
        patch = {
            "target_file": "calc.py",
            "original_snippet": "return a - b",
            "replacement_snippet": "return a + b"
        }

        ok, msg = apply_patch_to_working_copy(working_copy, patch)
        assert ok is True

        # Check working copy has patched code
        with open(os.path.join(working_copy, "calc.py"), "r", encoding="utf-8") as wc_f:
            assert "return a + b" in wc_f.read()

        # Check ORIGINAL remained untouched
        with open(str(f), "r", encoding="utf-8") as orig_f:
            assert orig_f.read() == initial_code

    finally:
        safe_cleanup(working_copy)


def test_reject_correction_when_no_safe_patch(tmp_path):
    p = tmp_path / "module.py"
    p.write_text("x = 10\n", encoding="utf-8")

    unsafe_patch = {
        "target_file": "module.py",
        "original_snippet": "",
        "replacement_snippet": ""
    }
    ok, msg = validate_patch_safety(str(tmp_path), unsafe_patch)
    assert ok is False
    assert "empty" in msg


def test_end_to_end_controlled_demo_on_shop_cart():
    """
    End-to-end controlled demonstration:
    1. Verify original samples/shop_cart regression test fails initially.
    2. Read original cart.py content.
    3. Create separate working copy.
    4. Apply suggested patch to working copy.
    5. Run regression tests in working copy and verify tests PASS!
    6. Verify original samples/shop_cart cart.py is 100% untouched.
    """
    sample_path = os.path.abspath(SAMPLE_DIR)
    cart_file = os.path.join(sample_path, "cart.py")

    with open(cart_file, "r", encoding="utf-8") as f:
        original_cart_content = f.read()

    # 1. Verify original repository fails regression test
    init_res = subprocess.run(
        [sys.executable, "-m", "pytest", "."],
        cwd=sample_path,
        capture_output=True,
        text=True
    )
    assert init_res.returncode != 0
    assert "FAILED" in init_res.stdout or "FAILED" in init_res.stderr

    # 2. Create isolated working copy
    working_copy = create_working_copy(sample_path)
    try:
        # 3. Apply demo patch to working copy
        ok, msg = apply_patch_to_working_copy(working_copy, VALID_DEMO_PATCH)
        assert ok is True
        assert "Successfully applied patch" in msg

        # 4. Run pytest against working copy
        test_res = subprocess.run(
            [sys.executable, "-m", "pytest", "."],
            cwd=working_copy,
            capture_output=True,
            text=True
        )
        assert test_res.returncode == 0
        assert "3 passed" in test_res.stdout

        # 5. Verify original sample repo was NEVER modified
        with open(cart_file, "r", encoding="utf-8") as f:
            current_cart_content = f.read()
        assert current_cart_content == original_cart_content
    finally:
        safe_cleanup(working_copy)
