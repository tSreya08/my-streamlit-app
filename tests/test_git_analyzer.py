import os
import pytest
from core.git_analyzer import parse_diff_hunks, inspect_git_repository


def test_parse_diff_hunks():
    sample_diff = """@@ -10,3 +16,11 @@ class ShoppingCart:
 
     def get_subtotal(self) -> float:
         return sum(item["price"] * item["quantity"] for item in self.items)
+
+    def calculate_total(self, tax_rate: float = 0.05) -> float:
+        subtotal = self.get_subtotal()
+        discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)
+        discount_amount = subtotal * discount_rate
+        tax_amount = (subtotal - discount_amount) * tax_rate
+        return round((subtotal - discount_amount) + tax_amount, 2)
"""
    hunks = parse_diff_hunks(sample_diff)
    assert len(hunks) == 1
    h = hunks[0]
    assert h["old_start"] == 10
    assert h["new_start"] == 16
    assert h["new_count"] == 11
    assert "class ShoppingCart" in h["function_heading"]
    assert len(h["added_lines"]) > 0
    assert any("calculate_total" in line for line in h["added_lines"])


def test_git_analysis_unavailable_without_git(tmp_path):
    empty_dir = str(tmp_path)
    res = inspect_git_repository(empty_dir, culprit_file="app.py", target_line=10)
    assert res["has_git"] is False
    assert "No Git repository found" in res["status_message"]
    assert res["recent_commits"] == []
    assert res["file_commits"] == []


def test_git_analysis_on_shop_cart_sample():
    sample_dir = os.path.abspath("samples/shop_cart")
    res = inspect_git_repository(
        project_dir=sample_dir,
        culprit_file="cart.py",
        target_line=31,
        target_function="calculate_total"
    )

    # 1. Branch and general commits
    assert res["has_git"] is True
    assert res["current_branch"] in ["master", "main"]
    assert len(res["recent_commits"]) == 4

    # Verify latest commit is innocent receipt formatting
    latest = res["latest_commit"]
    assert latest is not None
    assert "feat: Add order receipt formatting" in latest["message"]

    # 2. File-specific commits
    assert len(res["file_commits"]) == 4
    messages = [c["message"] for c in res["file_commits"]]
    assert any("feat: Add loyalty discount calculation" in m for m in messages)
    assert any("docs: Add method docstrings" in m for m in messages)

    # 3. Blame at target line 31 points to commit ffacc60 (loyalty discount calculation)
    blame_culprit = res["culprit_blame_commit"]
    assert blame_culprit is not None
    assert blame_culprit["line_no"] == 31
    assert "feat: Add loyalty discount calculation" in blame_culprit["message"]
    assert blame_culprit["commit_hash"] != latest["commit_hash"]

    # 4. Evidence summary explicitly distinguishes latest commit from introducing commit
    assert "did NOT modify the failing line" in res["evidence_summary"]

    # 5. Correlated commits
    assert len(res["correlated_commits"]) > 0
    correlated_msgs = [c["message"] for c in res["correlated_commits"]]
    assert any("feat: Add loyalty discount calculation" in m for m in correlated_msgs)
