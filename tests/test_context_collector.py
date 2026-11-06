import os
import pytest
import core
from core.context_collector import (
    parse_stack_trace,
    find_file_in_project,
    get_source_window,
    analyze_traceback_with_project,
    collect_incident_context
)

# 1. ZeroDivisionError Traceback
TRACE_ZERO_DIVISION = """Traceback (most recent call last):
  File "payment.py", line 28, in calculate_discount
    discount = amount / total
ZeroDivisionError: division by zero"""

# 2. TypeError Traceback
TRACE_TYPE_ERROR = """Traceback (most recent call last):
  File "samples/shop_cart/test_cart.py", line 19, in test_standard_user_checkout
    assert cart.calculate_total(tax_rate=0.05) == 52.50
  File "samples/shop_cart/cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'"""

# 3. FileNotFoundError Traceback
TRACE_FILE_NOT_FOUND = """Traceback (most recent call last):
  File "config_loader.py", line 12, in load_settings
    with open("config.json", "r") as f:
FileNotFoundError: [Errno 2] No such file or directory: 'config.json'"""

# 4. Multi-frame trace with final frame in standard library
TRACE_WITH_STD_LIB = """Traceback (most recent call last):
  File "/workspace/src/api.py", line 45, in handle_request
    data = parse_payload(raw)
  File "/workspace/src/parser.py", line 12, in parse_payload
    return json.loads(raw)
  File "/usr/lib/python3.14/json/__init__.py", line 346, in loads
    return _default_decoder.decode(s)
  File "/usr/lib/python3.14/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)"""


def test_parse_zero_division_error():
    res = parse_stack_trace(TRACE_ZERO_DIVISION)
    assert res["traceback_parsed"] is True
    assert res["exception_type"] == "ZeroDivisionError"
    assert res["exception_message"] == "division by zero"
    assert len(res["frames"]) == 1
    assert res["frames"][0]["file"] == "payment.py"
    assert res["frames"][0]["line"] == 28
    assert res["frames"][0]["function"] == "calculate_discount"


def test_parse_type_error():
    res = parse_stack_trace(TRACE_TYPE_ERROR)
    assert res["traceback_parsed"] is True
    assert res["exception_type"] == "TypeError"
    assert "unsupported operand type" in res["exception_message"]
    assert len(res["frames"]) == 2
    assert res["frames"][1]["line"] == 31


def test_parse_file_not_found_error():
    res = parse_stack_trace(TRACE_FILE_NOT_FOUND)
    assert res["traceback_parsed"] is True
    assert res["exception_type"] == "FileNotFoundError"
    assert "No such file or directory" in res["exception_message"]
    assert res["frames"][0]["file"] == "config_loader.py"
    assert res["frames"][0]["line"] == 12


def test_windows_paths_and_paths_with_spaces():
    win_trace = """Traceback (most recent call last):
  File "C:\\My Projects\\e commerce\\cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'"""

    res = parse_stack_trace(win_trace)
    assert res["traceback_parsed"] is True
    assert res["frames"][0]["file"] == "C:\\My Projects\\e commerce\\cart.py"
    assert res["frames"][0]["line"] == 31

    # Test locating in samples/shop_cart by basename despite foreign absolute path with spaces
    matched = find_file_in_project("samples/shop_cart", res["frames"][0]["file"])
    assert matched is not None
    assert matched.endswith("cart.py")


def test_linux_paths():
    linux_trace = """Traceback (most recent call last):
  File "/var/app/backend/cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'"""

    res = parse_stack_trace(linux_trace)
    assert res["traceback_parsed"] is True
    assert res["frames"][0]["file"] == "/var/app/backend/cart.py"
    matched = find_file_in_project("samples/shop_cart", res["frames"][0]["file"])
    assert matched is not None
    assert matched.endswith("cart.py")


def test_innermost_application_frame_identification(tmp_path):
    # Setup temporary project with api.py and parser.py (mimicking user project)
    proj_dir = str(tmp_path)
    src_dir = os.path.join(proj_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    with open(os.path.join(src_dir, "api.py"), "w", encoding="utf-8") as f:
        f.write("# API\ndef handle_request(): pass\n")
    with open(os.path.join(src_dir, "parser.py"), "w", encoding="utf-8") as f:
        f.write("# Parser\ndef parse_payload(raw):\n    return json.loads(raw)\n")

    analysis = analyze_traceback_with_project(proj_dir, TRACE_WITH_STD_LIB)

    assert analysis["traceback_parsed"] is True
    # All 4 frames must be preserved
    assert len(analysis["frames"]) == 4

    # Frame 0 and 1 are in project
    assert analysis["frames"][0]["is_application_frame"] is True
    assert analysis["frames"][1]["is_application_frame"] is True

    # Frame 2 and 3 are standard library json files, NOT in user project
    assert analysis["frames"][2]["is_application_frame"] is False
    assert analysis["frames"][3]["is_application_frame"] is False

    # Innermost application frame must be frame 1 (parser.py), not frame 3!
    innermost = analysis["innermost_application_frame"]
    assert innermost is not None
    assert innermost["matched_file"] == "src/parser.py" or innermost["matched_file"] == "src\\parser.py"
    assert innermost["line"] == 12


def test_malformed_and_incomplete_tracebacks():
    # 1. Bare error message with no stack frames
    bare_error = "ZeroDivisionError: division by zero"
    res1 = parse_stack_trace(bare_error)
    assert res1["traceback_parsed"] is True
    assert res1["has_frames"] is False
    assert res1["exception_type"] == "ZeroDivisionError"
    assert res1["exception_message"] == "division by zero"

    # 2. Incomplete trace (has frame, but missing exception line)
    incomplete_trace = """Traceback (most recent call last):
  File "cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate"""
    res2 = parse_stack_trace(incomplete_trace)
    assert res2["traceback_parsed"] is True
    assert len(res2["frames"]) == 1
    assert res2["exception_type"] == "UnknownError"

    # 3. Completely random non-traceback text
    random_text = "2026-11-05 20:00:00 INFO Server started on port 8000"
    res3 = parse_stack_trace(random_text)
    assert res3["traceback_parsed"] is False
    assert res3["has_frames"] is False
    assert res3["exception_type"] == "UnknownError"


def test_source_code_window_extraction_and_marker():
    analysis = analyze_traceback_with_project("samples/shop_cart", TRACE_TYPE_ERROR)

    assert analysis["traceback_parsed"] is True
    assert analysis["source_located"] is True
    window = analysis["culprit_source_window"]
    assert window is not None
    assert window["found"] is True
    assert window["line_valid"] is True
    assert window["target_line"] == 31
    assert ">> CRASH >>" in window["window_code"]
    assert "discount_amount = subtotal * discount_rate" in window["window_code"]


def test_missing_file_explanation():
    missing_trace = """Traceback (most recent call last):
  File "non_existent_module.py", line 55, in execute
    run()
ValueError: invalid configuration"""
    analysis = analyze_traceback_with_project("samples/shop_cart", missing_trace)

    assert analysis["traceback_parsed"] is True
    assert analysis["source_located"] is False
    assert analysis["innermost_application_frame"] is None
    assert "none of the referenced files were found" in analysis["status_explanation"]


def test_path_traversal_prevention_in_file_lookup():
    # Attempt to traverse outside project directory
    traversal_ref = "../../test_sandbox_runner.py"
    matched = find_file_in_project("samples/shop_cart", traversal_ref)
    assert matched is None
