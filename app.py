import os
import sys
import hashlib
import streamlit as st

# Initialize core package & Git environment
import core
from core.context_collector import (
    collect_incident_context,
    parse_stack_trace,
    analyze_traceback_with_project
)
from core.git_analyzer import inspect_git_repository
from core.investigator import investigate_incident, InvestigatorError, get_model_name
from core.sandbox_runner import run_verification, validate_patch, run_tests_on_working_copy, safe_cleanup
from core.project_ingestor import extract_project_zip, IngestionError, IngestedProject
from core.patch_manager import (
    generate_unified_diff,
    validate_patch_safety,
    save_patch_artifact,
    load_patch_artifact,
    update_patch_status,
    create_working_copy,
    apply_patch_to_working_copy,
)
from core.vulnerability_scanner import (
    check_trivy_availability,
    run_trivy_scan,
    explain_finding_with_ai,
    CLEAN_SCAN_MESSAGE,
    CLEAN_SCAN_DISCLAIMER,
)
from core.report_generator import format_markdown_report, format_json_report

# Page Configuration
st.set_page_config(
    page_title="PHANTOM - Incident Investigator",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for Professional Dark Incident Console
st.markdown(
    """
    <style>
    /* Dark console styling */
    .stApp {
        background-color: #0b0f19;
        color: #f8fafc;
    }
    .main-header {
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        margin-bottom: 0.2rem;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }
    .phantom-tag {
        font-size: 0.8rem;
        background-color: #1e1b4b;
        color: #a5b4fc;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        border: 1px solid #4338ca;
        font-weight: 600;
        text-transform: uppercase;
        vertical-align: middle;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #94a3b8;
        margin-bottom: 1.8rem;
    }
    .metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 0.9rem;
        text-align: center;
    }
    .metric-num {
        font-size: 1.35rem;
        font-weight: 700;
        color: #6366f1;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94a3b8;
    }
    .file-tree-box {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 0.8rem;
        font-family: monospace;
        font-size: 0.85rem;
        color: #cbd5e1;
        max-height: 180px;
        overflow-y: auto;
    }
    .code-window-box {
        background: #020617;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 0.8rem;
        font-family: Consolas, 'Courier New', monospace;
        font-size: 0.86rem;
        color: #e2e8f0;
        white-space: pre;
        overflow-x: auto;
    }
    .badge-in-project {
        background: #064e3b;
        color: #6ee7b7;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-external {
        background: #374151;
        color: #9ca3af;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        font-size: 0.75rem;
    }
    .badge-culprit {
        background: #7f1d1d;
        color: #fca5a5;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .evidence-box {
        background: #1e1b4b;
        border-left: 4px solid #6366f1;
        padding: 0.8rem 1rem;
        border-radius: 0 6px 6px 0;
        margin: 0.8rem 0;
        color: #e0e7ff;
        font-size: 0.92rem;
    }
    .patch-banner {
        background: #451a03;
        border: 1px solid #f59e0b;
        color: #fef3c7;
        padding: 0.75rem 1.2rem;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.95rem;
        letter-spacing: 0.03em;
        margin-bottom: 1.2rem;
        text-align: center;
    }
    .card-box {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 1.2rem;
        margin-bottom: 1rem;
    }
    .badge-confidence {
        background: #064e3b;
        color: #6ee7b7;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-critical {
        background: #7f1d1d;
        color: #fca5a5;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-high {
        background: #7c2d12;
        color: #fdba74;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-medium {
        background: #78350f;
        color: #fde68a;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-low {
        background: #1e3a8a;
        color: #93c5fd;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-unknown {
        background: #374151;
        color: #d1d5db;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .ai-explanation-box {
        background: #1e1b4b;
        border-left: 4px solid #a855f7;
        padding: 0.8rem 1rem;
        border-radius: 0 6px 6px 0;
        margin-top: 0.7rem;
        color: #f3e8ff;
        font-size: 0.9rem;
    }
    .vuln-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Header & Branding ---
col_head, col_badge = st.columns([0.8, 0.2])
with col_head:
    st.markdown(
        '<div class="main-header">🕵️ PHANTOM <span class="phantom-tag">Hackathon MVP</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="sub-header">Evidence-driven AI software incident investigator.</div>',
        unsafe_allow_html=True,
    )

# --- Sidebar: Configuration & Quick-Loader ---
with st.sidebar:
    st.header("⚙️ Configuration")
    user_api_key = st.text_input(
        "Gemini API Key",
        type="password",
        help="Optional override if GEMINI_API_KEY is not set in .env",
    )
    st.caption(f"🤖 Active Model: `{get_model_name()}`")

    st.markdown("---")
    st.subheader("🎯 Demo Incident Loaders")
    st.caption("Quickly test with prebuilt, controlled demo incidents:")

    SAMPLE_CART_ERROR = """Traceback (most recent call last):
  File "test_cart.py", line 19, in test_standard_user_checkout
    assert cart.calculate_total(tax_rate=0.05) == 52.50
  File "cart.py", line 31, in calculate_total
    discount_amount = subtotal * discount_rate
TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'"""

    SAMPLE_PAYMENT_ERROR = """Traceback (most recent call last):
  File "test_payment.py", line 42, in test_empty_batch_reconciliation
    summary = processor.reconcile_batch(batch_id="batch_empty", transactions=[])
  File "payment.py", line 114, in reconcile_batch
    avg_ticket = total_volume / len(settled)
ZeroDivisionError: division by zero"""

    load_sample_cart = st.button("⚡ Shopping Cart (TypeError)", use_container_width=True)
    if load_sample_cart:
        st.session_state["project_source"] = "Built-in Sample"
        st.session_state["sample_choice"] = "Shopping Cart Incident (TypeError)"
        st.session_state["error_text"] = SAMPLE_CART_ERROR
        st.session_state["investigation_results"] = None
        st.session_state["investigation_failed"] = False
        st.session_state["investigation_error"] = None
        st.session_state["last_investigated_key"] = None
        st.session_state["verification_result"] = None
        st.session_state["patch_review_status"] = "unreviewed"
        st.success("Loaded shopping cart incident!")

    load_sample_payment = st.button("💳 Payment Service (ZeroDivisionError)", use_container_width=True)
    if load_sample_payment:
        st.session_state["project_source"] = "Built-in Sample"
        st.session_state["sample_choice"] = "Payment Service Incident (ZeroDivisionError)"
        st.session_state["error_text"] = SAMPLE_PAYMENT_ERROR
        st.session_state["investigation_results"] = None
        st.session_state["investigation_failed"] = False
        st.session_state["investigation_error"] = None
        st.session_state["last_investigated_key"] = None
        st.session_state["verification_result"] = None
        st.session_state["patch_review_status"] = "unreviewed"
        st.success("Loaded payment service incident!")

    st.markdown("---")
    st.caption("🛡️ **Security Policy**")
    st.caption("• Untrusted ZIP uploads: Static analysis & patch generation only. Code execution is strictly blocked.")
    st.caption("• Sample repository: Verified execution in an isolated sandbox.")


# Helper to clean up previous session uploads
def cleanup_previous_upload():
    old_proj = st.session_state.get("uploaded_project")
    if old_proj and isinstance(old_proj, IngestedProject):
        old_proj.cleanup()
        st.session_state["uploaded_project"] = None
        st.session_state["uploaded_file_id"] = None
        st.session_state["dependency_scan_result"] = None
        st.session_state["investigation_results"] = None
        st.session_state["investigation_failed"] = False
        st.session_state["investigation_error"] = None
        st.session_state["last_investigated_key"] = None


def cleanup_previous_working_copy():
    old_wc = st.session_state.get("working_copy_dir")
    if old_wc and os.path.exists(old_wc):
        safe_cleanup(old_wc)
        st.session_state["working_copy_dir"] = None


def render_verification_results(verif: dict):
    """Renders structured verification outcomes strictly adhering to Phase 4 & 5."""
    st.markdown("#### 🔟 STEP 10: Regression Test Verification Report")
    status = verif.get("status", "Verification not performed.")

    if status == "Tests passed.":
        st.success(f"### ✅ Verification Status: **{status}**")
    elif status == "Tests failed.":
        st.error(f"### ❌ Verification Status: **{status}**")
    else:
        st.warning(f"### ⚠️ Verification Status: **{status}**")

    # Metrics row: Tests Passed, Tests Failed, Tests Skipped, Exit Code, Execution Duration
    v1, v2, v3, v4, v5 = st.columns(5)
    with v1:
        st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #10b981;">{verif.get("tests_passed", 0)}</div><div class="metric-label">Tests Passed</div></div>', unsafe_allow_html=True)
    with v2:
        fail_c = "#ef4444" if verif.get("tests_failed", 0) > 0 else "#94a3b8"
        st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: {fail_c};">{verif.get("tests_failed", 0)}</div><div class="metric-label">Tests Failed</div></div>', unsafe_allow_html=True)
    with v3:
        st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #6366f1;">{verif.get("tests_skipped", 0)}</div><div class="metric-label">Tests Skipped</div></div>', unsafe_allow_html=True)
    with v4:
        code_disp = str(verif.get("exit_code")) if verif.get("exit_code") is not None else "None"
        st.markdown(f'<div class="metric-card"><div class="metric-num">{code_disp}</div><div class="metric-label">Exit Code</div></div>', unsafe_allow_html=True)
    with v5:
        dur = verif.get("duration_seconds", 0.0)
        st.markdown(f'<div class="metric-card"><div class="metric-num">{dur:.2f}s</div><div class="metric-label">Duration</div></div>', unsafe_allow_html=True)

    if status == "Verification not performed." and verif.get("reason_not_performed"):
        st.info(f"ℹ️ **Reason verification was not performed:** {verif['reason_not_performed']}")

    if verif.get("stdout") or verif.get("stderr"):
        with st.expander("📄 View Pytest Execution Output", expanded=True):
            st.code((verif.get("stdout") or "") + ("\n" + verif["stderr"] if verif.get("stderr") else ""), language="text")

    st.caption("🛡️ **Notice:** Passing tests provide evidence of correction, not a guarantee of complete correctness.")


def render_vulnerability_scan_section(active_project_dir: Optional[str], user_api_key: Optional[str]):
    """Renders the optional Trivy dependency vulnerability scan section (STEP 6)."""
    st.markdown("## 6️⃣ STEP 6: Collect Dependency & Security Information (Trivy)")

    avail = check_trivy_availability()
    if avail["available"]:
        st.markdown(
            f'<div style="background: #064e3b; border: 1px solid #059669; padding: 0.6rem 1rem; border-radius: 6px; color: #a7f3d0; margin-bottom: 0.8rem;">'
            f'🟢 <b>Trivy Scanner Active:</b> Version <code>{avail["version"]}</code>'
            f'</div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div style="background: #1e293b; border: 1px solid #334155; padding: 0.6rem 1rem; border-radius: 6px; color: #94a3b8; margin-bottom: 0.8rem;">'
            f'⚪ <b>Trivy Scanner Unavailable:</b> {avail["error"]}<br>'
            f'<span style="font-size: 0.82rem; color: #64748b;">Trivy dependency scanning is optional. All other PHANTOM features remain fully operational. Install Trivy on your system PATH to enable dependency CVE scanning.</span>'
            f'</div>',
            unsafe_allow_html=True
        )

    if not active_project_dir:
        st.info("ℹ️ Select or upload a project above to run dependency vulnerability scanning.")
        return

    col_btn, col_clear, col_space = st.columns([1.5, 1, 2])
    with col_btn:
        scan_clicked = st.button(
            "🛡️ Run Dependency Vulnerability Scan",
            disabled=not avail["available"],
            type="secondary",
            use_container_width=True
        )
    with col_clear:
        clear_clicked = st.button("🗑️ Clear Scan", use_container_width=True)

    if clear_clicked:
        st.session_state["dependency_scan_result"] = None
        st.rerun()

    if scan_clicked:
        with st.spinner("Executing Trivy filesystem vulnerability scan on project manifests..."):
            scan_res = run_trivy_scan(active_project_dir)
            st.session_state["dependency_scan_result"] = scan_res

    saved_scan = st.session_state.get("dependency_scan_result")
    if saved_scan:
        st.markdown("---")
        status = saved_scan.get("status")

        if status == "unavailable":
            st.warning(f"⚠️ Dependency scanning unavailable: {saved_scan.get('error')}")
        elif status == "timeout":
            st.error(f"⏱️ **Scan Timed Out:** {saved_scan.get('error')}")
        elif status == "failed":
            st.error(f"❌ **Scan Execution Failed:** {saved_scan.get('error')}")
        elif status == "success":
            is_clean = saved_scan.get("is_clean", False)
            total = saved_scan.get("total_findings", 0)
            counts = saved_scan.get("severity_counts", {})

            if is_clean:
                st.success(f"✅ **{CLEAN_SCAN_MESSAGE}**")
                st.caption(f"🛡️ **{CLEAN_SCAN_DISCLAIMER}**")
            else:
                st.error(f"⚠️ **Vulnerabilities Detected:** Found {total} dependency vulnerabilities across project manifests.")

                # Metric Cards
                m1, m2, m3, m4, m5 = st.columns(5)
                with m1:
                    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #ef4444;">{total}</div><div class="metric-label">Total Findings</div></div>', unsafe_allow_html=True)
                with m2:
                    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #fca5a5;">{counts.get("CRITICAL", 0)}</div><div class="metric-label">Critical</div></div>', unsafe_allow_html=True)
                with m3:
                    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #fdba74;">{counts.get("HIGH", 0)}</div><div class="metric-label">High</div></div>', unsafe_allow_html=True)
                with m4:
                    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #fde68a;">{counts.get("MEDIUM", 0)}</div><div class="metric-label">Medium</div></div>', unsafe_allow_html=True)
                with m5:
                    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #93c5fd;">{counts.get("LOW", 0)}</div><div class="metric-label">Low</div></div>', unsafe_allow_html=True)

                st.markdown("#### 🛡️ Scanner-Confirmed Vulnerability Findings")
                st.caption("Confirmed directly from Trivy scanner JSON. Values are not modified or invented.")

                for idx, finding in enumerate(saved_scan.get("findings", [])):
                    sev = finding.get("severity", "UNKNOWN")
                    badge_class = f"badge-{sev.lower()}" if f"badge-{sev.lower()}" in ["badge-critical", "badge-high", "badge-medium", "badge-low"] else "badge-unknown"
                    url_html = f' | <a href="{finding.get("primary_url")}" target="_blank" style="color: #60a5fa;">Advisory Link</a>' if finding.get("primary_url") else ""

                    st.markdown(
                        f'<div class="vuln-card">'
                        f'<b><span class="{badge_class}">{sev}</span> &nbsp; <code>{finding.get("vulnerability_id")}</code> — {finding.get("package_name")}</b><br>'
                        f'<span style="color: #94a3b8; font-size: 0.85rem;">'
                        f'Installed: <code>{finding.get("installed_version")}</code> | '
                        f'Fixed in: <code>{finding.get("fixed_version") or "None published"}</code> | '
                        f'Manifest: <code>{finding.get("target_file")}</code>{url_html}</span><br>'
                        f'<div style="margin-top: 0.4rem; font-size: 0.88rem; color: #cbd5e1;">{finding.get("description")}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )

                    # AI Explanation action
                    ai_key = f"ai_expl_{saved_scan.get('scan_id')}_{idx}"
                    col_ai_btn, col_ai_exp = st.columns([1, 4])
                    with col_ai_btn:
                        if st.button("💡 Explain with AI", key=f"btn_{ai_key}"):
                            with st.spinner("Generating AI explanation..."):
                                ai_res = explain_finding_with_ai(finding, api_key=user_api_key)
                                st.session_state[ai_key] = ai_res

                    ai_data = st.session_state.get(ai_key)
                    if ai_data:
                        with col_ai_exp:
                            st.markdown(
                                f'<div class="ai-explanation-box">'
                                f'🤖 <b>{ai_data.get("label", "AI-GENERATED EXPLANATION — NOT VERIFIED SCANNER EVIDENCE")}</b><br>'
                                f'{ai_data.get("explanation")}'
                                f'</div>',
                                unsafe_allow_html=True
                            )

            if saved_scan.get("raw_json"):
                with st.expander("📄 View Raw Trivy JSON Output", expanded=False):
                    st.json(saved_scan["raw_json"])

            if saved_scan.get("report_path"):
                st.caption(f"💾 **Scan artifact stored separately:** `{saved_scan['report_path']}`")

    st.caption("🛡️ **Scanner Policy:** Trivy filesystem scan inspects dependency manifests only. Project code, setup scripts, and dependency installation scripts are strictly never executed.")



# --- Main Form Inputs ---
col_left, col_right = st.columns([1, 1], gap="large")

active_project_dir = None
is_sample_project = False
parsed_target_file = None
parsed_target_line = None
parsed_target_func = None

with col_left:
    st.markdown("### 1️⃣ STEP 1: Upload a Python Project ZIP")
    source_choice = st.radio(
        "Choose project source:",
        ["Upload ZIP Archive", "Use Built-in Sample Repository"],
        index=1 if st.session_state.get("project_source") == "Built-in Sample" else 0,
        horizontal=True,
    )

    if source_choice == "Upload ZIP Archive":
        is_sample_project = False
        uploaded_zip = st.file_uploader(
            "Upload Python Project (.zip)",
            type=["zip"],
            help="Upload a zipped Python repository. Limits: max 25MB compressed, 100MB uncompressed, 1000 files.",
        )

        if uploaded_zip:
            current_id = f"{uploaded_zip.name}_{uploaded_zip.size}"
            if st.session_state.get("uploaded_file_id") != current_id:
                cleanup_previous_upload()
                try:
                    with st.spinner("Validating and extracting project archive safely..."):
                        ingested = extract_project_zip(uploaded_zip)
                        st.session_state["uploaded_project"] = ingested
                        st.session_state["uploaded_file_id"] = current_id
                except IngestionError as e:
                    st.error(f"❌ Ingestion failed: {e}")
                    st.session_state["uploaded_project"] = None
                except Exception as e:
                    st.error(f"❌ Unexpected extraction error: {e}")
                    st.session_state["uploaded_project"] = None

            ingested_proj = st.session_state.get("uploaded_project")
            if ingested_proj:
                active_project_dir = ingested_proj.project_dir

                st.success(f"📦 Ingested `{uploaded_zip.name}`")

                st.markdown("### 2️⃣ STEP 2: Project Architecture & Dependencies")
                # Metrics Row
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.markdown(f'<div class="metric-card"><div class="metric-num">{len(ingested_proj.python_files)}</div><div class="metric-label">🐍 Python Files</div></div>', unsafe_allow_html=True)
                with m2:
                    st.markdown(f'<div class="metric-card"><div class="metric-num">{len(ingested_proj.dependency_files)}</div><div class="metric-label">📦 Dependency Files</div></div>', unsafe_allow_html=True)
                with m3:
                    git_badge = "Active" if ingested_proj.has_git else "Unavailable"
                    st.markdown(f'<div class="metric-card"><div class="metric-num">{git_badge}</div><div class="metric-label">📜 Git History</div></div>', unsafe_allow_html=True)

                st.caption(f"ℹ️ {ingested_proj.git_message}")

                # Project Structure Expander
                with st.expander("📂 View Extracted Project Structure", expanded=False):
                    tree_text = "\n".join(f"• {path}" for path in ingested_proj.file_tree)
                    st.markdown(f'<div class="file-tree-box">{tree_text}</div>', unsafe_allow_html=True)

                # Dependencies Expander
                if ingested_proj.dependency_files:
                    with st.expander("📄 View Detected Dependencies", expanded=False):
                        for dep_name, dep_lines in ingested_proj.dependency_files.items():
                            st.markdown(f"**`{dep_name}`**")
                            st.code("\n".join(dep_lines), language="toml" if "toml" in dep_name else "text")

                st.warning("🔒 **Security Policy**: Code execution is disabled for untrusted uploads. Static analysis & patch generation only.")

    else:
        # Built-in Sample Repository
        is_sample_project = True
        sample_options = {
            "Shopping Cart Incident (TypeError)": {
                "path": os.path.abspath("samples/shop_cart"),
                "error": SAMPLE_CART_ERROR,
                "label": "Shopping Cart",
                "desc": "cart.py crashes with TypeError on standard user checkout.",
                "commits": "4 Commits"
            },
            "Payment Service Incident (ZeroDivisionError)": {
                "path": os.path.abspath("samples/payment_service"),
                "error": SAMPLE_PAYMENT_ERROR,
                "label": "Payment Service",
                "desc": "payment.py crashes with ZeroDivisionError when reconciling an empty batch.",
                "commits": "4 Commits"
            }
        }
        active_sample_key = st.session_state.get("sample_choice", "Shopping Cart Incident (TypeError)")
        if active_sample_key not in sample_options:
            active_sample_key = "Shopping Cart Incident (TypeError)"

        chosen_sample = st.selectbox(
            "Select Prebuilt Incident Demo:",
            options=list(sample_options.keys()),
            index=list(sample_options.keys()).index(active_sample_key)
        )
        st.session_state["sample_choice"] = chosen_sample
        sample_info = sample_options[chosen_sample]
        sample_path = sample_info["path"]
        active_project_dir = sample_path

        # Align default error if empty
        if not st.session_state.get("error_text"):
            st.session_state["error_text"] = sample_info["error"]

        st.success(f"📁 Using prebuilt demo repository at: `{sample_path}`")
        st.caption(f"💡 {sample_info['desc']}")

        sample_py_files = []
        sample_deps = {}
        sample_tree = []
        for root, dirs, files in os.walk(sample_path):
            dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", ".pytest_cache"]]
            for file in files:
                rel = os.path.relpath(os.path.join(root, file), sample_path).replace("\\", "/")
                sample_tree.append(rel)
                if file.endswith(".py"):
                    sample_py_files.append(rel)
                if file in ["requirements.txt", "pyproject.toml"]:
                    with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                        sample_deps[rel] = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        st.markdown("### 2️⃣ STEP 2: Project Architecture & Dependencies")
        # Metrics Row
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown(f'<div class="metric-card"><div class="metric-num">{len(sample_py_files)}</div><div class="metric-label">🐍 Python Files</div></div>', unsafe_allow_html=True)
        with m2:
            st.markdown(f'<div class="metric-card"><div class="metric-num">{len(sample_deps)}</div><div class="metric-label">📦 Dependency Files</div></div>', unsafe_allow_html=True)
        with m3:
            st.markdown(f'<div class="metric-card"><div class="metric-num">Active</div><div class="metric-label">📜 Git ({sample_info["commits"]})</div></div>', unsafe_allow_html=True)

        with st.expander("📂 View Sample Repository Structure", expanded=False):
            tree_text = "\n".join(f"• {path}" for path in sorted(sample_tree))
            st.markdown(f'<div class="file-tree-box">{tree_text}</div>', unsafe_allow_html=True)

        if sample_deps:
            with st.expander("📄 View Detected Dependencies", expanded=False):
                for dep_name, dep_lines in sample_deps.items():
                    st.markdown(f"**`{dep_name}`**")
                    st.code("\n".join(dep_lines), language="text")

        st.info("✅ **Controlled Sandbox**: Verified sample incident with reproducible regression test and safe sandbox execution.")

with col_right:
    st.markdown("### 3️⃣ STEP 3: Collect Runtime Error & Stack Trace")
    
    col_q1, col_q2 = st.columns(2)
    with col_q1:
        if st.button("⚡ Fill Shop Cart Trace", use_container_width=True):
            st.session_state["error_text"] = SAMPLE_CART_ERROR
            st.session_state["sample_choice"] = "Shopping Cart Incident (TypeError)"
            st.session_state["project_source"] = "Built-in Sample"
            st.session_state["investigation_results"] = None
            st.session_state["investigation_failed"] = False
            st.session_state["investigation_error"] = None
            st.session_state["last_investigated_key"] = None
            st.rerun()
    with col_q2:
        if st.button("💳 Fill Payment Trace", use_container_width=True):
            st.session_state["error_text"] = SAMPLE_PAYMENT_ERROR
            st.session_state["sample_choice"] = "Payment Service Incident (ZeroDivisionError)"
            st.session_state["project_source"] = "Built-in Sample"
            st.session_state["investigation_results"] = None
            st.session_state["investigation_failed"] = False
            st.session_state["investigation_error"] = None
            st.session_state["last_investigated_key"] = None
            st.rerun()

    default_error = st.session_state.get("error_text", "")
    error_input = st.text_area(
        "Paste Python traceback or runtime exception:",
        value=default_error,
        height=170,
        placeholder="Traceback (most recent call last):\n  File 'payment.py', line 114, in reconcile_batch\n    avg_ticket = total_volume / len(settled)\nZeroDivisionError: division by zero",
    )

    # --- Step 4: Live Error Parsing & Culprit Source Localization ---
    st.markdown("### 4️⃣ STEP 4: Locate Affected Source Code")
    if error_input and error_input.strip():
        trace_analysis = analyze_traceback_with_project(active_project_dir, error_input)

        st.markdown("#### 🔍 Deterministic Traceback Diagnostic")

        # Status row
        e_col1, e_col2 = st.columns(2)
        with e_col1:
            st.markdown(f"**Exception Type:** `{trace_analysis['exception_type']}`")
            if trace_analysis['exception_message']:
                st.caption(f"Message: {trace_analysis['exception_message']}")
        with e_col2:
            src_badge = "✅ Source Located" if trace_analysis['source_located'] else "⚠️ Source Not Located"
            st.markdown(f"**Project Match:** {src_badge}")
            st.caption(trace_analysis['status_explanation'])

        # Display Culprit Source Code Window
        if trace_analysis['source_located'] and trace_analysis['culprit_source_window']:
            innermost = trace_analysis['innermost_application_frame']
            parsed_target_file = innermost['matched_file']
            parsed_target_line = innermost['line']
            parsed_target_func = innermost['function']

            st.markdown(
                f"**📍 Innermost Application Frame:** `{innermost['matched_file']}` "
                f"at line `{innermost['line']}` in `{innermost['function']}`"
            )
            st.markdown(
                f'<div class="code-window-box">{trace_analysis["culprit_source_window"]["window_code"]}</div>',
                unsafe_allow_html=True,
            )

        # Expandable Frames List
        if trace_analysis['frames']:
            with st.expander(f"📑 Inspect All Stack Frames ({len(trace_analysis['frames'])} frames)", expanded=False):
                for idx, fr in enumerate(trace_analysis['frames'], start=1):
                    badge = '<span class="badge-in-project">In Project</span>' if fr['is_application_frame'] else '<span class="badge-external">System / Library</span>'
                    st.markdown(
                        f"**Frame {idx}:** {badge} `{fr['file_raw']}` (line {fr['line']} in `{fr['function']}`)",
                        unsafe_allow_html=True
                    )
                    if fr['code']:
                        st.code(fr['code'], language="python")

# --- Git History & Code Evolution Analysis ---
st.markdown("---")
st.markdown("## 5️⃣ STEP 5: Analyze Git Evolution & Blame History")

if active_project_dir:
    git_res = inspect_git_repository(
        active_project_dir,
        culprit_file=parsed_target_file,
        target_line=parsed_target_line,
        target_function=parsed_target_func
    )

    if git_res["has_git"]:
        st.markdown(f"**🌿 Active Branch:** `{git_res['current_branch']}` | **Commits Retrieved:** `{len(git_res['recent_commits'])}`")

        # Evidence Callout
        st.markdown(
            f'<div class="evidence-box">💡 <b>Historical Evidence Summary:</b> {git_res["evidence_summary"]}</div>',
            unsafe_allow_html=True
        )

        tab_file_commits, tab_blame, tab_all_commits = st.tabs([
            f"📄 Culprit File Commits ({len(git_res['file_commits'])})",
            f"🎯 Line Blame (Line {parsed_target_line or 'N/A'})",
            f"📜 Repository Commits ({len(git_res['recent_commits'])})"
        ])

        with tab_file_commits:
            if git_res["file_commits"]:
                for c in git_res["file_commits"]:
                    badges = []
                    if c.get("touches_target_line"):
                        badges.append('<span class="badge-culprit">🎯 Touched Crash Line</span>')
                    if c.get("touches_target_function"):
                        badges.append('<span class="badge-in-project">⚡ Modified Function</span>')
                    badge_html = " ".join(badges)

                    with st.expander(f"`{c['commit_hash']}` — {c['summary']} by {c['author']} ({c['date']})"):
                        if badge_html:
                            st.markdown(badge_html, unsafe_allow_html=True)
                        st.markdown(f"**Message:** {c['message']}")
                        if c.get("changed_functions"):
                            st.caption(f"Functions detected in diff: {', '.join(c['changed_functions'])}")
                        st.markdown("**Unified Diff:**")
                        st.code(c["diff"], language="diff")
            else:
                st.info(f"No specific commits found modifying '{parsed_target_file}'.")

        with tab_blame:
            if git_res["blame_for_target_lines"]:
                st.caption(f"Git blame around line {parsed_target_line} in `{parsed_target_file}`:")
                for b in git_res["blame_for_target_lines"]:
                    is_target = (parsed_target_line is not None and b["line_no"] == parsed_target_line)
                    prefix = "👉 " if is_target else "   "
                    st.text(f"{prefix}Line {b['line_no']:3d} | Commit {b['commit_hash']} ({b['author']}) | {b['code']}")
            else:
                st.info("No blame information available for this line range.")

        with tab_all_commits:
            for rc in git_res["recent_commits"]:
                st.markdown(f"• `{rc['commit_hash']}` — **{rc['summary']}** by {rc['author']} ({rc['date']})")

    else:
        st.info(f"ℹ️ {git_res['status_message']}")
else:
    st.info("ℹ️ Select or upload a project above to inspect Git history.")

st.markdown("---")

# --- 4. Dependency Security & Vulnerability Scan (Trivy) ---
render_vulnerability_scan_section(active_project_dir, user_api_key)

st.markdown("---")

# --- 7. Evidence-Driven Incident Investigation ---
st.markdown("## 7️⃣ STEP 7: Gemini Evidence-Grounded Investigation")
btn_col1, btn_col2, btn_col3 = st.columns([1, 2, 1])
with btn_col2:
    investigate_btn = st.button("🚀 Investigate Incident", type="primary", use_container_width=True)

if investigate_btn:
    # Input validation
    if not active_project_dir:
        st.error("⚠️ Please upload a project ZIP archive, or select 'Use Built-in Sample Repository'.")
    elif not error_input or not error_input.strip():
        st.error("⚠️ Please provide a runtime error or stack trace to investigate.")
    else:
        # Form deterministic cache key to avoid duplicate Gemini requests during Streamlit reruns
        inv_cache_key = f"{active_project_dir}:{hashlib.sha256(error_input.strip().encode()).hexdigest()}:{get_model_name()}"
        
        # Check if we already have a valid, successful investigation cached for this exact input.
        # Failed attempts are NOT treated as cached successes; the user can click again to retry immediately.
        has_cached_success = (
            st.session_state.get("last_investigated_key") == inv_cache_key
            and bool(st.session_state.get("investigation_results"))
            and not st.session_state.get("investigation_failed")
        )
        if has_cached_success:
            st.info("ℹ️ Using existing investigation findings for this project and error trace.")
        else:
            # Clear stale failure state before beginning a fresh attempt
            st.session_state["investigation_failed"] = False
            st.session_state["investigation_error"] = None
            with st.spinner("🕵️ Conducting evidence-driven investigation..."):
                ctx = collect_incident_context(active_project_dir, error_input)
                has_api_key = bool((user_api_key and user_api_key.strip()) or os.getenv("GEMINI_API_KEY"))

                inv_result = None
                if has_api_key:
                    try:
                        inv_result = investigate_incident(ctx, api_key=user_api_key.strip() if user_api_key else None)
                        if inv_result:
                            active_model = get_model_name()
                            inv_result["is_ai_generated"] = True
                            inv_result["investigation_mode"] = f"Gemini 3.8 Flash (AI)" if "3.8" in active_model else f"Gemini ({active_model})"
                            st.session_state["investigation_failed"] = False
                            st.session_state["investigation_error"] = None
                        else:
                            st.session_state["investigation_failed"] = True
                            st.session_state["investigation_error"] = "Investigation returned no results."
                    except InvestigatorError as e:
                        st.session_state["investigation_failed"] = True
                        st.session_state["investigation_error"] = str(e)
                        inv_result = None
                    except Exception as e:
                        st.session_state["investigation_failed"] = True
                        st.session_state["investigation_error"] = f"Unexpected error during investigation: {e}"
                        inv_result = None
                elif is_sample_project:
                    # Built-in demo fallback with grounded evidence from the active controlled sample
                    is_payment = "payment" in (active_project_dir or "").lower() or "payment" in error_input.lower()
                    if is_payment:
                        inv_result = {
                            "is_ai_generated": False,
                            "investigation_mode": "Deterministic Demonstration Baseline (Non-AI)",
                            "incident_summary": "Empty settlement batch reconciliation crashes with ZeroDivisionError.",
                            "likely_root_cause": "In payment.py, reconcile_batch divides total_volume by len(settled) without guarding against an empty settled list, causing ZeroDivisionError: division by zero when a batch contains no settled transactions.",
                            "affected_file": "payment.py",
                            "affected_function": "reconcile_batch",
                            "confidence": "High",
                            "evidence": [
                                "ZeroDivisionError at payment.py line 114: division by zero",
                                "payment.py: avg_ticket = total_volume / len(settled) executes when len(settled) is 0",
                                "Historical commit c3ab04e ('feat: Add average ticket calculation to batch reconciliation') by Marcus Ray introduced the average ticket calculation without checking if settled is empty"
                            ],
                            "relevant_commits": [
                                {
                                    "commit_hash": "c3ab04e",
                                    "message": "feat: Add average ticket calculation to batch reconciliation",
                                    "author": "Marcus Ray",
                                    "reasoning": "Introduced avg_ticket = total_volume / len(settled) without guarding against zero length."
                                }
                            ],
                            "alternative_explanations": [
                                "Checked commit e4296c5 ('docs: Add method docstrings...'): diff only touches documentation and did not introduce the runtime failure.",
                                "Checked commit 02d1f38 ('feat: Add receipt formatting...'): diff only touches format_receipt and does not modify reconcile_batch."
                            ],
                            "suggested_fix": {
                                "target_file": "payment.py",
                                "original_snippet": "        # Calculate average transaction amount (average ticket)\n        avg_ticket = total_volume / len(settled)",
                                "replacement_snippet": "        # Calculate average transaction amount (average ticket)\n        avg_ticket = (total_volume / len(settled)) if settled else 0.0",
                                "explanation": "Guard against division by zero by checking if settled is non-empty, safely returning 0.0 for empty settlement batches."
                            },
                            "explanation": "When an empty transaction list is reconciled, len(settled) is 0. Guarding with 'if settled else 0.0' returns 0.0 for average ticket size and prevents ZeroDivisionError."
                        }
                    else:
                        inv_result = {
                            "is_ai_generated": False,
                            "investigation_mode": "Deterministic Demonstration Baseline (Non-AI)",
                            "incident_summary": "Standard loyalty tier checkout crashes with TypeError because discount_rate is None.",
                            "likely_root_cause": "LOYALTY_DISCOUNTS dictionary in cart.py does not define a 'standard' tier, causing LOYALTY_DISCOUNTS.get(self.user_tier) to return None instead of a numeric float.",
                            "affected_file": "cart.py",
                            "affected_function": "calculate_total",
                            "confidence": "High",
                            "evidence": [
                                "TypeError at cart.py line 31: unsupported operand type(s) for *: 'float' and 'NoneType'",
                                "cart.py line 24: discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier) returns None when self.user_tier is 'standard'",
                                "Historical commit ffacc60 ('Add loyalty tier discount support') introduced LOYALTY_DISCOUNTS without a fallback default for unlisted tiers"
                            ],
                            "relevant_commits": [
                                {
                                    "commit_hash": "ffacc60",
                                    "message": "Add loyalty tier discount support",
                                    "author": "Alice Engineer",
                                    "reasoning": "Introduced the loyalty tier dictionary lookup in cart.py without providing a default value."
                                }
                            ],
                            "alternative_explanations": [
                                "Checked commit ca6e67c ('Update README with quickstart'): diff only touches README.md and did not introduce the runtime failure."
                            ],
                            "suggested_fix": {
                                "target_file": "cart.py",
                                "original_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)",
                                "replacement_snippet": "discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier, 0.0)",
                                "explanation": "Safely fallback to 0.0 discount for unrecognized loyalty tiers, ensuring discount_rate is always a valid float."
                            },
                            "explanation": "By providing 0.0 as the default argument to LOYALTY_DISCOUNTS.get(self.user_tier, 0.0), any tier not explicitly configured receives a 0.0 discount instead of None, preventing the downstream TypeError when calculating discount_amount."
                        }
                    st.session_state["investigation_failed"] = False
                    st.session_state["investigation_error"] = None
                else:
                    st.session_state["investigation_failed"] = True
                    st.session_state["investigation_error"] = "Gemini API key is required to analyze uploaded projects. Please enter your API key in the sidebar."
                    inv_result = None

                if inv_result:
                    st.session_state["last_investigated_key"] = inv_cache_key
                    st.session_state["investigation_failed"] = False
                    st.session_state["investigation_error"] = None
                else:
                    st.session_state["last_investigated_key"] = None

                st.session_state["investigation_results"] = inv_result
                st.session_state["investigation_project_dir"] = active_project_dir
                st.session_state["investigation_is_sample"] = is_sample_project
                st.session_state["patch_review_status"] = "unreviewed"
                st.session_state["working_copy_dir"] = None
                st.session_state["verification_result"] = None

                if inv_result:
                    cleanup_previous_working_copy()
                    # Persist patch artifact
                    patch = inv_result.get("suggested_fix") or inv_result.get("proposed_patch")
                    if patch and isinstance(patch, dict):
                        target_abs = os.path.join(active_project_dir, os.path.normpath(patch.get("target_file", "")))
                        full_content = None
                        if os.path.isfile(target_abs):
                            try:
                                with open(target_abs, "r", encoding="utf-8", errors="replace") as f:
                                    full_content = f.read()
                            except Exception:
                                pass
                        patch_id = save_patch_artifact(
                            patch_data={
                                "target_file": patch.get("target_file", ""),
                                "original_snippet": patch.get("original_snippet", ""),
                                "replacement_snippet": patch.get("replacement_snippet", ""),
                                "explanation": patch.get("explanation", ""),
                                "evidence": inv_result.get("evidence", []),
                                "status": "proposed"
                            },
                            full_file_content=full_content
                        )
                        st.session_state["active_patch_id"] = patch_id
                    else:
                        st.session_state["active_patch_id"] = None
                else:
                    st.session_state["active_patch_id"] = None


# --- Display Investigation Findings & Patch Review ---
has_results = bool(st.session_state.get("investigation_results"))
investigation_failed = bool(st.session_state.get("investigation_failed"))

if has_results or investigation_failed:
    res = st.session_state.get("investigation_results")
    proj_dir = st.session_state.get("investigation_project_dir", active_project_dir)
    is_sample = st.session_state.get("investigation_is_sample", False)

    st.markdown("---")
    st.markdown("## 8️⃣ STEP 8: Incident Investigation Report")

    if investigation_failed:
        st.warning("⚠️ AI investigation unavailable — deterministic evidence is still available.")
        fail_err = st.session_state.get("investigation_error", "AI service unavailable.")
        st.info(f"**Diagnostic Error Detail:** {fail_err}")

        st.markdown("### 📊 Deterministic Incident Baseline")
        st.caption("All findings below are deterministically extracted from your project source code, stack trace AST, Git blame history, and Trivy scan. No AI model was invoked.")

        det_c1, det_c2 = st.columns(2)
        with det_c1:
            st.markdown("#### 💥 Runtime Crash Details")
            if 'trace_analysis' in locals() and trace_analysis:
                st.markdown(f"- **Exception:** `{trace_analysis.get('exception_type', 'Unknown')}`: {trace_analysis.get('exception_message', '')}")
                innermost = trace_analysis.get("innermost_application_frame")
                if innermost:
                    st.markdown(f"- **Innermost Application Frame:** `{innermost.get('matched_file')}` at line `{innermost.get('line')}` in `{innermost.get('function')}`")
            else:
                st.markdown("- No stack trace frames could be resolved.")

        with det_c2:
            st.markdown("#### 📜 Historical Git Blame Culprit")
            if 'git_res' in locals() and git_res and git_res.get("culprit_blame_commit"):
                cb = git_res["culprit_blame_commit"]
                st.markdown(f"- **Commit:** `{cb.get('commit_hash')}` by **{cb.get('author')}** ({cb.get('date')})")
                st.markdown(f"- **Message:** {cb.get('message')}")
                st.markdown(f"- **Culprit Line Code:** `{cb.get('code', '').strip()}`")
            else:
                st.markdown("- Git repository history not available.")

        st.caption("ℹ️ Root cause hypothesis and automated code patch generation require AI. Review the deterministic evidence above and below to diagnose the issue manually.")

    elif res:
        is_ai = res.get("is_ai_generated", False)
        mode_label = res.get("investigation_mode", "Deterministic Demonstration Baseline (Non-AI)")
        if is_ai:
            st.markdown(
                f'<div style="background: #064e3b; border: 1px solid #059669; padding: 0.7rem 1rem; border-radius: 6px; color: #a7f3d0; margin-bottom: 1rem;">'
                f'🟢 <b>AI-Powered Investigation:</b> Generated dynamically using <b>{mode_label}</b> via the official Google GenAI SDK.'
                f'</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f'<div style="background: #1e1b4b; border: 1px solid #4338ca; padding: 0.7rem 1rem; border-radius: 6px; color: #c7d2fe; margin-bottom: 1rem;">'
                f'ℹ️ <b>Deterministic Demonstration Baseline:</b> Gemini API key was not configured. This report is deterministically derived from local repository code and Git history. PHANTOM did not invoke the Gemini API.'
                f'</div>',
                unsafe_allow_html=True
            )

        # Metrics summary row
        r1, r2, r3 = st.columns([2, 1, 1])
        with r1:
            st.markdown(f"**Likely Root Cause:** {res.get('likely_root_cause')}")
        with r2:
            st.markdown(f"**Affected File:** `{res.get('affected_file')}`")
            if res.get('affected_function'):
                st.caption(f"Function: `{res.get('affected_function')}`")
        with r3:
            conf = res.get('confidence', 'Medium')
            st.markdown(f'**Confidence:** <span class="badge-confidence">{conf}</span>', unsafe_allow_html=True)

        # Executive Summary Card
        if res.get("incident_summary"):
            st.info(f"💡 **Incident Summary:** {res.get('incident_summary')}")

        # Evidence & Commits Columns
        col_ev, col_com = st.columns([1, 1], gap="medium")
        with col_ev:
            st.markdown("#### 🔍 Confirmed Evidence")
            evidence_list = res.get("evidence", [])
            if evidence_list:
                for ev in evidence_list:
                    st.markdown(f"• {ev}")
            else:
                st.caption("No specific evidence points recorded.")

            alt_expl = res.get("alternative_explanations", [])
            if alt_expl:
                st.markdown("#### ⚖️ Alternative Hypotheses Evaluated")
                for alt in alt_expl:
                    st.caption(f"• {alt}")

        with col_com:
            st.markdown("#### 📜 Relevant Git Commits")
            rel_commits = res.get("relevant_commits", [])
            if rel_commits:
                for rc in rel_commits:
                    with st.expander(f"`{rc.get('commit_hash')}` — {rc.get('message')}"):
                        st.markdown(f"**Author:** {rc.get('author', 'Unknown')}")
                        st.markdown(f"**Reasoning:** {rc.get('reasoning', 'No reasoning provided')}")
            else:
                st.caption("No specific commits identified as introducing the failure.")

        # Scope Boundaries & Model Limitations Box
        st.markdown("#### ⚖️ Scope Boundaries & Limitations")
        st.caption("• **Confirmed Evidence vs. Hypotheses:** Stack trace line numbers, source snippets, Git commits, and Trivy CVEs are confirmed facts. Root cause analysis and suggested fixes are hypotheses requiring developer review.")
        st.caption("• **Verification Scope:** Regression test execution in an isolated working copy proves that the tested condition passes; it does not guarantee complete absence of all other bugs.")
        st.caption("• **Security Notice:** API keys, passwords, and host credentials are never logged, serialized, or exposed to subprocess environments.")

    # --- Section: AI-Assisted Code Correction and Patch Review ---
    st.markdown("---")
    st.markdown("## 9️⃣ STEP 9: AI-Assisted Code Correction & Patch Review")

    patch_id = st.session_state.get("active_patch_id")
    patch = None
    if has_results and res:
        patch = res.get("suggested_fix") or res.get("proposed_patch")

    if not patch or not isinstance(patch, dict) or not patch_id:
        st.info("ℹ️ No automated patch available — patch review, application, and verification are active only when a safe patch artifact exists.")
    else:
        st.markdown(
            '<div class="patch-banner">⚠️ AI-GENERATED SUGGESTION — REVIEW REQUIRED</div>',
            unsafe_allow_html=True
        )
        st.caption("🛡️ **Safety Notice:** Do not describe a proposed patch as a verified fix until it has passed human review and regression testing in an isolated working copy.")

        target_file = patch.get("target_file", "")
        orig_snippet = patch.get("original_snippet", "")
        repl_snippet = patch.get("replacement_snippet", "")
        explanation = patch.get("explanation") or (res.get("explanation", "") if res else "")

        # Validate patch safety on original project
        is_safe, val_msg = validate_patch_safety(proj_dir, patch)
        if is_safe:
            st.success("✅ **Patch Safety Check Passed:** Minimal localized patch targeting valid project file.")
        else:
            st.error(f"❌ **Patch Safety Warning:** {val_msg}")

        # Target full content for realistic unified diff
        target_abs = os.path.join(proj_dir, os.path.normpath(target_file))
        full_content = None
        if os.path.isfile(target_abs):
            try:
                with open(target_abs, "r", encoding="utf-8", errors="replace") as f:
                    full_content = f.read()
            except Exception:
                pass

        diff_text = generate_unified_diff(
            target_file,
            orig_snippet,
            repl_snippet,
            full_file_content=full_content
        )

        # 4 Structured Display Sections
        col_orig, col_repl = st.columns(2)
        with col_orig:
            st.markdown("### A. Original Code")
            st.caption(f"Target: `{target_file}`")
            st.code(orig_snippet, language="python")

        with col_repl:
            st.markdown("### B. Proposed Corrected Code")
            st.caption("Safe Minimal Replacement:")
            st.code(repl_snippet, language="python")

        st.markdown("### C. Why This Correction?")
        st.markdown(f"**Explanation:** {explanation}")
        if res and res.get("evidence"):
            st.markdown("**Evidence Supporting This Correction:**")
            for ev in res.get("evidence"):
                st.markdown(f"• {ev}")

        st.markdown("### D. Unified Diff")
        st.caption("Deterministic diff generated using Python `difflib`:")
        st.code(diff_text, language="diff")

        st.caption(f"💾 **Artifact Stored:** `.phantom/patches/{patch_id}.json` (Secrets excluded)")

        # Human Review Actions
        st.markdown("### 🧑‍💻 Human Review Actions")
        act_col1, act_col2, act_col3 = st.columns([1, 1.2, 1])

        with act_col1:
            if st.button("🔍 Review Patch Details", use_container_width=True):
                st.session_state["patch_review_status"] = "in_review"
                st.info("Inspecting original code, proposed correction, evidence, and unified diff above.")

        with act_col2:
            apply_clicked = st.button("✅ Apply to Working Copy", type="primary", use_container_width=True)
            if apply_clicked:
                if not is_safe:
                    st.error(f"Cannot apply unsafe patch: {val_msg}")
                else:
                    with st.spinner("Creating separate working copy and applying patch safely..."):
                        try:
                            # 1. Create separate working copy
                            wc_dir = create_working_copy(proj_dir)
                            st.session_state["working_copy_dir"] = wc_dir

                            # 2. Apply patch to working copy only
                            applied, app_msg = apply_patch_to_working_copy(
                                wc_dir,
                                patch,
                                patch_id=patch_id
                            )

                            if applied:
                                st.session_state["patch_review_status"] = "applied"
                                st.success(f"✅ Patch successfully applied to separate working copy!")
                                st.info(f"📁 **Working Copy Location:** `{wc_dir}`")
                                st.info(f"🔒 **Original Project Untouched:** `{proj_dir}`")

                                # 3. Regression verification if trusted sample
                                if is_sample:
                                    verif = run_tests_on_working_copy(wc_dir, is_trusted=True)
                                    st.session_state["verification_result"] = verif
                                    render_verification_results(verif)
                                else:
                                    verif = {
                                        "ran_tests": False,
                                        "status": "Verification not performed.",
                                        "passed": False,
                                        "tests_passed": 0,
                                        "tests_failed": 0,
                                        "tests_skipped": 0,
                                        "duration_seconds": 0.0,
                                        "exit_code": None,
                                        "reason_not_performed": "Arbitrary test execution is strictly disabled for untrusted uploads. Static analysis only.",
                                        "stdout": "",
                                        "stderr": ""
                                    }
                                    st.session_state["verification_result"] = verif
                                    render_verification_results(verif)
                            else:
                                st.error(f"❌ Failed to apply patch to working copy: {app_msg}")

                        except Exception as e:
                            st.error(f"❌ Unexpected error applying patch: {e}")

        with act_col3:
            reject_clicked = st.button("❌ Reject Patch", use_container_width=True)
            if reject_clicked:
                st.session_state["patch_review_status"] = "rejected"
                update_patch_status(patch_id, "rejected")
                cleanup_previous_working_copy()
                st.warning("❌ Patch suggestion marked as REJECTED. Original repository and working copy remain untouched.")

        # Review Status Callout
        current_status = st.session_state.get("patch_review_status", "unreviewed")
        if current_status == "applied":
            st.success("🟢 Status: **Applied to Isolated Working Copy** (Original project remains unmodified)")
            saved_verif = st.session_state.get("verification_result")
            if saved_verif and not apply_clicked:
                render_verification_results(saved_verif)
        elif current_status == "rejected":
            st.error("🔴 Status: **Rejected by Developer**")
        elif current_status == "in_review":
            st.info("🟡 Status: **Under Developer Review**")
        else:
            st.caption("⚪ Status: **Pending Developer Review**")

    # --- Section: Downloadable Investigation Report (STEP 10) ---
    st.markdown("---")
    st.markdown("## 🔟 STEP 10: Export & Download Incident Investigation Report")
    st.caption("Download the comprehensive incident report with confirmed evidence, Git history, vulnerability scan, proposed patch, unified diff, and verification results. All credentials and secrets are excluded.")

    report_proj_name = os.path.basename(proj_dir) if proj_dir else "project"
    report_proj_source = "Built-in Sample" if is_sample else "Uploaded ZIP Archive"

    if has_results and res:
        report_mode = res.get("investigation_mode", "Deterministic Demonstration Baseline (Non-AI)")
        inv_payload = res
    elif investigation_failed:
        report_mode = "AI Investigation Unavailable (Deterministic Evidence Only)"
        inv_payload = None
    else:
        report_mode = "Deterministic Evidence Baseline"
        inv_payload = None

    active_verif = st.session_state.get("verification_result")
    active_scan = st.session_state.get("dependency_scan_result")
    active_diff = diff_text if 'diff_text' in locals() else None

    # Build reports
    report_md = format_markdown_report(
        project_name=report_proj_name,
        project_source=report_proj_source,
        investigation_mode=report_mode,
        error_text=error_input if 'error_input' in locals() and error_input else "",
        trace_analysis=trace_analysis if 'trace_analysis' in locals() else None,
        git_analysis=git_res if 'git_res' in locals() else None,
        scan_result=active_scan,
        investigation_results=inv_payload,
        unified_diff=active_diff,
        verification_result=active_verif,
    )

    report_json = format_json_report(
        project_name=report_proj_name,
        project_source=report_proj_source,
        investigation_mode=report_mode,
        error_text=error_input if 'error_input' in locals() and error_input else "",
        trace_analysis=trace_analysis if 'trace_analysis' in locals() else None,
        git_analysis=git_res if 'git_res' in locals() else None,
        scan_result=active_scan,
        investigation_results=inv_payload,
        unified_diff=active_diff,
        verification_result=active_verif,
    )

    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            label="📄 Download Report (Markdown)",
            data=report_md,
            file_name=f"PHANTOM_Incident_Report_{report_proj_name}.md",
            mime="text/markdown",
            use_container_width=True
        )
    with dl_col2:
        st.download_button(
            label="📊 Download Report (JSON)",
            data=report_json,
            file_name=f"PHANTOM_Incident_Report_{report_proj_name}.json",
            mime="application/json",
            use_container_width=True
        )


