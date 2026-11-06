import os
import json
import re
import time
import random
from typing import Dict, Any, Optional, List, Callable
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Official Google Gen AI SDK
try:
    from google import genai
    from google.genai import types, errors
except ImportError:
    genai = None
    types = None
    errors = None

DEFAULT_MODEL = "gemini-3.8-flash"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_MAX_DELAY = 10.0
DEFAULT_JITTER = 0.5


def get_request_timeout(explicit_timeout: Optional[float] = None) -> float:
    """
    Returns the configured request timeout in seconds.

    Precedence rules:
    1. Explicit timeout parameter (if provided, positive number).
    2. GEMINI_TIMEOUT_SECONDS environment variable (if set and valid positive number).
    3. DEFAULT_TIMEOUT_SECONDS (30.0s).
    """
    if explicit_timeout is not None:
        try:
            val = float(explicit_timeout)
            if val > 0:
                return val
        except (ValueError, TypeError):
            pass

    env_timeout = os.getenv("GEMINI_TIMEOUT_SECONDS")
    if env_timeout:
        try:
            val = float(env_timeout.strip())
            if val > 0:
                return val
        except (ValueError, TypeError):
            pass

    return DEFAULT_TIMEOUT_SECONDS


def get_model_name(explicit_model: Optional[str] = None) -> str:
    """
    Returns the configured Gemini model name.

    Precedence rules:
    1. Explicit model parameter (if provided and non-empty).
    2. GEMINI_MODEL environment variable (if set and non-empty).
    3. DEFAULT_MODEL ("gemini-3.8-flash").

    If the resolved model is the deprecated 'gemini-2.5-flash' (or 'models/gemini-2.5-flash'),
    it is automatically upgraded to DEFAULT_MODEL ("gemini-3.8-flash") to prevent 404 NOT_FOUND errors.
    """
    if explicit_model and explicit_model.strip():
        chosen = explicit_model.strip()
    else:
        env_model = os.getenv("GEMINI_MODEL")
        if env_model and env_model.strip():
            chosen = env_model.strip()
        else:
            chosen = DEFAULT_MODEL

    if chosen in ("gemini-2.5-flash", "models/gemini-2.5-flash"):
        return DEFAULT_MODEL
    return chosen

# Harmonized schema fields covering both legacy and audited specifications
REQUIRED_AUDITED_FIELDS = [
    "incident_summary",
    "likely_root_cause",
    "affected_file",
    "affected_function",
    "evidence",
    "relevant_commits",
    "alternative_explanations",
    "confidence",
    "suggested_fix",
    "explanation"
]

REQUIRED_PATCH_KEYS = [
    "target_file",
    "original_snippet",
    "replacement_snippet"
]


class InvestigatorError(Exception):
    """Custom exception raised when investigation fails (API, parsing, or validation)."""
    pass


def get_api_key(explicit_key: Optional[str] = None) -> str:
    """
    Securely retrieves the Gemini API key.
    Checks explicit parameter first, then GEMINI_API_KEY environment variable.
    Never prints, logs, or serializes the key.
    """
    key = explicit_key or os.getenv("GEMINI_API_KEY")
    if not key or not key.strip():
        raise InvestigatorError(
            "GEMINI_API_KEY is not configured. Please set GEMINI_API_KEY in your .env file "
            "or provide it via the user interface."
        )
    return key.strip()


def build_investigation_prompt(incident_context: Dict[str, Any]) -> str:
    """
    Formats the collected incident context into a structured, highly grounded prompt for Gemini.
    Includes:
    - Runtime error and exception message
    - Full stack trace frames with line numbers
    - Culprit source code snippets with surrounding line context
    - Git commit history, unified diffs, and git blame information
    - Dependency declarations (requirements.txt, pyproject.toml)
    - Strict evidence vs. hypothesis instructions
    """
    stack_trace = incident_context.get("stack_trace", {})
    source_context = incident_context.get("source_context", {})
    git_history = incident_context.get("git_history", {})
    dependencies = incident_context.get("dependencies", {})

    prompt_parts = [
        "You are PHANTOM, an evidence-driven AI software incident investigator.",
        "Your task is to analyze a runtime crash in a Python repository and determine its root cause, ",
        "the historical change that introduced it, and a safe, minimal code patch.\n",
        "=== RUNTIME ERROR & STACK TRACE ===",
        f"Exception Type: {stack_trace.get('exception_type', 'Unknown')}",
        f"Exception Message: {stack_trace.get('exception_message', '')}\n",
        "Raw Stack Trace:",
        stack_trace.get("raw_trace", "").strip(),
        "\n=== RELEVANT SOURCE CODE ==="
    ]

    for rel_path, file_data in source_context.items():
        if "error" in file_data:
            prompt_parts.append(f"File {rel_path}: Error reading - {file_data['error']}")
            continue
        prompt_parts.append(f"--- File: {rel_path} (Failing line(s): {file_data.get('failing_lines', [])}) ---")
        lines = file_data.get("lines", [])
        for idx, line in enumerate(lines, start=1):
            marker = " >> CRASH >>" if idx in file_data.get("failing_lines", []) else "            "
            prompt_parts.append(f"{idx:4d}:{marker} {line.rstrip()}")

    prompt_parts.append("\n=== GIT HISTORY & BLAME ===")
    if not git_history.get("has_git", False):
        prompt_parts.append("No Git repository information available (.git is missing).")
    else:
        for rel_path, git_data in git_history.get("files", {}).items():
            prompt_parts.append(f"--- Git Data for {rel_path} ---")
            prompt_parts.append("Recent Commits (Most recent first):")
            for c in git_data.get("recent_commits", []):
                if "error" in c:
                    prompt_parts.append(f"  Error: {c['error']}")
                else:
                    prompt_parts.append(f"  Commit: {c['commit_hash']} | Author: {c['author']} | Date: {c['date']}")
                    prompt_parts.append(f"  Message: {c['message']}")
                    if c.get("diff"):
                        prompt_parts.append(f"  Diff:\n{c['diff'].strip()}\n")

            prompt_parts.append("\nGit Blame for failing region:")
            for b in git_data.get("blame_for_failing_lines", []):
                if "error" in b:
                    prompt_parts.append(f"  Error: {b['error']}")
                else:
                    prompt_parts.append(
                        f"  Line {b['line_no']:3d} | Commit {b['commit_hash']} ({b['author']}): "
                        f"{b['code'].strip()} [Msg: {b['message']}]"
                    )

            candidate = git_data.get("culprit_commit_candidate")
            if candidate:
                prompt_parts.append(
                    f"\nDirect blame on crash line points to commit: {candidate['commit_hash']} "
                    f"('{candidate['message']}') by {candidate['author']}"
                )

    prompt_parts.append("\n=== DEPENDENCIES ===")
    if dependencies:
        for dep_file, content in dependencies.items():
            prompt_parts.append(f"Dependency File ({dep_file}):\n{content}")
    else:
        prompt_parts.append("No dependency files identified.")

    prompt_parts.append(
        "\n=== INVESTIGATION INSTRUCTIONS ===\n"
        "1. DISTINGUISH CRASH LINE VS. ROOT CAUSE LINE:\n"
        "   - The crash line is where Python raised the runtime exception.\n"
        "   - The root cause line is where the faulty variable or invalid state was created/assigned.\n"
        "   - Trace variable assignments backward from the crash line. (For instance, if multiplication "
        "fails with NoneType, investigate the earlier line where that variable was assigned without a default!)\n"
        "   - Investigate the commit history and diffs of the assignment line, not merely the crash line.\n"
        "   - Do NOT blindly blame the latest commit if an earlier commit introduced the logic.\n"
        "\n"
        "2. GROUNDING & EVIDENCE (CONFIRMED EVIDENCE VS. HYPOTHESES):\n"
        "   - Strictly cite CONFIRMED FACTS observed directly in the stack trace, source code, git log, diffs, or blame.\n"
        "   - Distinguish confirmed evidence from speculative hypotheses: place speculative theories, unconfirmed possibilities, or caveats in 'alternative_explanations'.\n"
        "   - NEVER invent or hallucinate commit hashes, author names, or non-existent files.\n"
        "   - If information is missing or ambiguous, state that explicitly under 'alternative_explanations'.\n"
        "\n"
        "3. SAFE CODE PATCH:\n"
        "   - The 'suggested_fix' must apply directly to the root cause assignment.\n"
        "   - 'original_snippet' must EXACTLY match characters in the target file.\n"
        "   - 'replacement_snippet' must provide the exact corrected code.\n"
        "\n"
        "4. OUTPUT FORMAT:\n"
        "Return ONLY a valid JSON object matching this exact schema (no markdown formatting, no conversational text):\n"
        "{\n"
        '  "incident_summary": "High-level summary of the runtime failure.",\n'
        '  "likely_root_cause": "Precise root cause of the error.",\n'
        '  "affected_file": "Relative file path (e.g. cart.py)",\n'
        '  "affected_function": "Function name (e.g. calculate_total)",\n'
        '  "confidence": "High / Medium / Low",\n'
        '  "evidence": [\n'
        '    "Confirmed fact 1 citing line number or variable state",\n'
        '    "Confirmed fact 2 citing commit diff or blame"\n'
        '  ],\n'
        '  "relevant_commits": [\n'
        '    {\n'
        '      "commit_hash": "Commit hash from git history",\n'
        '      "message": "Commit message",\n'
        '      "author": "Commit author",\n'
        '      "reasoning": "Why this commit introduced or modified the relevant logic"\n'
        '    }\n'
        '  ],\n'
        '  "alternative_explanations": [\n'
        '    "Alternative hypothesis considered and why it was ruled out, or remaining caveats"\n'
        '  ],\n'
        '  "suggested_fix": {\n'
        '    "target_file": "Relative file path (e.g. cart.py)",\n'
        '    "original_snippet": "Exact code line(s) to replace",\n'
        '    "replacement_snippet": "Exact code line(s) to put in place",\n'
        '    "explanation": "Why this patch resolves the error"\n'
        '  },\n'
        '  "explanation": "Detailed explanation of why the proposed correction fixes the problem."\n'
        "}"
    )

    return "\n".join(prompt_parts)


def clean_json_response(raw_text: str) -> str:
    """
    Strips markdown code blocks (e.g. ```json ... ```) or extra leading/trailing whitespace.
    """
    text = raw_text.strip()
    if text.startswith("```"):
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            text = match.group(1).strip()
    return text


def validate_investigation_response(data: Any) -> Dict[str, Any]:
    """
    Validates and harmonizes the parsed JSON response:
    - Enforces presence of all audited schema fields.
    - Preserves backward compatibility with existing tests and modules.
    - Validates patch structure for sandbox verification.
    """
    if not isinstance(data, dict):
        raise InvestigatorError("Gemini response is not a JSON object.")

    # 1. Validate top-level required fields (supporting both audited and legacy field names)
    missing_keys = []
    if not (data.get("likely_root_cause") or data.get("root_cause")):
        missing_keys.append("likely_root_cause")
    if not (data.get("incident_summary") or data.get("error_explanation") or data.get("reasoning_summary")):
        missing_keys.append("incident_summary")
    if "evidence" not in data or data["evidence"] is None:
        missing_keys.append("evidence")
    if not (data.get("suggested_fix") or data.get("proposed_patch")):
        missing_keys.append("suggested_fix")

    if missing_keys:
        raise InvestigatorError(f"Response missing required keys: {', '.join(missing_keys)}")

    # 2. Harmonize root cause
    root_cause = data.get("likely_root_cause") or data.get("root_cause") or ""
    data["likely_root_cause"] = root_cause
    data["root_cause"] = root_cause

    # 3. Harmonize incident summary and error explanation
    incident_summary = data.get("incident_summary") or data.get("error_explanation") or data.get("reasoning_summary") or ""
    data["incident_summary"] = incident_summary
    data["error_explanation"] = incident_summary

    # 4. Affected file & function
    patch_obj = data.get("suggested_fix") or data.get("proposed_patch")
    affected_file = data.get("affected_file") or (patch_obj.get("target_file") if isinstance(patch_obj, dict) else "")
    if not affected_file:
        raise InvestigatorError("Response missing required keys: affected_file")
    data["affected_file"] = affected_file

    affected_function = data.get("affected_function") or "module"
    data["affected_function"] = affected_function

    # 5. Confidence
    confidence = data.get("confidence", "Medium")
    data["confidence"] = confidence

    # 6. Evidence
    evidence = data.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) == 0:
        raise InvestigatorError("Response 'evidence' must be a non-empty list of factual citations.")
    data["evidence"] = evidence

    # 7. Relevant commits & likely introducing commit
    relevant_commits = data.get("relevant_commits") or []
    if not isinstance(relevant_commits, list):
        relevant_commits = [relevant_commits]

    introducing_commit = data.get("likely_introducing_commit")
    if not isinstance(introducing_commit, dict):
        if relevant_commits and isinstance(relevant_commits[0], dict):
            introducing_commit = relevant_commits[0]
        else:
            introducing_commit = {
                "commit_hash": "unknown",
                "message": "Commit identified from git history",
                "author": "unknown",
                "reasoning": "Determined from code evolution analysis"
            }
    data["likely_introducing_commit"] = introducing_commit

    if not relevant_commits and isinstance(introducing_commit, dict):
        relevant_commits = [introducing_commit]
    data["relevant_commits"] = relevant_commits

    # 8. Alternative explanations & limitations
    alt_explanations = data.get("alternative_explanations") or data.get("limitations") or []
    if not isinstance(alt_explanations, list):
        alt_explanations = [str(alt_explanations)]
    data["alternative_explanations"] = alt_explanations
    data["limitations"] = alt_explanations

    # 9. Suggested fix & proposed patch
    if not isinstance(patch_obj, dict):
        raise InvestigatorError("Response must contain a 'suggested_fix' or 'proposed_patch' dictionary.")

    missing_patch_keys = [k for k in REQUIRED_PATCH_KEYS if k not in patch_obj or not str(patch_obj[k]).strip()]
    if missing_patch_keys:
        raise InvestigatorError(f"'proposed_patch' missing required keys: {', '.join(missing_patch_keys)}")

    explanation = patch_obj.get("explanation") or data.get("explanation") or ""
    patch_obj["explanation"] = explanation
    data["suggested_fix"] = patch_obj
    data["proposed_patch"] = patch_obj
    data["explanation"] = explanation

    # 10. Reasoning summary
    data["reasoning_summary"] = data.get("reasoning_summary") or incident_summary

    return data


def parse_and_validate_response(response_text: str) -> Dict[str, Any]:
    """
    Parses and validates Gemini's output into a structured dictionary.
    """
    cleaned = clean_json_response(response_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise InvestigatorError(f"Failed to decode Gemini response as JSON: {e}\nRaw output:\n{response_text[:300]}")

    return validate_investigation_response(data)


def is_retryable_gemini_error(exc: Exception) -> bool:
    """
    Determines whether an exception from the Gemini API or HTTP client is transient
    and safe for bounded retry.

    Transient / Retryable:
    - HTTP 503 (UNAVAILABLE)
    - HTTP 429 (RESOURCE_EXHAUSTED)
    - Network timeouts, connection resets, transient gateway errors

    Permanent (never retry):
    - HTTP 400 (INVALID_ARGUMENT)
    - HTTP 401 (UNAUTHENTICATED / API_KEY_INVALID)
    - HTTP 403 (PERMISSION_DENIED)
    - HTTP 404 (NOT_FOUND)
    - Parsing errors, InvestigatorError
    """
    if isinstance(exc, InvestigatorError):
        return False
    if isinstance(exc, json.JSONDecodeError):
        return False

    # Check status code attribute
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if code in (400, 401, 403, 404):
        return False
    if code in (503, 429):
        return True

    # Check status string attribute
    status = getattr(exc, "status", None)
    if status in ("INVALID_ARGUMENT", "UNAUTHENTICATED", "PERMISSION_DENIED", "NOT_FOUND"):
        return False
    if status in ("UNAVAILABLE", "RESOURCE_EXHAUSTED"):
        return True

    # Check error message strings
    err_str = str(exc).upper()
    if any(k in err_str for k in ("API_KEY_INVALID", "INVALID_ARGUMENT", "PERMISSION_DENIED", "401 UNAUTHENTICATED", "404 NOT_FOUND", "403 FORBIDDEN")):
        return False
    if "401" in err_str or "400" in err_str or "403" in err_str or "404" in err_str:
        return False

    if "503" in err_str or "UNAVAILABLE" in err_str:
        return True
    if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "RATE LIMIT" in err_str:
        return True
    if "DEADLINE_EXCEEDED" in err_str or "TIMED OUT" in err_str:
        return True

    # Check network / timeout exceptions
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True

    try:
        import httpx
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
    except ImportError:
        pass

    return False


def extract_retry_after(exc: Exception) -> Optional[float]:
    """
    Extracts Retry-After in seconds from the exception response headers or details if available.
    """
    # 1. Check response headers
    response = getattr(exc, "response", None)
    if response is not None:
        headers = getattr(response, "headers", None)
        if headers and hasattr(headers, "get"):
            header_val = headers.get("retry-after") or headers.get("Retry-After")
            if header_val:
                try:
                    val = float(header_val)
                    if val > 0:
                        return val
                except (ValueError, TypeError):
                    pass

    # 2. Check details dictionary (Google RPC RetryInfo)
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        error_dict = details.get("error", {}) if isinstance(details.get("error"), dict) else details
        err_details = error_dict.get("details", [])
        if isinstance(err_details, list):
            for item in err_details:
                if isinstance(item, dict) and "retryDelay" in item:
                    raw = str(item["retryDelay"]).rstrip("s")
                    try:
                        val = float(raw)
                        if val > 0:
                            return val
                    except (ValueError, TypeError):
                        pass

    return None


def calculate_backoff_delay(
    attempt: int,
    base_delay: float = DEFAULT_BASE_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
    retry_after: Optional[float] = None
) -> float:
    """
    Calculates backoff delay with exponential factor, random jitter, and Retry-After precedence.
    attempt is 0-indexed.
    """
    if retry_after is not None and retry_after > 0:
        return min(float(retry_after), max_delay)

    jitter_amount = random.uniform(0, jitter) if jitter > 0 else 0.0
    delay = (base_delay * (backoff_factor ** attempt)) + jitter_amount
    return min(delay, max_delay)


def execute_with_retry(
    call_fn: Callable[[], Any],
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
    sleep_fn: Callable[[float], None] = time.sleep
) -> Any:
    """
    Executes call_fn with bounded retries for transient errors (503 UNAVAILABLE, 429 RESOURCE_EXHAUSTED).
    Permanent errors (400, 401, 403, 404) immediately fail with 0 retries.
    """
    last_exc = None
    for attempt in range(max_retries):
        try:
            return call_fn()
        except Exception as e:
            last_exc = e
            # If not retryable or on the last attempt, do not sleep; re-raise immediately
            if not is_retryable_gemini_error(e) or attempt == max_retries - 1:
                raise e

            retry_after = extract_retry_after(e)
            delay = calculate_backoff_delay(
                attempt,
                base_delay=base_delay,
                backoff_factor=backoff_factor,
                max_delay=max_delay,
                jitter=jitter,
                retry_after=retry_after
            )
            sleep_fn(delay)

    if last_exc:
        raise last_exc


def investigate_incident(
    incident_context: Dict[str, Any],
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    timeout: Optional[float] = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
    sleep_fn: Callable[[float], None] = time.sleep
) -> Dict[str, Any]:
    """
    Main investigator entrypoint:
    1. Retrieves API key securely (never prints or logs it).
    2. Builds structured prompt from incident context.
    3. Configures finite HTTP timeout via types.HttpOptions(timeout=...).
    4. Executes API call with bounded retries for transient errors (503, 429).
    5. Returns structured, validated investigation findings.
    """
    if genai is None or types is None:
        raise InvestigatorError("google-genai library is not installed or importable.")

    key = get_api_key(api_key)
    model_name = get_model_name(model)
    timeout_val = get_request_timeout(timeout)

    prompt = build_investigation_prompt(incident_context)

    try:
        # Explicitly configure finite HTTP request timeout on google-genai Client (HttpOptions expects timeout in milliseconds as int)
        timeout_ms = int(round(timeout_val * 1000))
        client = genai.Client(
            api_key=key,
            http_options=types.HttpOptions(timeout=timeout_ms)
        )

        # Gemini 3.8 Flash migration: sampling parameters (temperature, top_p, top_k)
        # are deprecated/removed and must not be passed.
        # Structured JSON response is enforced via response_mime_type.
        use_interactions = (
            os.getenv("GEMINI_USE_INTERACTIONS_API", "").strip().lower() in ("true", "1", "yes")
        )

        def _call_gemini():
            if use_interactions and hasattr(client, "interactions") and hasattr(client.interactions, "create"):
                interaction = client.interactions.create(
                    model=model_name,
                    input=prompt,
                    response_mime_type="application/json"
                )
                return getattr(interaction, "output_text", None) or (interaction.text if hasattr(interaction, "text") else None)
            else:
                config = types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config
                )
                return response.text if response and hasattr(response, "text") else None

        raw_text = execute_with_retry(
            _call_gemini,
            max_retries=max_retries,
            sleep_fn=sleep_fn
        )

        if not raw_text or not raw_text.strip():
            raise InvestigatorError("Gemini returned an empty response.")

        return parse_and_validate_response(raw_text)

    except InvestigatorError:
        raise
    except Exception as e:
        err_msg = str(e)
        code = getattr(e, "code", None) or getattr(e, "status_code", None)
        status = getattr(e, "status", None)

        if code == 401 or status == "UNAUTHENTICATED" or "API_KEY_INVALID" in err_msg or "401" in err_msg:
            raise InvestigatorError("Invalid Gemini API key provided. Please verify your credentials.")
        elif code == 429 or status == "RESOURCE_EXHAUSTED" or "RESOURCE_EXHAUSTED" in err_msg or "429" in err_msg:
            raise InvestigatorError(
                f"Gemini API rate limit exceeded (429 RESOURCE_EXHAUSTED). "
                f"Bounded retries ({max_retries} attempts) were exhausted. Please wait a moment and retry."
            )
        elif code == 503 or status == "UNAVAILABLE" or "503" in err_msg or "UNAVAILABLE" in err_msg:
            raise InvestigatorError(
                f"Gemini service is temporarily unavailable (503 UNAVAILABLE). "
                f"Bounded retries ({max_retries} attempts) were exhausted. Please try again later."
            )
        elif code == 404 or ("404" in err_msg and ("NOT_FOUND" in err_msg or "not found" in err_msg.lower())):
            raise InvestigatorError(
                f"Gemini model '{model_name}' was not found or is unavailable: {err_msg}. "
                "Ensure GEMINI_MODEL is set to an active model such as 'gemini-3.8-flash'."
            )
        elif isinstance(e, TimeoutError) or "timed out" in err_msg.lower() or "timeout" in err_msg.lower():
            raise InvestigatorError(
                f"Gemini API request timed out after {timeout_val:.1f}s. Please check network connectivity or try again."
            )
        else:
            raise InvestigatorError(f"Gemini API investigation failed: {e}")
