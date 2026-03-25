#!/usr/bin/env python3
# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Baseline Inference Script
# BSD-3-Clause License

"""
Baseline Inference Script for the Incident Response Triage Environment.

This script runs an LLM agent against all 3 tasks in the environment
and produces reproducible baseline scores. It demonstrates how an AI agent
interacts with the environment through the step/reset/state API.

Supports ANY OpenAI-compatible LLM provider via the --api-base flag or
auto-detection from environment variables.

Architecture:
    This agent implements a ReflAct-inspired reasoning loop (Kim et al., 2025)
    combined with Pre-Act multi-step planning (Rawat et al., 2025) and
    phase-based investigation structure derived from SOC incident response
    playbooks (Reynolds, 2025; Baral et al., 2025). Key techniques:

    1. ReflAct reflection: At each step the agent assesses its current state
       relative to the investigation goal before deciding the next action.
    2. Pre-Act planning: An investigation plan is generated upfront and
       tracked across steps, preventing redundant actions and ensuring
       complete evidence coverage.
    3. Phase enforcement: INVESTIGATE → ANALYZE → RESPOND → REPORT workflow
       mirrors real SOC playbooks (NIST SP 800-61, SANS IR framework).
    4. Few-shot examples: Exact JSON formats for every action type, with
       special emphasis on classify_severity, contain_threat, and
       submit_report — the actions that require precise parameter formats.
    5. Evidence tracking: Explicit tracking of discovered evidence and IOCs
       in the prompt context to avoid wasting steps on duplicate actions.

Usage:
    # OpenAI (default):
    OPENAI_API_KEY=sk-... python baseline_inference.py

    # OpenRouter (auto-detected from env var):
    OPENROUTER_API_KEY=sk-or-... python baseline_inference.py --model google/gemini-2.5-flash

    # Anthropic (OpenAI-compatible endpoint):
    ANTHROPIC_API_KEY=sk-ant-... python baseline_inference.py --model claude-sonnet-4-20250514

    # Any provider via explicit flags:
    python baseline_inference.py --api-key KEY --api-base https://my-provider/v1 --model my-model

    # Local models (Ollama, vLLM, etc.):
    python baseline_inference.py --api-base http://localhost:11434/v1 --api-key dummy --model llama3

    # Run against a remote HF Space:
    OPENAI_API_KEY=sk-... python baseline_inference.py --base-url https://huggingface.co/spaces/your-user/incident-response-env

Environment Variables (checked in order):
    LLM_API_KEY + LLM_API_BASE : Universal override for any provider
    OPENROUTER_API_KEY          : OpenRouter (https://openrouter.ai/api/v1)
    ANTHROPIC_API_KEY            : Anthropic (https://api.anthropic.com/v1)
    OPENAI_API_KEY               : OpenAI (https://api.openai.com/v1) [default]

Output:
    Prints scores for each task and aggregate results.

References:
    - ReflAct: Kim et al. (2025) "World-Grounded Decision Making in LLM Agents
      via Goal-State Reflection" arXiv:2505.15182
    - Pre-Act: Rawat et al. (2025) "Multi-Step Planning and Reasoning Improves
      Acting in LLM Agents" arXiv:2505.09970
    - LLM-IRAgent: Reynolds (2025) "Automated Incident Response Playbooks Using
      Policy-Driven LLM Agents in SOC Operations" JRPS v16.i4.331
    - ReAct SOC: Baral et al. (2025) "Autonomous Cyber Incident Response Using
      Reasoning and Action" IEEE IWCMC 2025
    - Focused ReAct: Li et al. (2024) "Focused ReAct through Reiterate and
      Early Stop" arXiv:2410.10779
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: openai package required. Install with: pip install openai>=1.0.0")
    sys.exit(1)


# =============================================================================
# Configuration
# =============================================================================

# ReflAct-inspired system prompt with Pre-Act planning and few-shot examples.
# References:
#   - ReflAct (Kim et al., 2025): Reflect on state-vs-goal before acting
#   - Pre-Act (Rawat et al., 2025): Create investigation plan upfront
#   - LLM-IRAgent (Reynolds, 2025): Phase-based SOC playbook structure
#   - Focused ReAct (Li et al., 2024): Reiterate goal to prevent drift
SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst AI agent investigating cybersecurity incidents.

## INVESTIGATION PROTOCOL (MANDATORY PHASES)

You MUST follow these phases IN ORDER. Do not skip to later phases until the current one is complete.

### PHASE 1: INVESTIGATE (gather evidence systematically)
Query ALL 6 log sources (email, edr, auth, proxy, firewall, dns) — each reveals unique evidence.
Inspect ALL endpoints mentioned in findings.
Check threat intel for EVERY IOC you discover (IPs, domains, hashes, filenames, emails).
Check user history for any suspicious users.
Run correlate_events ONCE after gathering sufficient evidence.

### PHASE 2: CLASSIFY (after thorough investigation)
Use classify_severity with BOTH severity AND threat_category fields.
Severity levels: critical, high, medium, low, informational
Threat categories: malware, phishing, data_exfiltration, brute_force, insider_threat, lateral_movement, privilege_escalation, false_positive

### PHASE 3: CONTAIN (execute ALL needed containment)
Use contain_threat with BOTH containment_actions (list) AND target (string).
You may need MULTIPLE contain_threat calls with different targets.
Available containment_actions: isolate_host, block_ip, disable_account, quarantine_file, revoke_sessions, none

### PHASE 4: REPORT (submit comprehensive report)
Use submit_report with a detailed report_summary (50+ words).
Include: incident type, IOCs found, evidence summary, severity justification, containment actions taken, and recommendations.

## REFLACT REASONING (DO THIS EVERY STEP)
Before choosing your action, reflect using this format:

REFLECTION: [What evidence have I gathered so far? What is my current investigation state?]
GOAL CHECK: [What critical evidence/IOCs am I still missing? Which phase am I in?]
PLAN: [What specific action should I take next and why?]
ACTION: <the JSON action>

## CRITICAL RULES
- NEVER repeat the same action with the same parameters — it wastes steps
- Query EVERY log source (email, edr, auth, proxy, firewall, dns) — each has unique evidence
- When you find an IOC, ALWAYS run check_threat_intel on it
- classify_severity MUST include both severity AND threat_category
- contain_threat MUST include both containment_actions (list) AND target (string)
- submit_report MUST have a detailed report_summary (50+ words mentioning IOCs and findings)
- ALWAYS submit_report before running out of steps

## JSON ACTION FORMAT (respond with ONLY a JSON object)

Example actions for each type:

1. Examine alert:
{"action_type": "examine_alert"}

2. Query logs (use each source: email, edr, auth, proxy, firewall, dns):
{"action_type": "query_logs", "log_source": "email"}
{"action_type": "query_logs", "log_source": "edr"}
{"action_type": "query_logs", "log_source": "auth"}
{"action_type": "query_logs", "log_source": "proxy"}
{"action_type": "query_logs", "log_source": "firewall"}
{"action_type": "query_logs", "log_source": "dns"}

3. Check threat intel (specify the IOC):
{"action_type": "check_threat_intel", "query_filter": "185.220.101.42"}
{"action_type": "check_threat_intel", "query_filter": "svchost_update.exe"}

4. Inspect endpoint:
{"action_type": "inspect_endpoint", "endpoint_id": "WS-JSMITH-PC"}

5. Check user history:
{"action_type": "check_user_history", "user_id": "jsmith"}

6. Correlate events:
{"action_type": "correlate_events"}

7. Classify severity (MUST include BOTH fields):
{"action_type": "classify_severity", "severity": "critical", "threat_category": "lateral_movement"}
{"action_type": "classify_severity", "severity": "high", "threat_category": "phishing"}

8. Contain threat (MUST include BOTH containment_actions list AND target):
{"action_type": "contain_threat", "containment_actions": ["isolate_host"], "target": "WS-JSMITH-PC"}
{"action_type": "contain_threat", "containment_actions": ["block_ip"], "target": "185.220.101.42"}
{"action_type": "contain_threat", "containment_actions": ["disable_account", "revoke_sessions"], "target": "jsmith"}
{"action_type": "contain_threat", "containment_actions": ["quarantine_file"], "target": "a3f2b8c1d4e5..."}

9. Escalate:
{"action_type": "escalate", "escalate_to": "tier3"}
{"action_type": "escalate", "escalate_to": "management"}

10. Submit report (MUST be detailed, 50+ words):
{"action_type": "submit_report", "report_summary": "INCIDENT REPORT: [Type] incident detected. Severity: [level]. IOCs identified: [list IOCs]. Evidence: [summarize findings]. Containment: [actions taken]. The attack vector was [description]. Recommend [next steps]. Classification: [category]."}

RESPOND WITH ONLY THE JSON ACTION OBJECT. No markdown, no code blocks, no extra text."""


# Valid fields for the IncidentAction Pydantic model.
# Any extra keys the LLM invents will cause a 422 from the server
# because the model uses extra="forbid".
VALID_ACTION_FIELDS = {
    "action_type", "log_source", "query_filter", "endpoint_id",
    "user_id", "severity", "threat_category", "containment_actions",
    "target", "report_summary", "escalate_to", "metadata",
}

VALID_ACTION_TYPES = {
    "examine_alert", "query_logs", "check_threat_intel",
    "correlate_events", "inspect_endpoint", "check_user_history",
    "classify_severity", "contain_threat", "escalate",
    "close_as_false_positive", "submit_report",
}


def sanitize_action(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize the action dict so it matches the Pydantic model exactly.
    Strips unknown keys and normalizes action_type values.
    """
    clean: Dict[str, Any] = {}
    for k, v in raw.items():
        # Normalize key
        nk = k.strip().lower().replace("-", "_").replace(" ", "_")
        if nk in VALID_ACTION_FIELDS:
            clean[nk] = v

    if "action_type" not in clean:
        clean["action_type"] = "examine_alert"

    # Normalize action_type value
    at = clean["action_type"]
    if isinstance(at, str):
        at = at.strip().lower().replace(" ", "_").replace("-", "_")
    if at not in VALID_ACTION_TYPES:
        # Try fuzzy match
        for valid in VALID_ACTION_TYPES:
            if at in valid or valid in at:
                at = valid
                break
        else:
            at = "examine_alert"
    clean["action_type"] = at

    # Normalize severity values
    if "severity" in clean and isinstance(clean["severity"], str):
        clean["severity"] = clean["severity"].strip().lower().replace(" ", "_")

    # Normalize threat_category values
    if "threat_category" in clean and isinstance(clean["threat_category"], str):
        clean["threat_category"] = clean["threat_category"].strip().lower().replace(" ", "_")

    # Normalize containment_actions to list
    if "containment_actions" in clean:
        ca = clean["containment_actions"]
        if isinstance(ca, str):
            clean["containment_actions"] = [ca.strip().lower().replace(" ", "_")]
        elif isinstance(ca, list):
            clean["containment_actions"] = [
                c.strip().lower().replace(" ", "_") if isinstance(c, str) else str(c)
                for c in ca
            ]

    return clean


def make_action_from_llm_response(response_text: Optional[str]) -> Dict[str, Any]:
    """Parse LLM response into a sanitized action dict."""
    if not response_text:
        return sanitize_action({"action_type": "examine_alert"})

    raw = {}
    try:
        # Try to extract JSON from the response
        text = response_text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        raw = json.loads(text)
    except (json.JSONDecodeError, IndexError):
        # Fallback: try to find JSON object in text
        import re
        # Match nested JSON (up to 2 levels deep)
        json_match = re.search(
            r'\{[^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*\}',
            response_text,
        )
        if json_match:
            try:
                raw = json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

    if not raw or not isinstance(raw, dict):
        raw = {"action_type": "examine_alert"}

    return sanitize_action(raw)


def build_state_summary(
    actions_taken: List[str],
    evidence_collected: List[str],
    iocs_discovered: List[str],
    investigation_progress: float,
    steps_remaining: int,
    severity_set: bool,
    containment_done: bool,
    report_submitted: bool,
) -> str:
    """
    Build a concise state summary for the ReflAct reflection.
    This tracks what the agent has done and what it still needs to do,
    following ReflAct's principle of grounding decisions in state-vs-goal.
    """
    log_sources_queried = set()
    for a in actions_taken:
        if a.startswith("query_logs:"):
            log_sources_queried.add(a.split(":")[1])

    all_sources = {"email", "edr", "auth", "proxy", "firewall", "dns"}
    missing_sources = all_sources - log_sources_queried

    summary = "=== INVESTIGATION STATE ===\n"
    summary += f"Steps used: {len(actions_taken)} | Steps remaining: {steps_remaining}\n"
    summary += f"Investigation progress: {investigation_progress:.0%}\n"
    summary += f"Evidence items: {len(evidence_collected)}\n"
    summary += f"IOCs discovered: {len(iocs_discovered)}"
    if iocs_discovered:
        summary += f" ({', '.join(iocs_discovered[:5])})"
    summary += "\n"
    summary += f"Log sources queried: {', '.join(sorted(log_sources_queried)) or 'none'}\n"
    if missing_sources:
        summary += f"*** UNQUERIED LOG SOURCES: {', '.join(sorted(missing_sources))} ***\n"

    # Phase tracking
    if not severity_set:
        if missing_sources and len(actions_taken) < steps_remaining:
            summary += "CURRENT PHASE: INVESTIGATE (gather more evidence)\n"
        else:
            summary += "CURRENT PHASE: CLASSIFY (ready to classify severity)\n"
    elif not containment_done:
        summary += "CURRENT PHASE: CONTAIN (execute containment actions)\n"
    elif not report_submitted:
        summary += "CURRENT PHASE: REPORT (submit final report)\n"
    else:
        summary += "CURRENT PHASE: COMPLETE\n"

    # Urgency warnings
    if steps_remaining <= 5 and not report_submitted:
        summary += "*** URGENT: FEW STEPS LEFT — classify, contain, and submit_report NOW ***\n"
    elif steps_remaining <= 3 and not report_submitted:
        summary += "*** CRITICAL: MUST submit_report IMMEDIATELY ***\n"

    return summary


def run_llm_agent(
    base_url: str,
    task_id: str,
    client: OpenAI,
    model: str = "gpt-4o-mini",
    verbose: bool = False,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Run the LLM agent against a single task using ReflAct reasoning.

    Architecture:
        - ReflAct-style state-goal reflection at each step
        - Phase-based investigation flow (INVESTIGATE→CLASSIFY→CONTAIN→REPORT)
        - Explicit evidence/IOC tracking to prevent redundant actions
        - Urgency detection for step-limited episodes

    Args:
        base_url: Environment server URL
        task_id: Task to run (easy/medium/hard)
        client: OpenAI client
        model: Model to use
        verbose: Print detailed output

    Returns:
        Dict with score and action history
    """
    # Reset environment (use /env/reset for stateful interaction)
    reset_response = requests.post(
        f"{base_url}/env/reset",
        json={"seed": 42, "task_id": task_id},
        timeout=30,
    )
    if reset_response.status_code != 200:
        print(f"  RESET FAILED ({reset_response.status_code}): {reset_response.text[:200]}")
        return {"task_id": task_id, "score": 0.0, "steps_taken": 0, "actions": [], "breakdown": {}}
    reset_data = reset_response.json()

    observation = reset_data.get("observation", {})

    # Pre-Act: Generate initial investigation plan in the first user message
    initial_prompt = (
        f"TASK: {task_id.upper()} difficulty incident investigation\n\n"
        f"ALERT ID: {observation.get('alert_id', 'N/A')}\n"
        f"ALERT: {observation.get('alert_summary', '')}\n\n"
        f"INITIAL FINDINGS: {observation.get('findings', '')}\n\n"
        f"Steps available: {observation.get('steps_remaining', 20)}\n"
        f"Available actions: {observation.get('available_actions', [])}\n\n"
        "INVESTIGATION PLAN:\n"
        "1. examine_alert for detailed alert info\n"
        "2. Query ALL 6 log sources (email, edr, auth, proxy, firewall, dns)\n"
        "3. Check threat intel for all IOCs discovered\n"
        "4. Inspect endpoints and check user history\n"
        "5. Correlate events\n"
        "6. Classify severity and threat category\n"
        "7. Execute containment actions with correct targets\n"
        "8. Submit comprehensive report\n\n"
        "Begin with step 1. Respond with ONLY a JSON action."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": initial_prompt},
    ]

    actions_taken = []
    actions_with_params = []  # Track full action strings for dedup
    max_agent_steps = 30
    done = False

    # State tracking for ReflAct reflection
    evidence_collected = observation.get("evidence_collected", [])
    iocs_discovered = observation.get("iocs_discovered", [])
    investigation_progress = 0.0
    steps_remaining = observation.get("steps_remaining", 20)
    severity_set = False
    containment_done = False
    report_submitted = False
    consecutive_same_action = 0
    last_action_key = ""

    for step_num in range(max_agent_steps):
        if done:
            break

        # Get LLM response with retry for rate limits
        assistant_msg = None
        for _attempt in range(3):
            try:
                create_kwargs: Dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                    "temperature": 0.2,
                    "max_tokens": 1024,
                }
                if extra_headers:
                    create_kwargs["extra_headers"] = extra_headers
                llm_response = client.chat.completions.create(**create_kwargs)
                # Guard against empty choices or None content
                if not llm_response.choices:
                    if verbose:
                        print(f"  Step {step_num + 1}: LLM returned empty choices, using fallback")
                    assistant_msg = '{"action_type": "examine_alert"}'
                else:
                    assistant_msg = llm_response.choices[0].message.content
                    if assistant_msg is None:
                        # Some models return None content (reasoning models, refusals, etc.)
                        if verbose:
                            print(f"  Step {step_num + 1}: LLM returned None content, using fallback")
                        assistant_msg = '{"action_type": "examine_alert"}'
                break  # Success, exit retry loop
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "rate limit" in err_str.lower():
                    wait_secs = 5 * (_attempt + 1)
                    if verbose:
                        print(f"  Rate limited, waiting {wait_secs}s (attempt {_attempt + 1}/3)...")
                    time.sleep(wait_secs)
                    continue
                print(f"  LLM API error: {e}")
                assistant_msg = '{"action_type": "examine_alert"}'
                break
        if assistant_msg is None:
            print(f"  LLM rate limit exhausted after 3 retries, using fallback")
            assistant_msg = '{"action_type": "examine_alert"}'

        messages.append({"role": "assistant", "content": assistant_msg})

        # Parse action
        action = make_action_from_llm_response(assistant_msg)

        # Build action key for deduplication
        action_key = action.get("action_type", "")
        if action.get("log_source"):
            action_key += f":{action['log_source']}"
        if action.get("query_filter"):
            action_key += f":{action['query_filter']}"
        if action.get("endpoint_id"):
            action_key += f":{action['endpoint_id']}"
        if action.get("user_id"):
            action_key += f":{action['user_id']}"

        # Detect repetition and force progression (Focused ReAct: Li et al., 2024)
        if action_key == last_action_key:
            consecutive_same_action += 1
        else:
            consecutive_same_action = 0
        last_action_key = action_key

        if consecutive_same_action >= 2:
            # Agent is stuck — force it to the next phase
            if verbose:
                print(f"  Step {step_num + 1}: STUCK on {action_key}, forcing progression")
            if not severity_set:
                action = {"action_type": "classify_severity", "severity": "high", "threat_category": "phishing"}
                severity_set = True
            elif not containment_done:
                action = {"action_type": "submit_report", "report_summary": "Investigation report submitted with available evidence."}
            else:
                action = {"action_type": "submit_report", "report_summary": "Investigation complete. Report submitted."}
            consecutive_same_action = 0

        # Urgency: force report submission if about to run out of steps
        if steps_remaining <= 2 and not report_submitted:
            ioc_list = ", ".join(iocs_discovered[:5]) if iocs_discovered else "under investigation"
            evidence_summary = ", ".join(evidence_collected[:5]) if evidence_collected else "collected during investigation"
            action = {
                "action_type": "submit_report",
                "report_summary": (
                    f"INCIDENT REPORT for {task_id.upper()} task. "
                    f"IOCs identified: {ioc_list}. "
                    f"Evidence: {evidence_summary}. "
                    f"Investigation progress: {investigation_progress:.0%}. "
                    f"Severity and containment actions have been applied as determined during investigation. "
                    f"Recommend continued monitoring and follow-up analysis."
                ),
            }

        actions_taken.append(action_key)
        actions_with_params.append(action)

        if verbose:
            print(f"  Step {step_num + 1}: {action_key}")

        # Execute step (use /env/step for stateful interaction)
        try:
            step_response = requests.post(
                f"{base_url}/env/step",
                json={"action": action},
                timeout=30,
            )
            if step_response.status_code == 422:
                # Validation error — show details and retry with fallback
                err_detail = step_response.json().get("detail", step_response.text[:200])
                if verbose:
                    print(f"    422 Validation Error: {err_detail}")
                # Retry with a safe fallback action
                fallback = {"action_type": "examine_alert"}
                step_response = requests.post(
                    f"{base_url}/env/step",
                    json={"action": fallback},
                    timeout=30,
                )
            step_data = step_response.json()
        except Exception as e:
            print(f"  Step API error: {e}")
            break

        obs = step_data.get("observation", {})
        reward = step_data.get("reward", 0)
        done = step_data.get("done", False)

        # Update state tracking
        evidence_collected = obs.get("evidence_collected", evidence_collected)
        iocs_discovered = obs.get("iocs_discovered", iocs_discovered)
        investigation_progress = obs.get("investigation_progress", investigation_progress)
        steps_remaining = obs.get("steps_remaining", steps_remaining)

        if action.get("action_type") == "classify_severity":
            severity_set = True
        if action.get("action_type") == "contain_threat":
            containment_done = True
        if action.get("action_type") == "submit_report":
            report_submitted = True

        # Build ReflAct state summary for feedback
        state_summary = build_state_summary(
            actions_taken=actions_taken,
            evidence_collected=evidence_collected,
            iocs_discovered=iocs_discovered,
            investigation_progress=investigation_progress,
            steps_remaining=steps_remaining,
            severity_set=severity_set,
            containment_done=containment_done,
            report_submitted=report_submitted,
        )

        # Feed observation back to LLM with state context
        feedback = (
            f"ACTION RESULT: {obs.get('action_result', '')}\n\n"
            f"FINDINGS:\n{obs.get('findings', '')}\n\n"
            f"{state_summary}\n"
        )

        if done:
            feedback += "EPISODE COMPLETE."
        else:
            # Phase-specific guidance
            if steps_remaining <= 5 and not report_submitted:
                if not severity_set:
                    feedback += (
                        "*** URGENT: You are running low on steps. "
                        "You MUST now: (1) classify_severity with severity and threat_category, "
                        "(2) contain_threat with correct targets, "
                        "(3) submit_report with detailed summary. Do classify_severity NOW. ***"
                    )
                elif not containment_done:
                    feedback += (
                        "*** URGENT: classify done. Now IMMEDIATELY contain_threat "
                        "with appropriate containment_actions and target. ***"
                    )
                else:
                    feedback += (
                        "*** URGENT: NOW submit_report with a detailed report_summary "
                        "(50+ words, mention all IOCs and findings). ***"
                    )
            else:
                feedback += "Reflect on your state vs goal, then choose your next action. Respond with ONLY JSON."

        messages.append({"role": "user", "content": feedback})

    # Get grader score
    try:
        grader_response = requests.get(f"{base_url}/grader", timeout=10)
        grader_data = grader_response.json()
    except Exception:
        grader_data = {"score": 0.0, "breakdown": {}}

    return {
        "task_id": task_id,
        "score": grader_data.get("score", 0.0),
        "steps_taken": len(actions_taken),
        "actions": actions_taken,
        "breakdown": grader_data.get("breakdown", {}),
    }


# =============================================================================
# Provider Auto-Detection
# =============================================================================

# Known provider configurations: (env_var_key, api_base_url, provider_name)
PROVIDER_CONFIGS: List[Tuple[str, str, str]] = [
    ("LLM_API_KEY",        os.environ.get("LLM_API_BASE", ""), "Custom"),
    ("OPENROUTER_API_KEY", "https://openrouter.ai/api/v1",     "OpenRouter"),
    ("ANTHROPIC_API_KEY",  "https://api.anthropic.com/v1",      "Anthropic"),
    ("OPENAI_API_KEY",     "https://api.openai.com/v1",         "OpenAI"),
]


def resolve_llm_config(
    cli_api_key: Optional[str] = None,
    cli_api_base: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Resolve LLM API key, base URL, and provider name.

    Priority:
        1. Explicit CLI flags (--api-key, --api-base)
        2. Auto-detect from environment variables

    Returns:
        (api_key, api_base, provider_name)

    Raises:
        SystemExit if no API key is found.
    """
    # 1. CLI flags take highest priority
    if cli_api_key:
        base = cli_api_base or "https://api.openai.com/v1"
        return cli_api_key, base, "Custom" if cli_api_base else "OpenAI"

    # 2. Auto-detect from environment variables
    for env_key, default_base, provider in PROVIDER_CONFIGS:
        key = os.environ.get(env_key)
        if key:
            base = cli_api_base or default_base
            if not base:
                # LLM_API_KEY without LLM_API_BASE — fall back to OpenAI
                base = "https://api.openai.com/v1"
            return key, base, provider

    # No key found
    print("ERROR: No LLM API key found.")
    print()
    print("Set one of these environment variables:")
    print("  OPENAI_API_KEY       - for OpenAI models")
    print("  OPENROUTER_API_KEY   - for OpenRouter (any model)")
    print("  ANTHROPIC_API_KEY    - for Anthropic models")
    print("  LLM_API_KEY          - for any provider (set LLM_API_BASE too)")
    print()
    print("Or pass explicitly: --api-key YOUR_KEY --api-base https://provider/v1")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Baseline inference for Incident Response Triage Environment"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Environment server URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="LLM model name (default: gpt-4o-mini). Use provider-specific "
             "names, e.g. 'google/gemini-2.5-flash' for OpenRouter, "
             "'claude-sonnet-4-20250514' for Anthropic.",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="LLM API key. Overrides all environment variables.",
    )
    parser.add_argument(
        "--api-base",
        default=None,
        help="LLM API base URL (e.g. https://openrouter.ai/api/v1, "
             "http://localhost:11434/v1 for Ollama). Overrides auto-detection.",
    )
    parser.add_argument(
        "--tasks",
        nargs="+",
        default=["easy", "medium", "hard"],
        help="Tasks to run (default: all)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed output",
    )
    args = parser.parse_args()

    # Resolve LLM provider
    api_key, api_base, provider_name = resolve_llm_config(
        cli_api_key=args.api_key,
        cli_api_base=args.api_base,
    )

    client = OpenAI(api_key=api_key, base_url=api_base)

    # Build extra headers for providers that need them
    extra_headers: Optional[Dict[str, str]] = None
    if provider_name == "OpenRouter" or "openrouter.ai" in api_base:
        extra_headers = {
            "HTTP-Referer": "https://github.com/incident-response-env",
            "X-Title": "Incident Response Triage Environment",
        }

    print("=" * 60)
    print("Incident Response Triage - Baseline Inference")
    print(f"Provider: {provider_name} ({api_base})")
    print(f"Server: {args.base_url}")
    print(f"Model: {args.model}")
    print(f"Tasks: {args.tasks}")
    print("=" * 60)

    results = {}
    total_score = 0.0

    for task_id in args.tasks:
        print(f"\n--- Task: {task_id.upper()} ---")
        start = time.time()

        result = run_llm_agent(
            base_url=args.base_url,
            task_id=task_id,
            client=client,
            model=args.model,
            verbose=args.verbose,
            extra_headers=extra_headers,
        )

        elapsed = time.time() - start
        results[task_id] = result
        total_score += result["score"]

        print(f"  Score: {result['score']:.4f}")
        print(f"  Steps: {result['steps_taken']}")
        print(f"  Time: {elapsed:.1f}s")

        if args.verbose and result.get("breakdown"):
            print(f"  Breakdown: {json.dumps(result['breakdown'], indent=4)}")

    # Summary
    mean_score = total_score / len(args.tasks)
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    for task_id, result in results.items():
        print(f"  {task_id:8s}: {result['score']:.4f} ({result['steps_taken']} steps)")
    print(f"  {'MEAN':8s}: {mean_score:.4f}")
    print("=" * 60)

    # Output JSON for reproducibility
    output = {
        "model": args.model,
        "results": results,
        "aggregate": {
            "mean_score": round(mean_score, 4),
            "total_score": round(total_score, 4),
        },
    }

    output_path = "baseline_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
