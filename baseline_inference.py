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

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst investigating a cybersecurity incident. You must:

1. Thoroughly investigate the alert by examining logs, checking threat intelligence, inspecting endpoints, and correlating events
2. Identify all Indicators of Compromise (IOCs)
3. Classify the incident severity (critical/high/medium/low/informational) and threat category
4. Execute appropriate containment actions with correct targets
5. Submit a comprehensive incident report

Available actions (use exact action_type values):
- examine_alert: Get detailed alert information
- query_logs: Query log sources (set log_source to: firewall/edr/proxy/auth/dns/email)
- check_threat_intel: Look up IOCs in threat intelligence (set query_filter to the IOC)
- correlate_events: Correlate findings across data sources
- inspect_endpoint: Inspect an endpoint (set endpoint_id to hostname or IP)
- check_user_history: Check user profile (set user_id)
- classify_severity: Set severity and threat_category
- contain_threat: Execute containment (set containment_actions list and target)
- escalate: Escalate incident (set escalate_to: tier2/tier3/management/legal)
- close_as_false_positive: Close as false positive
- submit_report: Submit final report (set report_summary)

Respond with a JSON object containing your chosen action parameters. Be thorough but efficient.
"""


def make_action_from_llm_response(response_text: str) -> Dict[str, Any]:
    """Parse LLM response into an action dict."""
    try:
        # Try to extract JSON from the response
        text = response_text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        action = json.loads(text)
        return action
    except (json.JSONDecodeError, IndexError):
        # Fallback: try to find JSON object in text
        import re
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response_text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        # Ultimate fallback
        return {"action_type": "examine_alert"}


def run_llm_agent(
    base_url: str,
    task_id: str,
    client: OpenAI,
    model: str = "gpt-4o-mini",
    verbose: bool = False,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Run the LLM agent against a single task.

    Args:
        base_url: Environment server URL
        task_id: Task to run (easy/medium/hard)
        client: OpenAI client
        model: Model to use
        verbose: Print detailed output

    Returns:
        Dict with score and action history
    """
    # Reset environment
    reset_response = requests.post(
        f"{base_url}/reset",
        json={"seed": 42, "task_id": task_id},
        timeout=30,
    )
    reset_data = reset_response.json()

    observation = reset_data.get("observation", {})
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"TASK: {task_id.upper()} difficulty\n\n"
                f"ALERT: {observation.get('alert_summary', '')}\n\n"
                f"INITIAL FINDINGS: {observation.get('findings', '')}\n\n"
                f"Steps remaining: {observation.get('steps_remaining', 20)}\n\n"
                "Begin your investigation. Respond with a JSON action."
            ),
        },
    ]

    actions_taken = []
    max_agent_steps = 25
    done = False

    for step_num in range(max_agent_steps):
        if done:
            break

        # Get LLM response
        try:
            create_kwargs: Dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 1024,
            }
            if extra_headers:
                create_kwargs["extra_headers"] = extra_headers
            llm_response = client.chat.completions.create(**create_kwargs)
            assistant_msg = llm_response.choices[0].message.content
        except Exception as e:
            print(f"  LLM API error: {e}")
            assistant_msg = '{"action_type": "examine_alert"}'

        messages.append({"role": "assistant", "content": assistant_msg})

        # Parse action
        action = make_action_from_llm_response(assistant_msg)
        actions_taken.append(action.get("action_type", "unknown"))

        if verbose:
            print(f"  Step {step_num + 1}: {action.get('action_type', 'unknown')}")

        # Execute step
        try:
            step_response = requests.post(
                f"{base_url}/step",
                json={"action": action},
                timeout=30,
            )
            step_data = step_response.json()
        except Exception as e:
            print(f"  Step API error: {e}")
            break

        obs = step_data.get("observation", {})
        reward = step_data.get("reward", 0)
        done = step_data.get("done", False)

        # Feed observation back to LLM
        feedback = (
            f"ACTION RESULT: {obs.get('action_result', '')}\n\n"
            f"FINDINGS: {obs.get('findings', '')}\n\n"
            f"Evidence collected: {obs.get('evidence_collected', [])}\n"
            f"IOCs discovered: {obs.get('iocs_discovered', [])}\n"
            f"Investigation progress: {obs.get('investigation_progress', 0):.0%}\n"
            f"Steps remaining: {obs.get('steps_remaining', 0)}\n"
            f"Reward this step: {reward}\n\n"
        )

        if done:
            feedback += "EPISODE COMPLETE."
        else:
            feedback += "Continue your investigation. Respond with next JSON action."

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
