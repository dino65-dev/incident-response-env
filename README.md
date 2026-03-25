# 🛡️ Incident Response Triage Environment

A real-world cybersecurity **Security Operations Center (SOC) analyst simulation** built on the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) framework. AI agents investigate security alerts, gather forensic evidence, correlate findings, classify threats, and execute incident response — exactly like human SOC analysts do every day.

> **Meta PyTorch OpenEnv Hackathon 2026 — Problem Statement 1 Submission**

---

## Why This Environment?

Every organization with a SOC faces the same problem: **alert fatigue**. Analysts process hundreds of alerts daily, each requiring multi-step investigation, contextual judgment, and decisive action. Training AI agents to handle this workflow has massive real-world value:

- **4,000+** SOC alerts per day at a typical enterprise ([IBM X-Force](https://www.ibm.com/reports/threat-intelligence))
- **$4.88M** average cost of a data breach in 2024 ([IBM Cost of Data Breach Report](https://www.ibm.com/reports/data-breach))
- **277 days** average time to identify and contain a breach
- AI SOC agents could reduce MTTR (Mean Time to Respond) by orders of magnitude

This environment provides the first standardized OpenEnv benchmark for training and evaluating AI security agents on realistic incident response workflows.

---

## Environment Description

The agent receives a cybersecurity alert and must:

1. **Investigate** — Examine logs (firewall, EDR, proxy, auth, DNS, email), query threat intelligence, inspect endpoints, check user profiles, correlate events
2. **Classify** — Determine severity (critical/high/medium/low/info) and threat category (malware, phishing, lateral movement, insider threat, etc.)
3. **Respond** — Execute containment actions (isolate hosts, block IPs, disable accounts, quarantine files) with correct targets
4. **Report** — Submit a comprehensive incident report summarizing findings

### What Makes It Creative

- **Layered evidence discovery**: Investigation actions progressively reveal forensic artifacts. The agent must piece together the attack narrative from fragmented evidence across multiple data sources — just like a real analyst.
- **Multi-dimensional reward shaping**: Reward is not binary. The agent earns partial credit for each evidence item discovered, each IOC identified, severity accuracy (with partial credit for adjacent levels), containment correctness, and report quality. This provides rich learning signal across the full trajectory.
- **Behavioral deception (hard task)**: The hardest scenario involves an insider threat where all activity appears legitimate on the surface. The agent must correlate subtle behavioral anomalies (after-hours access patterns, anomalous file scope, job search history, HR context) to distinguish malicious intent from routine work.
- **Anti-loop penalties**: Repeated identical actions receive diminishing returns, encouraging diverse investigation strategies.

---

## Action / Observation Space

### Action Space (`IncidentAction`)

| Field | Type | Description |
|-------|------|-------------|
| `action_type` | `ActionType` (enum) | **Required.** One of: `examine_alert`, `query_logs`, `check_threat_intel`, `correlate_events`, `inspect_endpoint`, `check_user_history`, `classify_severity`, `contain_threat`, `escalate`, `close_as_false_positive`, `submit_report` |
| `log_source` | `str` | Log source for `query_logs`: `firewall`, `edr`, `proxy`, `auth`, `dns`, `email` |
| `query_filter` | `str` | Filter/keyword for log queries or threat intel lookups (e.g., an IP address, domain, file hash) |
| `endpoint_id` | `str` | Hostname or IP for `inspect_endpoint` |
| `user_id` | `str` | Username for `check_user_history` |
| `severity` | `Severity` | For `classify_severity`: `critical`, `high`, `medium`, `low`, `informational` |
| `threat_category` | `ThreatCategory` | For `classify_severity`: `malware`, `phishing`, `data_exfiltration`, `brute_force`, `insider_threat`, `lateral_movement`, `privilege_escalation`, `false_positive` |
| `containment_actions` | `List[ContainmentAction]` | For `contain_threat`: `isolate_host`, `block_ip`, `disable_account`, `quarantine_file`, `revoke_sessions` |
| `target` | `str` | Target for containment (hostname, IP, username, or file hash) |
| `report_summary` | `str` | Final report text for `submit_report` |
| `escalate_to` | `str` | Escalation target: `tier2`, `tier3`, `management`, `legal` |

### Observation Space (`IncidentObservation`)

| Field | Type | Description |
|-------|------|-------------|
| `alert_id` | `str` | Unique alert identifier |
| `alert_summary` | `str` | Human-readable alert description |
| `alert_source` | `str` | System that generated the alert |
| `timestamp` | `str` | Alert timestamp (ISO 8601) |
| `findings` | `str` | Results from the last action (log entries, TI data, endpoint details, etc.) |
| `evidence_collected` | `List[str]` | Evidence items gathered so far |
| `iocs_discovered` | `List[str]` | IOCs found during investigation |
| `action_result` | `str` | Feedback message from the environment |
| `available_actions` | `List[str]` | Currently available action types |
| `steps_remaining` | `int` | Steps left before timeout |
| `investigation_progress` | `float` | Fraction of critical evidence found (0.0–1.0) |
| `done` | `bool` | Whether the episode has ended |
| `reward` | `float` | Reward for the last action |

---

## Tasks

### Task 1: Phishing Email Triage (Easy)

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Max Steps** | 20 |
| **Expected Steps** | 8–15 |
| **Scenario** | Phishing email with malicious macro attachment. Email gateway flags suspicious `.xlsm` file with obfuscated PowerShell payload. Agent must determine if the payload executed and contain the threat. |
| **Key Skills** | Email header analysis, IOC identification, endpoint triage |
| **Ground Truth** | Severity: HIGH, Category: Phishing, Containment: Quarantine file + Isolate host |

### Task 2: Brute Force & Lateral Movement (Medium)

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Max Steps** | 25 |
| **Expected Steps** | 12–20 |
| **Scenario** | VPN brute-force from a Russian IP succeeds against an MFA-exempt service account, followed by RDP lateral movement to 3 internal servers including a domain controller. Attacker extracts NTDS.dit and exfiltrates via transfer.sh. |
| **Key Skills** | Attack chain reconstruction, lateral movement detection, credential theft analysis |
| **Ground Truth** | Severity: CRITICAL, Category: Lateral Movement, Containment: Disable account + Block IP + Revoke sessions + Isolate DC, Escalation: Tier 3 |

### Task 3: Insider Threat Investigation (Hard)

| Property | Value |
|----------|-------|
| **Difficulty** | Hard |
| **Max Steps** | 30 |
| **Expected Steps** | 15–25 |
| **Scenario** | A DLP alert for a director uploading 340MB to personal Google Drive. The user has legitimate access and authorized cloud storage. Agent must distinguish malicious data exfiltration from routine work by correlating behavioral anomalies: after-hours access surge, anomalous file scope, job search activity, recruiter communications, and HR context (passed over for promotion). |
| **Key Skills** | Behavioral analysis, intent determination, contextual correlation |
| **Ground Truth** | Severity: CRITICAL, Category: Insider Threat, Containment: Disable account + Revoke sessions, Escalation: Management |

---

## Grading & Reward

### Grader Scoring (0.0 – 1.0)

| Component | Weight | Description |
|-----------|--------|-------------|
| Investigation Completeness | 25% | Fraction of critical evidence items discovered |
| IOC Identification | 15% | Fraction of critical IOCs found |
| Severity Classification | 15% | Exact match = full, adjacent = partial, far off = penalized |
| Threat Categorization | 10% | Correct category identification |
| Containment Actions | 20% | Correct actions on correct targets, penalties for wrong targets |
| Report Quality | 10% | Keyword coverage, IOC mentions, report length |
| Efficiency | 5% | Bonus for completing within expected step range |

### Step-Level Reward Shaping

The reward function provides **meaningful signal over the full trajectory**, not just binary success/failure:

- **+0.03** per critical evidence item discovered
- **+0.02–0.03** per IOC identified
- **+0.10** for correct severity classification (+0.03 for adjacent)
- **+0.08** for correct threat categorization
- **+0.06** per correct containment action on correct target
- **+0.05** for correct escalation target
- **+0.01–0.04** for report quality components
- **−0.02** for repeating the same action 3+ times (anti-loop)
- **−0.04** per wrong containment target (penalizes destructive actions)
- **−0.05** for significantly wrong severity
- **−0.20** for closing a real incident as false positive
- **−0.10** for timeout without resolution

---

## Baseline Scores

Deterministic baseline (scripted optimal agent, seed=42):

| Task | Score | Steps |
|------|-------|-------|
| Easy (Phishing) | 0.9400 | 17 |
| Medium (Lateral Movement) | 0.8600 | 19 |
| Hard (Insider Threat) | 0.9175 | 18 |
| **Mean** | **0.9058** | — |

The deterministic baseline achieves high scores because it follows the optimal investigation path. An LLM agent would face the challenge of discovering this path through observation and reasoning alone.

---

## Setup & Usage

### Prerequisites

- Python 3.11+
- Docker Desktop / Docker Engine
- OpenEnv: `pip install openenv-core[core]`

### Local Development

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/incident-response-env.git
cd incident-response-env

# Install dependencies
pip install openenv-core[core] openai

# Run the server locally
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload

# In another terminal, run the baseline (see "Supported LLM Providers" below)
OPENAI_API_KEY=sk-... python baseline_inference.py --verbose
```

### Supported LLM Providers

The baseline inference script works with **any OpenAI-compatible API**. Set the appropriate environment variable or use `--api-key` / `--api-base` flags:

```bash
# OpenAI (default)
OPENAI_API_KEY=sk-... python baseline_inference.py --model gpt-4o-mini

# OpenRouter — access 200+ models (Gemini, Claude, Llama, Mistral, etc.)
OPENROUTER_API_KEY=sk-or-... python baseline_inference.py --model google/gemini-2.5-flash

# Anthropic (OpenAI-compatible endpoint)
ANTHROPIC_API_KEY=sk-ant-... python baseline_inference.py --model claude-sonnet-4-20250514

# Local models via Ollama
python baseline_inference.py --api-base http://localhost:11434/v1 --api-key dummy --model llama3

# Any OpenAI-compatible provider
python baseline_inference.py --api-key YOUR_KEY --api-base https://your-provider/v1 --model your-model

# Universal override (works with any provider)
LLM_API_KEY=... LLM_API_BASE=https://provider/v1 python baseline_inference.py --model model-name
```

**Environment variables** (auto-detected in order):
| Variable | Provider | API Base |
|----------|----------|----------|
| `LLM_API_KEY` + `LLM_API_BASE` | Any | Custom |
| `OPENROUTER_API_KEY` | OpenRouter | `https://openrouter.ai/api/v1` |
| `ANTHROPIC_API_KEY` | Anthropic | `https://api.anthropic.com/v1` |
| `OPENAI_API_KEY` | OpenAI | `https://api.openai.com/v1` |

### Docker

```bash
# Build
docker build -f server/Dockerfile -t incident-response-env:latest .

# Run
docker run -p 8000:8000 incident-response-env:latest

# Test
curl http://localhost:8000/health
curl http://localhost:8000/tasks
```

### OpenEnv CLI

```bash
# Validate
openenv validate --verbose

# Build
openenv build

# Push to Hugging Face
openenv push
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/reset` | POST | Reset environment (accepts `task_id`: easy/medium/hard) |
| `/step` | POST | Execute an action |
| `/state` | GET | Get current state |
| `/schema` | GET | Get action/observation JSON schemas |
| `/tasks` | GET | List all tasks with descriptions and action schema |
| `/grader` | GET | Get grader score after episode completion |
| `/baseline` | POST | Run deterministic baseline on all 3 tasks |

### Example Interaction

```python
import requests

BASE = "http://localhost:8000"

# Reset to easy task
r = requests.post(f"{BASE}/reset", json={"task_id": "easy", "seed": 42})
obs = r.json()["observation"]
print(obs["alert_summary"])

# Examine the alert
r = requests.post(f"{BASE}/step", json={"action": {"action_type": "examine_alert"}})
obs = r.json()["observation"]
print(obs["findings"])

# Query email logs
r = requests.post(f"{BASE}/step", json={"action": {
    "action_type": "query_logs",
    "log_source": "email"
}})
obs = r.json()["observation"]
print(obs["findings"])

# Check threat intel
r = requests.post(f"{BASE}/step", json={"action": {
    "action_type": "check_threat_intel",
    "query_filter": "185.220.101.42"
}})

# Classify severity
r = requests.post(f"{BASE}/step", json={"action": {
    "action_type": "classify_severity",
    "severity": "high",
    "threat_category": "phishing"
}})

# Contain the threat
r = requests.post(f"{BASE}/step", json={"action": {
    "action_type": "contain_threat",
    "containment_actions": ["quarantine_file", "isolate_host"],
    "target": "WS-JSMITH-PC"
}})

# Submit report
r = requests.post(f"{BASE}/step", json={"action": {
    "action_type": "submit_report",
    "report_summary": "Phishing email with macro dropper. C2 to 185.220.101.42. Endpoint isolated."
}})

# Check grader score
r = requests.get(f"{BASE}/grader")
print(r.json())  # {"score": 0.85, "breakdown": {...}}
```

---

## Project Structure

```
incident-response-env/
├── __init__.py                    # Package exports
├── models.py                      # Pydantic Action/Observation/State models
├── scenarios.py                   # 3 incident scenarios with evidence layers
├── client.py                      # EnvClient implementation
├── openenv.yaml                   # OpenEnv configuration
├── pyproject.toml                 # Python project metadata
├── baseline_inference.py          # LLM baseline inference script
├── README.md                      # This file
└── server/
    ├── __init__.py
    ├── app.py                     # FastAPI application with custom endpoints
    ├── incident_response_env_environment.py  # Core environment + graders
    ├── baseline_runner.py         # Deterministic baseline runner
    └── Dockerfile                 # Container definition
```

---

## Design Decisions

### Why Cybersecurity Incident Response?

1. **Novel domain for OpenEnv**: No existing SOC/security triage environment in the OpenEnv catalog
2. **Genuine real-world task**: Every enterprise SOC performs this exact workflow daily
3. **Rich action space**: 11 distinct action types spanning investigation and response
4. **Natural difficulty progression**: From clear-cut phishing → multi-stage attacks → ambiguous insider threats
5. **Multi-dimensional grading**: 7 scoring components prevent gaming via any single dimension

### Reward Design Philosophy

The reward function embodies the principle that **partial progress matters in security**:
- An analyst who discovers 3 out of 5 evidence items is better than one who finds 0
- Getting severity "high" when the truth is "critical" is better than calling it "low"
- Containing the right host but missing an IP block is still partially effective
- A report mentioning key IOCs is more valuable than a generic summary

This continuous reward signal enables RL training with meaningful gradient throughout the episode, avoiding the sparse reward problem that plagues many agent environments.

---

## License

BSD 3-Clause License

## Acknowledgments

Built on the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) framework by Meta PyTorch and Hugging Face.

Scenarios are inspired by real-world incident patterns documented in:
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [IBM X-Force Threat Intelligence Index](https://www.ibm.com/reports/threat-intelligence)
- [CrowdStrike Global Threat Report](https://www.crowdstrike.com/global-threat-report/)
