# Incident Response Triage Environment

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
2. **Classify** — Determine severity (critical/high/medium/low/info) and threat category (malware, phishing, lateral movement, insider threat, ransomware, supply chain, APT/zero-day, etc.)
3. **Respond** — Execute containment actions (isolate hosts, block IPs, disable accounts, quarantine files) with correct targets
4. **Report** — Submit a comprehensive incident report summarizing findings

### What Makes It Creative

- **Layered evidence discovery**: Investigation actions progressively reveal forensic artifacts. The agent must piece together the attack narrative from fragmented evidence across multiple data sources — just like a real analyst.
- **Multi-dimensional reward shaping**: Reward is not binary. The agent earns partial credit across 11 grading dimensions including evidence discovery, IOC identification, severity/category accuracy, containment completeness and precision, report quality, efficiency, escalation accuracy, evidence chain coherence, and phase discipline.
- **Progressive difficulty**: Six scenarios span easy to expert difficulty, from clear-cut phishing through multi-stage ransomware and supply chain attacks to an advanced persistent threat with zero-day exploitation and DNS tunneling C2.
- **Behavioral deception**: The insider threat scenario involves activity that appears legitimate on the surface. The agent must correlate subtle behavioral anomalies to distinguish malicious intent from routine work.
- **Anti-loop penalties**: Repeated identical actions receive increasing penalties, encouraging diverse investigation strategies.
- **Phase discipline**: Agents are rewarded for following proper IR workflow (investigate before classify, classify before contain) and penalized for phase violations.

### Self-Evolving Environment (Unique Feature)

This environment features a **self-evolving scenario generation engine** that creates an open-ended curriculum of cybersecurity incidents:

- **α-Curriculum Reward**: Automatically generates scenarios in the agent's "zone of proximal development" (target success rate ~50%)
- **POET-inspired Evolution**: Population of scenario genomes with mutation, crossover, and fitness-proportionate selection
- **Novelty Search**: Diversity pressure ensures the environment explores the full space of possible incidents
- **Elo Rating System**: Both agent and scenarios are rated, providing natural difficulty calibration
- **Procedural Generation**: 6 attack archetypes (phishing, lateral movement, insider threat, ransomware, supply chain, APT) with parameterized complexity

Use `task_id="evolved"` to activate self-evolving mode:
```python
# Activate self-evolving mode
obs = env.reset(task_id="evolved")
# ... run agent ...
# Trigger evolution based on performance
requests.post(f"{base_url}/env/evolve")
stats = requests.get(f"{base_url}/env/evolution-stats").json()
```

---

## Action / Observation Space

### Action Space (`IncidentAction`)

| Field | Type | Description |
|-------|------|-------------|
| `action_type` | `ActionType` (enum) | **Required.** One of: `examine_alert`, `query_logs`, `check_threat_intel`, `correlate_events`, `inspect_endpoint`, `check_user_history`, `classify_severity`, `contain_threat`, `escalate`, `close_as_false_positive`, `submit_report`, `analyze_malware`, `request_forensic_image` |
| `log_source` | `str` | Log source for `query_logs`: `firewall`, `edr`, `proxy`, `auth`, `dns`, `email` |
| `query_filter` | `str` | Filter/keyword for log queries, threat intel lookups, or malware analysis (e.g., an IP address, domain, file hash) |
| `endpoint_id` | `str` | Hostname or IP for `inspect_endpoint` or `request_forensic_image` |
| `user_id` | `str` | Username for `check_user_history` |
| `severity` | `Severity` | For `classify_severity`: `critical`, `high`, `medium`, `low`, `informational` |
| `threat_category` | `ThreatCategory` | For `classify_severity`: `malware`, `phishing`, `data_exfiltration`, `brute_force`, `insider_threat`, `lateral_movement`, `privilege_escalation`, `false_positive`, `ransomware`, `supply_chain`, `apt_zero_day` |
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
| **Scenario** | A DLP alert for a director uploading 340MB to personal Google Drive. The user has legitimate access and authorized cloud storage. Agent must distinguish malicious data exfiltration from routine work by correlating behavioral anomalies: after-hours access patterns, anomalous file scope, job search history, recruiter communications, and HR context (passed over for promotion). |
| **Key Skills** | Behavioral analysis, intent determination, contextual correlation |
| **Ground Truth** | Severity: CRITICAL, Category: Insider Threat, Containment: Disable account + Revoke sessions, Escalation: Management |

### Task 4: Ransomware Deployment & Encryption (Medium-Hard)

| Property | Value |
|----------|-------|
| **Difficulty** | Medium-Hard |
| **Max Steps** | 25 |
| **Expected Steps** | 15–22 |
| **Scenario** | EDR alerts on multiple hosts encrypting files simultaneously after hours. Entry via compromised RDP credentials to an admin workstation. Cobalt Strike beacon deployed, lateral movement via PsExec, then LockBit ransomware variant deployed to 3 servers. Ransom note found on each host. Agent must trace the full kill chain from initial RDP brute-force through C2 establishment, lateral movement, and encryption deployment. |
| **Key Skills** | Kill chain reconstruction, ransomware triage, C2 identification, multi-host containment |
| **Ground Truth** | Severity: CRITICAL, Category: Ransomware, Containment: Isolate hosts + Block IPs + Disable account + Revoke sessions, Escalation: Tier 3 |

### Task 5: Software Supply Chain Compromise (Hard-Plus)

| Property | Value |
|----------|-------|
| **Difficulty** | Hard-Plus |
| **Max Steps** | 30 |
| **Expected Steps** | 18–26 |
| **Scenario** | A trusted internal build tool (BuildForge) pushes a compromised update containing a backdoor that exfiltrates source code and deploys a cryptominer. The compromised package was signed with a stolen code-signing certificate. 8 developer workstations affected in a staged rollout. Agent must identify the supply chain vector, assess blast radius, and contain compromised CI/CD credentials. |
| **Key Skills** | Supply chain analysis, code-signing verification, CI/CD security, blast radius assessment |
| **Ground Truth** | Severity: CRITICAL, Category: Supply Chain, Containment: Isolate host + Quarantine file + Disable account + Revoke sessions, Escalation: Management |

### Task 6: APT with Zero-Day Exploitation (Expert)

| Property | Value |
|----------|-------|
| **Difficulty** | Expert |
| **Max Steps** | 35 |
| **Expected Steps** | 22–32 |
| **Scenario** | An Advanced Persistent Threat group ("Midnight Storm") exploits a zero-day in Confluence Server for initial access. They deploy a memory-resident implant (fileless), use living-off-the-land techniques for persistence, harvest credentials via DCSync, forge Golden Tickets, and establish covert C2 via DNS tunneling. The attack has been ongoing for 7 days before detection. Agent must unravel a sophisticated multi-stage intrusion spanning DNS tunneling C2, credential theft, lateral movement to Exchange and HR servers, and executive email exfiltration. |
| **Key Skills** | APT analysis, DNS tunneling detection, DCSync/Golden Ticket identification, fileless malware investigation |
| **Ground Truth** | Severity: CRITICAL, Category: APT/Zero-Day, Containment: Isolate hosts + Block IP + Disable accounts + Revoke sessions, Escalation: Tier 3 / Management / Legal |

---

## Grading & Reward

### Grader Scoring (0.0 – 1.0)

| Component | Weight | Description |
|-----------|--------|-------------|
| Investigation Thoroughness | 20% | Fraction of critical evidence items discovered |
| IOC Identification | 10% | Fraction of critical IOCs found |
| Severity Classification | 10% | Exact match = full, adjacent = partial, far off = penalized |
| Threat Categorization | 8% | Correct category identification |
| Containment Completeness | 15% | Fraction of required containment actions executed on correct targets |
| Containment Precision | 7% | Penalty for wrong-target containment actions |
| Report Quality | 8% | Keyword coverage, IOC mentions, report length |
| Efficiency | 5% | Bonus for completing within expected step range |
| Escalation Accuracy | 5% | Correct escalation target selection |
| Evidence Chain Coherence | 7% | Whether agent followed a logical investigation path before classifying |
| Phase Discipline | 5% | Proper IR workflow ordering (investigate → classify → contain → report) |

### Step-Level Reward Shaping

The reward function provides **meaningful signal over the full trajectory**, not just binary success/failure:

- **+0.03** per critical evidence item discovered
- **+0.02–0.03** per IOC identified
- **+0.02** per new log source queried (discovery bonus for investigation breadth)
- **+0.03** depth bonus for checking threat intel on 3+ critical IOCs
- **+0.10** for correct severity classification (+0.03 for adjacent)
- **+0.08** for correct threat categorization
- **+0.06** per correct containment action on correct target
- **+0.05** for correct escalation target
- **+0.05** breadth bonus if all 6 log sources queried by report time
- **+0.05** time pressure bonus for completing within 60% of max steps (+0.03 within 80%)
- **+0.03** evidence chain coherence bonus for investigating before classifying
- **+0.01–0.04** for report quality components
- **−0.05** for repeating the same action 3+ times (anti-loop)
- **−0.05** per wrong containment target
- **−0.03** phase violation: contain before classify
- **−0.10** phase violation: report without classify
- **−0.05** for significantly wrong severity
- **−0.02** for wrong escalation target
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
| Medium-Hard (Ransomware) | — | — |
| Hard-Plus (Supply Chain) | — | — |
| Expert (APT Zero-Day) | — | — |

The deterministic baseline achieves high scores because it follows the optimal investigation path. An LLM agent faces the challenge of discovering this path through observation and reasoning alone. Baseline scores for new tasks will be populated after initial runs.

---

## LLM Agent Architecture

The `baseline_inference.py` agent implements the following techniques:

### State-Goal Reflection
At each step, the agent reflects on its **current state relative to the investigation goal** before choosing an action — preventing goal-drift and hallucination that plague standard reactive agents.

### Investigation Planning
The agent generates a **multi-step investigation plan** upfront (INVESTIGATE → CLASSIFY → CONTAIN → REPORT) and tracks progress against it, enabling structured and methodical incident response.

### SOC Playbook Structure
The phased workflow mirrors real-world SOC incident response playbooks (NIST SP 800-61, SANS IR framework), ensuring agents follow proper IR procedures and phase discipline.

### Anti-Loop Detection
Explicit **repetition detection** and forced progression prevent the agent from getting stuck in action loops — a common failure mode for LLM agents in multi-step environments.

### Evidence-Grounded Feedback
Each step includes a **structured state summary** showing discovered evidence, identified IOCs, queried log sources, and current investigation phase — giving the LLM explicit grounding for its next decision.

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

The baseline inference script works with **any OpenAI-compatible API**. Just set `OPENAI_API_KEY` and optionally `OPENAI_BASE_URL`:

```bash
# OpenAI (default — just set API key)
OPENAI_API_KEY=sk-... python baseline_inference.py --model gpt-4o-mini

# OpenRouter — access 200+ models (Gemini, Claude, Llama, Mistral, etc.)
OPENAI_API_KEY=sk-or-... OPENAI_BASE_URL=https://openrouter.ai/api/v1 python baseline_inference.py --model google/gemini-2.5-flash

# Anthropic (OpenAI-compatible endpoint)
OPENAI_API_KEY=sk-ant-... OPENAI_BASE_URL=https://api.anthropic.com/v1 python baseline_inference.py --model claude-sonnet-4-20250514

# Local models via Ollama
python baseline_inference.py --api-base http://localhost:11434/v1 --api-key dummy --model llama3

# Any OpenAI-compatible provider (explicit flags)
python baseline_inference.py --api-key YOUR_KEY --api-base https://your-provider/v1 --model your-model
```

**Environment variables:**
| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key (required) |
| `OPENAI_BASE_URL` | API base URL (optional, defaults to `https://api.openai.com/v1`) |

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
| `/reset` | POST | Reset environment (accepts `task_id`: easy/medium/hard/medium_hard/hard_plus/expert) |
| `/step` | POST | Execute an action |
| `/state` | GET | Get current state |
| `/schema` | GET | Get action/observation JSON schemas |
| `/tasks` | GET | List all 6 tasks with descriptions and action schema |
| `/grader` | GET | Get grader score after episode completion |
| `/baseline` | POST | Run deterministic baseline on all 6 tasks |
| `/env/evolve` | POST | Trigger evolution of the scenario population |
| `/env/evolution-stats` | GET | Get evolution engine statistics |

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
├── scenarios.py                   # Backward-compat re-export (scenarios live in tasks/)
├── tasks/                         # All 6 incident scenarios
│   ├── __init__.py                # Exports SCENARIOS, TASK_DEFINITIONS
│   ├── base.py                    # Shared dataclasses (LogEntry, Scenario, etc.)
│   ├── task_easy_phishing.py      # Easy: Phishing email triage
│   ├── task_medium_lateral.py     # Medium: Brute force & lateral movement
│   ├── task_hard_insider.py       # Hard: Insider threat investigation
│   ├── task_medium_ransomware.py  # Medium-Hard: Ransomware deployment
│   ├── task_hard_supply_chain.py  # Hard-Plus: Supply chain compromise
│   └── task_expert_apt_zeroday.py # Expert: APT with zero-day exploitation
├── self_evolving/                 # Self-evolving scenario generation engine
│   ├── __init__.py                # Package exports
│   ├── evolution_engine.py        # α-Curriculum, POET mutations, Elo ratings
│   └── scenario_generator.py     # Procedural scenario generation from genomes
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
3. **Rich action space**: 13 distinct action types spanning investigation and response
4. **Natural difficulty progression**: From clear-cut phishing → multi-stage ransomware → supply chain compromise → sophisticated APT campaigns
5. **Multi-dimensional grading**: 11 scoring components prevent gaming via any single dimension

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
