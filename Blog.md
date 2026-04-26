# Training AI Agents to Think Like a SOC Team: Multi-Agent RL for Incident Response

*By Dinmay Kumar Brahma — PyTorch OpenEnv Hackathon, Round 2*

---

There's a problem that every Security Operations Center in the world deals with every single day: alert fatigue.

A mid-sized enterprise gets somewhere north of 4,000 security alerts per day. Real SOC teams don't throw one analyst at all 4,000 of them. They use a tiered structure — a junior analyst does the first pass, escalates to a senior analyst, who escalates to an IR lead for the truly dangerous incidents. Each person brings a different lens. Each person has a different piece of the puzzle.

So when I was thinking about what environment to build for this hackathon, I kept coming back to that structure. Not "train a single AI to triage alerts." But: **train a team of AI agents that coordinate, argue, and escalate the same way a real SOC team does.**

That's what this project became.

---

## What We Built

The environment is called `soc-marl-env` — a Multi-Agent Reinforcement Learning environment for SOC incident response, built on top of OpenEnv.

At its core, three agents play three distinct roles:

- **L1 (Triage Agent)** — Only sees raw log fragments and initial alert summaries. Can query logs, run basic pattern matching. Can't escalate on its own.
- **L2 (Senior Analyst)** — Gets L1's observations plus EDR telemetry and threat intel access. Identifies IOCs, correlates across sources.
- **L3 (IR Lead)** — Has the full picture but acts last. Owns the final severity classification, containment decision, and executive report.

Each agent operates in a **partially observable environment**. L1 doesn't see what L2 sees. L2 doesn't see L3's historical case knowledge. This is intentional — it forces the agents to *communicate*, not just independently solve.

The communication backbone is a `SharedInvestigationBoard` (built using the ReSCOM protocol from AAMAS 2025), where agents post structured messages that others can read. Think of it like a shared Slack channel inside the SOC — except every message is a structured observation the other agents can use as part of their policy.

---

## The Training Setup

I trained on **Qwen2.5-3B-Instruct** with LoRA (r=64) using **GRPO** from HuggingFace TRL — all on a free **T4 GPU in Google Colab**. No fancy hardware. Just a T4, Unsloth's 4-bit quantization, and a lot of patience.

The reward function has six components, directly aligned with the environment's grader:

| Signal | Weight | What it checks |
|--------|--------|----------------|
| Format/Phase discipline | 0.11 | `<think>` reasoning before classification tags |
| Evidence/IOC discovery | 0.19 | How many critical IOCs were identified |
| Severity classification | 0.14 | Exact severity level accuracy |
| Containment quality | 0.17 | Correct containment actions matched |
| Investigation efficiency | 0.10 | Focused output, not verbose rambling |
| Category classification | 0.09 | Incident type accuracy |

On top of that, two bonus signals:

- **CTDE coordination proxy** — a centralized critic estimates how well the joint observations across L1/L2/L3 would coordinate, rewarding multi-faceted responses
- **H-MARL reasoning bonus** — rewards *depth* of reasoning inside `<think>` blocks: hypothesis generation, cross-referencing, causal chains

Training also uses an **α-Curriculum** (inspired by GenEnvPOET) that dynamically reorders tasks by learning frontier. Tasks where the agent's success rate is near 0.5 — not too easy, not impossibly hard — get prioritized. This updates live every training step based on actual rollout scores.

---

## What Actually Happened During Training

Here's the reward curve from the 100-step run on T4:

![GRPO Training Reward Curves](./grpo_reward_curves.png)

Honestly? Mixed results — and I'd rather be upfront about that than pretend everything went perfectly.

**What worked:**

Format discipline converged fast. By step 30, the model had learned to always structure its reasoning inside `<think>` blocks before emitting any classification tags. That sounds small, but it's not — it means the model learned *procedural discipline*: reason first, classify second. The H-MARL reasoning bonus also grew by ~73% relative over training, meaning the internal reasoning genuinely got richer and more hypothesis-driven.

The α-Curriculum did exactly what it was designed to do. By the end of training, it correctly identified that `hard` and `easy` scenarios were no longer on the learning frontier and shifted sampling weight toward `medium` and `expert` difficulty.

**What didn't work (and why):**

The efficiency signal collapsed. The model found a sneaky reward hack — writing longer outputs scored higher on format, IOC discovery, and H-MARL simultaneously. So it bloated. Classic Goodhart's Law. Fixed with a hard token cap at 2,000: no partial credit above that, period.

Severity exact-match accuracy was 0% in EUREKA's independent trajectory evaluation, even though the training reward showed ~0.70. The gap exists because training used a continuous distance function (off-by-one = partial credit), while EUREKA measures strict exact match. Fixed: binary reward, small partial credit only for ±1 level.

KL divergence went from 0.000019 at step 1 to 0.109 at step 100 — roughly a 5,700x increase. The LoRA adapter moved aggressively away from the base model's priors, dragging category accuracy and efficiency down with it. Fix: β raised from 0.1 to 0.15, learning rate dropped from 2e-4 to 1e-4.

These aren't failures I'm embarrassed about. They're exactly the kind of reward engineering bugs that you only find by actually running the training loop.

---

## The Research Stack (Nine Subsystems, All Real)

This isn't a demo with placeholder modules. Every subsystem is a real implementation tied to actual research:

| Module | What it does | Inspired by |
|--------|-------------|-------------|
| `alphacurriculum.py` | Live task ordering by learning frontier | GenEnvPOET |
| `redteam/agent.py` | Adversarial red team with 7 attack types | AdvEvo-MARL (NeurIPS 2025) |
| `multiagent/tom.py` | Adaptive Theory-of-Mind across L1/L2/L3 | arXiv 2603.16264 |
| `multiagent/knowledgegraph.py` | Persistent incident memory graph | DAMCS (arXiv 2502.05453) |
| `multiagent/communication.py` | Structured inter-agent messages | ReSCOM (AAMAS 2025) |
| `multiagent/overseer.py` | Policy violation monitoring | Fleet AI Sub-Theme |
| `eureka/rewarddesigner.py` | Reflective reward refinement | EUREKA (NeurIPS 2023) |
| `training/ctde.py` | Centralized training, decentralized execution | CADP (IJCAI 2025) |
| `training/hmarl.py` | Hierarchical skill discovery | H-MARL (IEEE 2025) |

The Red Team agent is probably the most interesting piece. It runs in parallel with the Blue Team (our three-agent SOC), injecting adversarial perturbations — fake log entries, timestamp manipulation, DNS decoys, alert flooding. As the Blue Team gets better, the Red Team has to get smarter. That's the co-evolutionary loop that keeps the environment genuinely challenging rather than statically hard.

---

## The "Isn't this just one model?" Question

I've been asked this a few times, so let me address it directly.

Yes, there's one set of weights. We use CTDE — Centralized Training with Decentralized Execution. During training on the T4, one Qwen2.5-3B model learns a policy that expresses L1, L2, or L3 behavior depending on the role context in the prompt. During inference, three instances run with role-specific observation spaces, communicating through the SharedInvestigationBoard.

This was a deliberate architecture choice, not a hardware limitation workaround. True multi-model training on a T4 with three separate 3B models is just not feasible. But the behavior *does* diverge meaningfully by role — L1 is conservative and flags broadly, L2 correlates and filters, L3 synthesizes and decides. The role specialization is real.

---

## The Scenario Set

Six scenarios, difficulty 0.15 to 0.85:

- **Easy** — High-severity phishing, 4 obvious IOCs
- **Medium** — Critical ransomware, some decoy evidence
- **Hard** — Critical APT, 8 evidence sources, many misleading
- **Medium-Hard** — Critical lateral movement, partial observability
- **Hard-Plus** — Critical data exfiltration with counter-forensics
- **Expert** — Critical zero-day APT, red team active, 8 evidence sources

Each scenario has ground-truth severity, category, required containment actions, critical IOCs, and MITRE ATT&CK mappings. The reward function grades against all of them. It's a structured rubric, not vibes.

---

## Why This Matters

SOC analysts burn out. The alert volume is unsustainable. AI assistance in incident response is coming regardless — the question is whether the models that get deployed actually *reason about security* or just pattern-match their way to the right-sounding answer.

Those two things look identical on a demo. They don't look identical when a real incident hits.

The gap between them is exactly what this environment is designed to measure. An agent that scores well here doesn't just guess "critical" and list some keywords. It reasons through evidence, correlates across log sources, generates alternative hypotheses, and writes containment actions that map to actual infrastructure targets.

That's a much harder problem. And it's the one worth solving.

---

*Code: [github.com/dino65-dev/incident-response-env](https://github.com/dino65-dev/incident-response-env)*  
*Space: [huggingface.co/spaces/dino65-dev/soc-marl-env](https://huggingface.co/spaces/dino65-dev/soc-marl-env)*  
*Training notebook: GRPO_SOC_Training.ipynb (in repo)*
