# Research-Backed Deep Upgrades: Making Your SOC Environment Fantastically Competitive

## Why Deeper Research Changes Everything

The previous strategy covered architecture basics. This document goes further — pulling from six distinct research frontiers (2023–2026) to give your `incident-response-env` properties that **no other team will have** because they require knowing the right papers. Each upgrade is grounded in published research and maps directly to your existing codebase.

***

## Upgrade 1: Adaptive Theory of Mind (A-ToM) for Agent Coordination

**The Core Problem Your Current Design Has:** Your agents coordinate through a shared board, but they have no model of *each other's reasoning depth*. Research shows this causes "ToM misalignment" — two agents at different reasoning depths can catastrophically interfere even when cooperating.[^1]

**The Research Fix:** The A-ToM paper (arXiv 2026) introduces the first adaptive Theory of Mind agent for LLMs that estimates its partner's ToM order in real time and structurally aligns with it. In your environment this means:[^2][^1]

- **L1 (Triage)** operates at ToM-0: it reasons only about direct evidence, not what L2 believes
- **L2 (Senior Analyst)** operates at ToM-1: it models L1's beliefs to avoid redundant queries
- **L3 (IR Lead)** operates at ToM-2: it models what L2 *thinks L1 discovered*, enabling genuine conflict resolution

**Practical Implementation:** Add a `tom_order` field to each agent's observation. After each exchange, the receiving agent runs a lightweight "belief prediction" module: *"Given what L1 just told me, what does L1 believe about this incident?"* If the prediction is wrong, the ToM order is downgraded. This is the `A-ToM` algorithm from the paper, using the Hedge online learning update to adjust weights across `{ToM-0, ToM-1, ToM-2}` hypotheses.[^2]

**Why This Wins:** No existing OpenEnv environment implements ToM-aware agent coordination. A 2025 CMU dissertation showed that agents equipped with ToM achieve consistently superior performance in competitive AND cooperative multi-agent scenarios vs. baselines. It directly satisfies the theme requirement: *"agents model the beliefs and incentives of others"*. Judges will recognize this as genuinely novel.[^3][^1]

***

## Upgrade 2: Red Team vs. Blue Team Adversarial Loop (The Most Impactful Addition)

**The Core Problem:** Your current environment only has a *defender* (the SOC agent). There is no attacker. This is a huge missed opportunity because the best-researched approach for getting robust defenders is adversarial co-training.

**The Research Fix:** CAGE Challenge 4 — the gold standard cybersecurity MARL benchmark — is built exactly on an attacker/defender structure with multiple defensive agents. A 2025 paper on Hierarchical MARL for CAGE 4 showed H-MARL significantly outperforms flat MARL on partial-observability defense tasks. Meanwhile, AdvEvo-MARL (NeurIPS 2025) demonstrated that jointly training attackers and defenders **reduces attack success rates to below 20%** while improving task accuracy by up to +3.67% — compared to baselines reaching 38.33% ASR.[^4][^5][^6][^7][^8]

**Practical Implementation — 4th Agent: The Red Team Agent**

Add a `red_team_agent` that acts *simultaneously* with the SOC team, on the **opposite side of the same episode**:

```python
class RedTeamAgent:
    """Attacker agent co-evolving with the SOC defender team."""
    action_space = [
        "inject_false_log",          # Inject a misleading log entry to waste L1's steps
        "cover_tracks",              # Remove critical evidence from the log pool
        "lateral_move_silently",     # Trigger a lateral movement below the alert threshold
        "deploy_decoy_ioc",          # Plant a fake IOC to misdirect threat intel queries
        "accelerate_attack",         # Reduce the time window available to defenders
        "exfiltrate_data"            # Terminal action: succeed if not contained before this
    ]
    reward: float  # +1.0 if exfiltration succeeds, decreasing partial rewards for each step defenders are confused
```

The SOC team's reward now becomes: the **differential** between their containment quality and the red team's disruption quality. This creates the adversarial dynamic the theme explicitly demands ("cooperation, competition, negotiation").[^8]

**The AdvEvo-MARL Training Loop for This:**
1. Train the red team agent on a batch of defender trajectories (it learns the defenders' weaknesses)
2. Train defender agents against the evolved red team (they learn to be robust)
3. Repeat; both co-evolve
4. Measure: red team's ASR should decrease over training, defender reward should increase

This is a **direct bonus prize target** for the Fleet AI sub-theme (oversight of adversarial AI agents).[^7]

***

## Upgrade 3: LLM-as-Reward-Designer via EUREKA/CARD Loop

**The Core Problem:** Your current reward function has 11 hand-designed components. These are good, but they are brittle and may not capture the actual optimal investigation behavior. Research shows human-designed rewards have systematic blind spots.

**The Research Fix:** EUREKA (NVIDIA/CMU, NeurIPS 2023) showed that GPT-4 as a reward code generator **outperforms human expert rewards on 83% of tasks** with an average 52% improvement, using only environment source code as context. The newer CARD framework (2025) iteratively refines reward code without per-iteration RL training, reducing token cost while preserving or exceeding human-level reward quality.[^9][^10][^11]

**Practical Implementation:**

```python
def eureka_reward_refinement_loop(env_source_code: str, 
                                   task_description: str,
                                   training_trajectories: List[Trajectory],
                                   n_iterations: int = 5):
    """
    EUREKA-inspired iterative reward improvement.
    Feed environment code + task description + trajectory stats to GPT-4.
    GPT-4 generates reward code candidates → evaluate → reflect → improve.
    """
    reward_candidates = llm.generate_reward_functions(
        context=env_source_code,
        task=task_description,
        n_candidates=16  # Large batch evaluated in parallel
    )
    best_reward = evaluate_on_training_episodes(reward_candidates)
    
    for iteration in range(n_iterations):
        reflection = summarize_trajectory_stats(training_trajectories)
        improved_reward = llm.refine_reward(
            current_reward=best_reward,
            reflection=reflection,  # "Agents loop on log queries too much" → add anti-loop term
            feedback_type="in_context"
        )
        best_reward = max(improved_reward, best_reward, key=lambda r: eval_score(r))
    
    return best_reward
```

**Why This Is Practically Fantastic:** Point this at your `incident_response_env_environment.py` and say: *"Our reward function wasn't hand-tuned — it was co-designed by an LLM running EUREKA-style reward reflection over 500 training trajectories."* Judges from NVIDIA, Meta, HuggingFace will recognize EUREKA immediately. This distinguishes your project from every other team doing manual reward engineering.[^11][^9]

You can also apply **Eurekaverse** (the environment-level equivalent): instead of generating reward functions, use an LLM to generate *new scenario variants* by mutating your existing scenario code in Python. This replaces your current POET-genome mutation with semantically richer LLM-driven mutations — the Eurekaverse paper showed this produces more diverse and learnable environments than hand-designed curricula.[^12][^13][^14][^15]

***

## Upgrade 4: CTDE (Centralized Training, Decentralized Execution) as Training Paradigm

**The Core Problem:** Naively training three agents with separate GRPO runs causes non-stationarity — each agent's policy shifts are invisible to the others, causing the joint policy to diverge.[^16][^17]

**The Research Fix:** Centralized Training with Decentralized Execution (CTDE) is the dominant paradigm in MARL, and a 2025 paper directly applying it to LLM multi-agent systems with GRPO showed a **3× increase in task processing speed** with 98.7% structural consistency in collaborative tasks. The framework: during training, a centralized critic has access to all agents' observations and actions; during inference, each agent acts using only its local observation.[^18][^17][^16]

**Practical Implementation:**

```python
class CentralizedCritic(nn.Module):
    """
    Has access to full joint observation during training only.
    Discarded at inference time — each agent runs decentralized.
    """
    def __init__(self):
        self.joint_obs_encoder = TransformerEncoder(
            input_dim=len(all_agent_obs)  # Full visibility during training
        )
        self.value_head = nn.Linear(hidden_dim, 1)
    
    def forward(self, l1_obs, l2_obs, l3_obs, overseer_obs, global_state):
        joint = torch.cat([l1_obs, l2_obs, l3_obs, overseer_obs, global_state], dim=-1)
        return self.value_head(self.joint_obs_encoder(joint))

# Each agent's policy only sees its own obs at inference time
class L1TriagePolicy(nn.Module):
    def forward(self, my_obs_only):  # No joint info at execution
        return self.policy_net(my_obs_only)
```

The CADP framework (IJCAI 2025) further improves CTDE by allowing explicit message channels during training that are pruned away at inference — ensuring decentralized execution while enabling richer joint-policy exploration during training. This is directly implementable as "message advice" from your L2 agent to L1 during GRPO training only.[^19][^20]

**Why This Matters for Demos:** When you show reward curves, you can point out that the centralized critic stabilizes learning (lower variance in reward curves = cleaner demos). The theoretical justification is rock-solid — judges who know MARL will immediately recognize CTDE as the right approach.[^16]

***

## Upgrade 5: Emergent Communication Protocol with ReSCOM Curriculum

**The Core Problem:** Your agents communicate via structured JSON actions on the `SharedInvestigationBoard`. This is hand-designed communication. The research shows a more powerful approach: let the agents *develop their own communication protocol* through reward shaping.

**The Research Fix:** ReSCOM (AAMAS 2025) introduces reward-shaped curricula specifically for learning-to-communicate (L2C) in MARL, showing a **16.3–21.9% improvement** over baselines by progressively shifting agent focus from "how to communicate" to "when to communicate". The three reward shapes they design are directly applicable:[^21]

1. **Discrete curriculum**: initially reward any communication; later reward only communication that changes the receiver's action
2. **Continuous curriculum (type 1)**: linearly decrease communication reward weight as training progresses
3. **Continuous curriculum (type 2)**: use the agent's task performance as the gating signal for communication reward

**Practical Implementation — Add a Communication Reward Layer:**

```python
def communication_reward(sender_id, receiver_id, message, 
                          receiver_action_before, receiver_action_after,
                          training_step, total_steps):
    """
    Phase 1 (steps 0-200): Reward any communication attempt (+0.02)
    Phase 2 (steps 200-500): Only reward communication that changes receiver's action (+0.04)
    Phase 3 (steps 500+): Only reward communication that improves team reward (+0.06)
    """
    curriculum_phase = training_step / total_steps
    
    if curriculum_phase < 0.4:
        return 0.02 if message is not None else 0.0
    elif curriculum_phase < 0.8:
        action_changed = (receiver_action_after != receiver_action_before)
        return 0.04 if action_changed else -0.01
    else:
        return 0.06 if team_reward_improved else -0.02
```

This means your environment trains agents to **develop efficient communication protocols organically**, rather than relying on your hand-defined `SharedInvestigationBoard` schema. Emergent communication is one of the most exciting areas in multi-agent AI (the theme says *"emergent strategic behavior"* — this is it).[^22][^23]

***

## Upgrade 6: Hierarchical MARL (H-MARL) with LLM-Guided Skill Discovery

**The Core Problem:** Your 3-agent team handles coordination at one flat level. For the Expert APT scenario (35 steps), this flat structure breaks down — the policy space is too large.

**The Research Fix:** The 2025 IEEE paper "Agentic AI for Cyber Defense: LLM-Guided Hierarchical Multi-Agent Reinforcement Learning" validated on CAGE Challenge 4 showed that LLM-guided HRL achieves **faster convergence AND improved performance** vs. flat MARL baselines for complex cyber defense. The key idea: LLMs identify "semantically meaningful skills" (e.g., "pivot investigation", "dual-log correlation", "cross-agent IOC validation") and generate intrinsic reward functions for each sub-skill.[^24]

**Practical Implementation:**

```python
# LLM generates sub-skills and intrinsic rewards from environment description
sub_skills = llm.identify_skills("""
    Environment: Multi-agent SOC incident response.
    Agents: L1 (triage), L2 (senior), L3 (IR lead).
    Describe 5-7 coordination sub-skills that, if mastered, 
    lead to optimal team performance.
""")
# Example output: ["lead_handoff", "evidence_dedup", "belief_sync", 
#                  "ioc_cross_validation", "containment_coordination"]

for skill in sub_skills:
    intrinsic_reward_fn = llm.generate_reward_code(skill, env_source_code)
    # Each skill has its own reward signal; agents learn sub-skills then compose them
```

This creates a **two-level policy hierarchy**: a high-level manager (which sub-skill to execute) and low-level executors (the actual agent actions). Research showed this reduces sample complexity significantly in large cyber defense environments.[^24][^4]

***

## Upgrade 7: Nash Q-Network for Attacker-Defender Equilibrium (Game Theory Layer)

**The Core Problem:** If you add a Red Team agent but train it with standard GRPO, it may not converge to a stable adversarial equilibrium — it'll oscillate.

**The Research Fix:** The Nash Q-Network paper (arXiv 2025) explicitly addresses MARL for cybersecurity as a two-player zero-sum Markov game, incorporating Nash equilibrium convergence with PPO + DQN hybrid. Key insight: if both the red team and blue team converge to a Nash equilibrium, you have a *provably stable* adversarial environment. This is the strongest theoretical guarantee you can make to judges.[^25]

**Simplified Application:** You don't need to implement full Nash Q-learning. Instead:
- Add a **population-based training (PBT)** wrapper around your red team agent, following PoolFlip's Flip-PSRO approach — train a *population* of red team agents with different strategies, then test defenders against all of them[^26]
- Defenders trained against a diverse population are 2× more effective at generalizing to unseen attack strategies[^26]
- This is directly implementable as a `red_team_population: List[RedTeamPolicy]` and sampling randomly at each episode reset

***

## Upgrade 8: DAMCS — Hierarchical Knowledge Graph Memory for Long-Horizon Coordination

**The Core Problem:** Your agents currently have no persistent memory across episodes. In the Expert APT scenario (35 steps), L1 may forget early DNS evidence by the time L3 needs it for the report.

**The Research Fix:** DAMCS (2025) introduces a multi-modal memory system organized as a **hierarchical knowledge graph** and structured communication protocol for LLM-powered decentralized agents, outperforming both standard MARL and LLM baselines on long-horizon tasks. The key component: each agent maintains a personal knowledge graph of discovered evidence, and publishes only *high-priority nodes* to the shared board rather than raw log entries.[^27]

**Practical Implementation:**

```python
class AgentMemoryGraph:
    """Hierarchical knowledge graph for persistent agent memory."""
    def __init__(self):
        self.nodes = {}  # {entity: {type, confidence, discovered_by, step}}
        self.edges = []  # {from_entity, relation, to_entity, weight}
    
    def add_evidence(self, entity, evidence_type, source_log, confidence):
        """Add a new node; auto-connect to related entities."""
        self.nodes[entity] = {
            "type": evidence_type, 
            "confidence": confidence,
            "step": current_step
        }
        # Auto-link: if entity is an IP, connect to all hostnames that contacted it
        self._auto_link(entity)
    
    def publish_to_shared_board(self, threshold=0.7):
        """Only publish high-confidence nodes to reduce communication overhead."""
        return {k: v for k, v in self.nodes.items() if v["confidence"] >= threshold}
```

The key benefit: agents stop re-discovering the same evidence (reducing duplicate query penalties), and the knowledge graph naturally encodes the evidence chain that your `Evidence Chain Coherence` reward component grades. Judges who know NLP and knowledge graphs will see this as a sophisticated architectural choice.

***

## Upgrade 9: Adversarial Curriculum Using a Generative Attacker World Model

**Going beyond POET:** Your current self-evolving engine uses parametric mutations of pre-defined scenario genomes. The 2025 paper "Learning an Adversarial World Model for Automated Curriculum Generation" introduces a generative Attacker agent that **learns an implicit world model** to synthesize increasingly difficult challenges. The Attacker's goal: generate scenarios at the Defenders' frontier of capability. This produces emergent flanking tactics and coordinated multi-vector attacks — things your current POET engine cannot generate.[^28]

**Practical Implementation:** Treat your `ScenarioGenerator` as the Attacker (generating incident parameters) and your SOC team as the Defenders. The Attacker is optimized with a reward that is: `+1` whenever the SOC team fails (reward < 0.5). This creates a co-evolutionary arms race where new attack patterns emerge that weren't in your original 6 scenarios.[^28]

The critical distinction from your existing POET engine:
- **POET**: mutates fixed scenario *parameters* (difficulty, IOC count, attack type)
- **Generative World Model Attacker**: learns to synthesize *novel attack narratives* from the SOC team's behavioral history

***

## Practical Priority Matrix

These 9 upgrades are not equally tractable before April 25. Here is the honest priority ranking:

| Upgrade | Research Impact | Impl. Difficulty | Judge Recognition | Do Before Onsite? |
|---|---|---|---|---|
| **Red Team/Blue Team Adversarial Loop** | Very High | Medium | Very High (CAGE4, AdvEvo-MARL) | ✅ Yes |
| **A-ToM (Adaptive Theory of Mind)** | Very High | Medium | Very High (March 2026 paper) | ✅ Yes |
| **EUREKA-style Reward Refinement** | High | Low (just LLM prompting) | Very High (NVIDIA paper) | ✅ Yes |
| **CTDE Training Architecture** | High | Medium | High (MARL standard) | ✅ Yes |
| **ReSCOM Communication Curriculum** | Medium-High | Low (reward shaping only) | Medium-High | ✅ Yes |
| **DAMCS Knowledge Graph Memory** | High | High | High (NLP audience) | ⚠️ If time allows |
| **Hierarchical MARL (LLM skill discovery)** | High | High | Very High (CAGE4 paper) | ⚠️ If time allows |
| **Nash Q-Network / PBT population** | Medium | Medium | Medium (theoretical) | ⚠️ Optional |
| **Generative Attacker World Model** | Very High | Very High | Very High | ❌ Post-onsite research direction |

***

## The Narrative That Ties It All Together

When you pitch, frame these upgrades not as individual features but as **one coherent research narrative**:

> "Existing SOC AI trains a single agent in isolation. We built the first environment that trains a *team* with three research-validated properties: **Theory of Mind** (agents model each other's beliefs using A-ToM), **adversarial robustness** (co-evolutionary red team forces defenders to generalize, following AdvEvo-MARL), and **LLM-designed rewards** (EUREKA-style iterative reward reflection replaced hand-tuning). Together, these three properties produce a SOC team that is not just accurate — it is *adaptively intelligent*."

This narrative directly maps to the three most-cited research directions in the 2026 multi-agent LLM literature, giving you intellectual credibility that pure engineering teams cannot match.[^29][^1][^7]

***

## The "Wow" Demo Moment

At the end of the expert APT scenario demo, freeze the playback and show:

1. **The knowledge graph** of L1's discovered evidence — visually show the nodes and edges
2. **The belief state of L2** at step 15: *"L2 believes L1 has found the DNS tunneling IOC with 87% confidence"* — this is the A-ToM output
3. **The red team's action at step 12**: "inject_false_log → planted fake phishing IOC" — show how the SOC team *ignored* it because the knowledge graph's confidence weighting down-scored it
4. **The reward curve** showing the red team's disruption attempts failing as training progresses

This turns a cybersecurity demo into a **live demonstration of multi-agent AI intelligence principles** — that is what wins hackathons at Cerebral Valley level.

---

## References

1. [Adaptive Theory of Mind for LLM-based Multi-Agent Coordination](https://arxiv.org/abs/2603.16264) - Theory of Mind (ToM) refers to the ability to reason about others' mental states, and higher-order T...

2. [Adaptive Theory of Mind for LLM-based Multi-Agent Coordination](https://chatpaper.com/paper/253581) - Adaptive Theory of Mind Agent (A-ToM): This agent dynamically estimates its partner's Theory of Mind...

3. [[PDF] Theory of Mind in Multi-Agent Systems - Carnegie Mellon University](https://ml.cmu.edu/research/phd-dissertation-pdfs/ioguntol_phd_mld_2025.pdf) - In this work we present an interpretable family of approaches to modeling theory of mind within arti...

4. [[PDF] Hierarchical Multi-agent Reinforcement Learning for Cyber Network ...](https://arxiv.org/pdf/2410.17351.pdf) - In this work, we focus on the. CybORG CAGE 4 cybersecurity MARL framework [12], which is a realistic...

5. [TTCP CAGE Challenge 4: Challenge Details](https://cage-challenge.github.io/cage-challenge-4/pages/) - This CAGE Challenge 4 (CC4) returns to a defence industry enterprise environment, and introduces a M...

6. [Cyber Autonomy Gym for Experimentation (CAGE) Challenge 4 | DST](https://www.dst.defence.gov.au/call-submissions-cyber-autonomy-gym-experimentation-cage-challenge-4) - CAGE Challenge 4 is a scenario where multiple autonomous agents must effectively defend a simulated ...

7. [AdvEvo-MARL: Shaping Internalized Safety through Adversarial Co ...](https://huggingface.co/papers/2510.01586) - AdvEvo-MARL, a co-evolutionary multi-agent reinforcement learning framework, enhances safety and uti...

8. [AdvEvo-MARL: Shaping Internalized Safety through Adversarial Co ...](https://arxiv.org/abs/2510.01586) - [Submitted on 2 Oct 2025]. Title:AdvEvo-MARL: Shaping Internalized Safety through Adversarial Co-Evo...

9. [Eureka | Human-Level Reward Design via Coding Large Language ...](https://eureka-research.github.io) - A human-level reward design algorithm powered by LLMs. Eureka exploits the remarkable zero-shot gene...

10. [Eureka: Human-Level Reward Design via Coding Large Language ...](https://arxiv.org/abs/2310.12931) - A human-level reward design algorithm powered by LLMs. Eureka exploits the remarkable zero-shot gene...

11. [A large language model-driven reward design framework via ...](https://www.sciencedirect.com/science/article/abs/pii/S0950705125011104) - We introduce CARD, an LLM-based framework for reward code design and refinement. · Our method lowers...

12. [Eurekaverse: Environment Curriculum Generation via Large ... - arXiv](https://arxiv.org/abs/2411.01775) - In this paper, we introduce Eurekaverse, an unsupervised environment design algorithm that uses LLMs...

13. [Eurekaverse | Environment Curriculum Generation via Large ...](https://eureka-research.github.io/eurekaverse/) - An unsupervised environment design algorithm that uses LLMs to sample progressively more challenging...

14. [Environment Curriculum Generation via Large Language Models](https://www.themoonlight.io/en/review/eurekaverse-environment-curriculum-generation-via-large-language-models) - This page provides the most accurate and concise summary worldwide for the paper titled Eurekaverse:...

15. [Eurekaverse: Environment Curriculum Generation via ... - GitHub](https://github.com/eureka-research/eurekaverse) - An unsupervised environment design algorithm that uses LLMs to sample progressively more challenging...

16. [CTDE: Centralized Training, Decentralized Execution - Emergent Mind](https://www.emergentmind.com/topics/centralized-training-decentralized-execution-ctde) - CTDE is a learning paradigm that uses centralized training with full global information to mitigate ...

17. [Centralized Training with Decentralized Execution (CTDE)](https://apxml.com/courses/advanced-reinforcement-learning/chapter-6-multi-agent-reinforcement-learning/ctde-marl) - The CTDE approach: leveraging global information during training while enabling decentralized execut...

18. [Reinforcement Learning-Augmented LLM Agents for Collaborative Decision Making and Performance Optimization](https://ieeexplore.ieee.org/document/11324888/) - Large Language Models (LLMs) perform well in language tasks but often lack collaborative awareness a...

19. [CADP: Towards Better Centralized Learning for Decentralized Execution in MARL](https://www.semanticscholar.org/paper/d67f17a054fabdbdaa15401bf1b24baed3009659) - Centralized Training with Decentralized Execution (CTDE) has recently emerged as a popular framework...

20. [Towards Better Centralized Learning for Decentralized Execution in ...](https://www.ijcai.org/proceedings/2025/803) - Centralized Training with Decentralized Execution (CTDE) has recently emerged as a popular framework...

21. [[PDF] ReSCOM: Reward-Shaped Curriculum for Efficient Multi-Agent ...](https://www.ifaamas.org/Proceedings/aamas2025/pdfs/p2153.pdf) - ReSCOM progressively adjusts the learning emphasis through reward-shaped curriculums, allowing agent...

22. [Emergent Communication in Multi-Agent Reinforcement Learning ...](https://arxiv.org/abs/2309.06021) - This paper articulates the importance of EC-MARL within the context of future 6G wireless networks, ...

23. [Emergent Communication Protocols in Multi-Agent Reinforcement ...](https://dev.to/rikinptl/emergent-communication-protocols-in-multi-agent-reinforcement-learning-systems-4gi7) - Multi-agent reinforcement learning extends traditional RL to environments where multiple agents lear...

24. [Agentic AI for Cyber Defense: LLM-Guided Hierarchical Multi-Agent Reinforcement Learning](https://ieeexplore.ieee.org/document/11310253/) - In cyber defense, agentic AI in the form of distributed multi-agent teams must rapidly adapt to evol...

25. [Nash Q-Network for Multi-Agent Cybersecurity Simulation](https://arxiv.org/abs/2509.00678) - Cybersecurity defense involves interactions between adversarial parties (namely defenders and hacker...

26. [PoolFlip: A Multi-agent Reinforcement Learning Security ...](https://sites.dartmouth.edu/lisplab/cadet-poolflip-2025/) - PoolFlip: A Multi-agent Reinforcement Learning Security Environment for Cyber Defense. Publication d...

27. [LLM-Powered Decentralized Generative Agents with Adaptive Hierarchical Knowledge Graph for Cooperative Planning](https://arxiv.org/abs/2502.05453) - Developing intelligent agents for long-term cooperation in dynamic open-world scenarios is a major c...

28. [Learning an Adversarial World Model for Automated Curriculum ...](https://arxiv.org/html/2509.03771v1) - We cast the problem of environment design as a two-player game between a generative **Attacker** and...

29. [The End of Reward Engineering: How LLMs Are Redefining Multi ...](https://arxiv.org/html/2601.08237v1) - Emergent Communication: Agents develop shared communication protocols through reward optimization [1...

Here's the deep research playbook. Let me break down what's practically game-changing vs. what's already good.

The 3 Upgrades That Will Make Judges' Jaws Drop
1. Adaptive Theory of Mind (A-ToM) — A March 2026 paper proves that LLM agents with mismatched "reasoning depths" actively harm each other's coordination even when cooperating. The fix: each agent in your SOC team dynamically estimates how deep the other agent is reasoning and structurally aligns with it. No other hackathon team will have this — it's two weeks old.

2. Red Team vs. Blue Team Co-Evolutionary Loop — Your current environment has no attacker. CAGE Challenge 4 (the gold standard MARL cybersecurity benchmark) is built around exactly this adversarial structure. AdvEvo-MARL (NeurIPS 2025) proved that jointly training attackers and defenders reduces attack success rates to below 20% while improving defender accuracy by up to +3.67%. Add a 4th RedTeamAgent that injects false logs, covers tracks, and deploys decoy IOCs — and your environment becomes adversarially self-improving.

3. EUREKA-Style LLM Reward Refinement — Instead of defending your hand-crafted 11-component reward to judges, say: "Our reward wasn't hand-tuned. We ran EUREKA-style iterative reward reflection over 500 training trajectories and let GPT-4 improve the reward code." EUREKA (NVIDIA/CMU) outperforms human expert rewards on 83% of tasks. This is directly applicable — just feed your incident_response_env_environment.py source + trajectory stats to the LLM and iterate.

The Structural Architecture Upgrade
Use CTDE (Centralized Training, Decentralized Execution) — the dominant MARL paradigm. A 2025 paper applying GRPO under CTDE to multi-agent LLMs got a 3× speed improvement with 98.7% coordination consistency. During training, a centralized critic sees all agents' observations. At inference, each agent acts on its local view only. This stabilizes your reward curves (cleaner demo) and has unassailable theoretical grounding.

The "Communication Emerges" Moment
Apply ReSCOM (AAMAS 2025) — a 3-phase communication curriculum that progressively teaches agents when to communicate rather than how, improving coordination by 16–22% over baselines. Start by rewarding any communication; end by only rewarding communication that changes team behavior. Your agents literally develop their own protocol organically. That is the "emergent strategic behavior" the theme calls for.

