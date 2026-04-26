# Copyright (c) 2026 - OpenEnv Hackathon Submission
# H-MARL: Hierarchical MARL with LLM-Guided Skill Discovery
# BSD-3-Clause License

"""
Hierarchical MARL with LLM-Guided Skill Discovery.

Based on:
  - IEEE 2025: "Agentic AI for Cyber Defense: LLM-Guided Hierarchical
    Multi-Agent Reinforcement Learning" — validated on CAGE Challenge 4

Key idea: LLMs identify "semantically meaningful skills" and generate
intrinsic reward for each sub-skill. This creates a two-level hierarchy:
  High-level manager: which skill to execute
  Low-level executors: actual agent actions within a skill

This reduces sample complexity in large cyber defense environments.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class SubSkill:
    """A discovered sub-skill with intrinsic reward."""
    skill_id: str
    name: str
    description: str
    intrinsic_reward_code: str    # Python code for intrinsic reward
    relevant_actions: List[str]   # Actions that are part of this skill
    mastery_threshold: float = 0.7  # When the agent has "mastered" this skill
    current_mastery: float = 0.0
    usage_count: int = 0


# Pre-defined SOC investigation sub-skills
DEFAULT_SOC_SKILLS = [
    SubSkill(
        skill_id="lead_handoff",
        name="Lead Handoff",
        description="Efficiently transfer investigation lead from L1 to L2 when evidence warrants deeper analysis",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward for discovering critical evidence before handoff
    evidence_before_handoff = trajectory.get('evidence_at_handoff', 0)
    return min(0.1, evidence_before_handoff * 0.02)
""",
        relevant_actions=["examine_alert", "query_logs", "check_threat_intel"],
    ),
    SubSkill(
        skill_id="evidence_dedup",
        name="Evidence Deduplication",
        description="Avoid re-querying evidence already found by another agent",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Penalize redundant queries, reward unique evidence
    total_queries = trajectory.get('total_queries', 1)
    unique_evidence = trajectory.get('unique_evidence', 0)
    redundancy = 1 - (unique_evidence / max(total_queries, 1))
    return max(0, 0.05 - redundancy * 0.1)
""",
        relevant_actions=["query_logs", "check_threat_intel", "inspect_endpoint"],
    ),
    SubSkill(
        skill_id="belief_sync",
        name="Belief Synchronization",
        description="Align shared understanding of the incident across all agents via communication",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward when all agents agree on key findings
    belief_alignment = trajectory.get('belief_alignment', 0)
    return belief_alignment * 0.08
""",
        relevant_actions=["correlate_events"],
    ),
    SubSkill(
        skill_id="ioc_cross_validation",
        name="IOC Cross-Validation",
        description="Validate IOCs found by one agent using independent sources",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward for validating IOCs through multiple sources
    validated_iocs = trajectory.get('cross_validated_iocs', 0)
    return validated_iocs * 0.03
""",
        relevant_actions=["check_threat_intel", "analyze_malware", "correlate_events"],
    ),
    SubSkill(
        skill_id="containment_coordination",
        name="Containment Coordination",
        description="Coordinate containment actions across agents to avoid gaps and overlaps",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward for correct containment targeting, penalize overlaps
    correct_targets = trajectory.get('correct_containment', 0)
    overlapping = trajectory.get('overlapping_containment', 0)
    return correct_targets * 0.06 - overlapping * 0.03
""",
        relevant_actions=["contain_threat", "classify_severity"],
    ),
    SubSkill(
        skill_id="decoy_detection",
        name="Decoy Detection",
        description="Identify and flag red team decoy evidence to prevent misdirection",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward for correctly identifying decoys
    decoys_flagged = trajectory.get('decoys_correctly_flagged', 0)
    false_flags = trajectory.get('false_decoy_flags', 0)
    return decoys_flagged * 0.05 - false_flags * 0.08
""",
        relevant_actions=["check_threat_intel", "correlate_events", "inspect_endpoint"],
    ),
    SubSkill(
        skill_id="report_synthesis",
        name="Report Synthesis",
        description="Synthesize findings from all agents' knowledge graphs into a coherent incident report",
        intrinsic_reward_code="""
def intrinsic_reward(trajectory):
    # Reward for report quality informed by KG evidence chain
    kg_nodes_in_report = trajectory.get('kg_nodes_referenced', 0)
    report_quality = trajectory.get('report_quality', 0)
    return (kg_nodes_in_report * 0.01 + report_quality * 0.05)
""",
        relevant_actions=["submit_report", "correlate_events"],
    ),
]


class SkillDiscovery:
    """
    LLM-guided sub-skill discovery for SOC agents.

    Uses the LLM to identify semantically meaningful coordination skills
    and generates intrinsic reward functions for each.
    """

    def __init__(self, llm_client: Optional[Any] = None, model_name: str = "gpt-4o-mini"):
        self.llm_client = llm_client
        self.model_name = model_name
        self.skills: List[SubSkill] = list(DEFAULT_SOC_SKILLS)

    def discover_skills(
        self,
        env_description: str,
        agent_descriptions: List[str],
        n_skills: int = 7,
    ) -> List[SubSkill]:
        """
        Use LLM to identify sub-skills from environment description.
        Falls back to default skills if no LLM client available.
        """
        if not self.llm_client:
            return self.skills[:n_skills]

        prompt = (
            f"Environment: {env_description}\n\n"
            f"Agents: {', '.join(agent_descriptions)}\n\n"
            f"Identify {n_skills} coordination sub-skills that, if mastered, "
            f"lead to optimal team performance. For each skill, provide:\n"
            f"1. skill_id (snake_case)\n"
            f"2. name (human readable)\n"
            f"3. description\n"
            f"4. relevant_actions (list of action types)\n\n"
            f"Return as JSON array."
        )

        try:
            response = self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are an expert in multi-agent RL skill decomposition."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.5,
                max_tokens=2048,
            )

            import json
            skills_data = json.loads(response.choices[0].message.content)
            discovered = []
            for s in skills_data:
                discovered.append(SubSkill(
                    skill_id=s.get("skill_id", f"skill_{len(discovered)}"),
                    name=s.get("name", f"Skill {len(discovered)}"),
                    description=s.get("description", ""),
                    intrinsic_reward_code="def intrinsic_reward(t): return 0.0",
                    relevant_actions=s.get("relevant_actions", []),
                ))
            self.skills = discovered
            return discovered

        except Exception:
            return self.skills[:n_skills]

    def generate_intrinsic_rewards(self) -> Dict[str, Callable]:
        """
        Compile intrinsic reward functions for all discovered skills.
        Returns a dict of skill_id -> callable reward function.
        """
        reward_fns = {}
        for skill in self.skills:
            try:
                namespace = {}
                exec(skill.intrinsic_reward_code, namespace)
                fn = namespace.get("intrinsic_reward")
                if fn:
                    reward_fns[skill.skill_id] = fn
            except Exception:
                reward_fns[skill.skill_id] = lambda t: 0.0
        return reward_fns

    def update_mastery(self, skill_id: str, performance: float) -> None:
        """Update a skill's mastery level based on performance."""
        for skill in self.skills:
            if skill.skill_id == skill_id:
                # Exponential moving average
                skill.current_mastery = 0.8 * skill.current_mastery + 0.2 * performance
                skill.usage_count += 1
                break

    def get_skill_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all skills and their mastery levels."""
        return [
            {
                "skill_id": s.skill_id,
                "name": s.name,
                "mastery": round(s.current_mastery, 3),
                "usage_count": s.usage_count,
                "mastered": s.current_mastery >= s.mastery_threshold,
                "relevant_actions": s.relevant_actions,
            }
            for s in self.skills
        ]


class HierarchicalPolicy:
    """
    Two-level policy hierarchy for SOC agents.

    High-level manager: selects which sub-skill to execute
    Low-level executor: selects actual actions within the chosen skill
    """

    def __init__(self, agent_id: str, skills: List[SubSkill]):
        self.agent_id = agent_id
        self.skills = {s.skill_id: s for s in skills}
        self.current_skill: Optional[str] = None
        self._skill_history: List[str] = []

    def select_skill(
        self,
        observation: Dict[str, Any],
        step: int,
        max_steps: int,
    ) -> SubSkill:
        """
        High-level decision: which sub-skill to execute.

        Priority based on investigation phase and remaining time.
        """
        progress = step / max(max_steps, 1)
        evidence = observation.get("evidence_collected", [])
        severity_set = observation.get("severity_set", False)

        # Early game: evidence gathering
        if progress < 0.3:
            skill_id = "lead_handoff" if len(evidence) < 3 else "evidence_dedup"
        # Mid game: validation and synthesis
        elif progress < 0.6:
            if not severity_set:
                skill_id = "ioc_cross_validation"
            else:
                skill_id = "belief_sync"
        # Late game: containment and reporting
        elif progress < 0.85:
            skill_id = "containment_coordination"
        else:
            skill_id = "report_synthesis"

        # Override: if decoys detected, prioritize decoy detection
        red_alerts = observation.get("red_team_alerts", [])
        if red_alerts and progress < 0.7:
            skill_id = "decoy_detection"

        self.current_skill = skill_id
        self._skill_history.append(skill_id)

        return self.skills.get(skill_id, list(self.skills.values())[0])

    def filter_actions(
        self,
        skill: SubSkill,
        available_actions: List[str],
    ) -> List[str]:
        """
        Low-level: filter available actions to those relevant to the current skill.
        """
        relevant = [a for a in available_actions if a in skill.relevant_actions]
        return relevant if relevant else available_actions

    def get_skill_usage_stats(self) -> Dict[str, int]:
        """Get how often each skill was selected."""
        stats: Dict[str, int] = {}
        for skill_id in self._skill_history:
            stats[skill_id] = stats.get(skill_id, 0) + 1
        return stats
