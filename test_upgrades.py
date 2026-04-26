#!/usr/bin/env python3
"""Quick integration test for all research-backed upgrades."""

from red_team.agent import RedTeamAgent, RedTeamAction, RedTeamActionType
from red_team.strategies import get_random_strategy
from multi_agent.agents import L1TriageAgent, L2SeniorAnalyst, L3IRLead
from multi_agent.overseer import OverseerAgent
from multi_agent.communication import SharedInvestigationBoard
from eureka.reward_designer import EurekaRewardDesigner
from eureka.trajectory_analyzer import TrajectoryAnalyzer
from training.ctde import CTDETrainer, JointObservation
from training.hmarl import SkillDiscovery, HierarchicalPolicy, DEFAULT_SOC_SKILLS
from alpha_curriculum import AlphaCurriculumSelector

print("=" * 60)
print("INTEGRATION TEST: Research-Backed Upgrades")
print("=" * 60)

# 1. Red Team with visible reward signal
print("\n--- 1. Red Team Agent ---")
rt = RedTeamAgent(strategy=get_random_strategy())
result = rt.step(
    RedTeamAction(action_type=RedTeamActionType.INJECT_FALSE_LOG),
    {"log_sources_queried": [], "containment_score": 0.0, "severity_set": False, "steps_remaining": 20},
    ["evidence_1", "evidence_2"],
)
print(f"  Step reward: {result['reward']:+.3f}  detected: {result['detected']}")
summary = rt.get_reward_summary()
print(f"  Total reward: {summary['total_reward']:+.3f}  stealth: {summary['stealth_ratio']:.0%}")

# 2. Multi-Agent (ToM + KG + Communication)
print("\n--- 2. Multi-Agent SOC Team ---")
l1 = L1TriageAgent()
l2 = L2SeniorAnalyst()
l3 = L3IRLead()
overseer = OverseerAgent()
board = SharedInvestigationBoard()

l1.reset(["l2_senior", "l3_lead"])
l2.reset(["l1_triage", "l3_lead"])
l3.reset(["l1_triage", "l2_senior"])

obs = {"evidence_collected": ["email_spf_dkim_fail", "macro_execution"], "iocs_discovered": ["185.220.101.42"]}
l1.process_observation(obs, step=1)
l2.process_observation(obs, step=1)
l3.process_observation(obs, step=1)

kg = l1.memory.get_belief_summary()
print(f"  L1 KG: {kg['total_nodes']} nodes, {kg['iocs_found']} IOCs")

# Test ToM alignment
alignment = l3.tom.align_reasoning_depth("l1_triage")
print(f"  L3 ToM alignment: {alignment.get('reasoning_hint', '')[:80]}")

# Test handoff
msg = l1.prepare_message("l2_senior", "handoff", step=1)
board.send_message(msg)
l2.receive_messages([msg], board)
print(f"  Board: {board.get_board_summary()['total_messages']} messages")

# 3. Overseer (Fleet AI)
print("\n--- 3. Overseer Agent (Fleet AI) ---")
overseer.reset()
v = overseer.monitor_action("primary", "contain_threat", {"target": "test-host"}, step=1, board=board)
print(f"  Violation: {v.violation_type if v else 'None'}")
safety = overseer.safety_check_action("primary", "contain_threat", {"target": "test"}, l1.memory)
print(f"  Safety check: approved={safety.approved} reason={safety.reason}")
print(f"  Oversight: {overseer.get_oversight_summary()}")

# 4. KG connected to everything
print("\n--- 4. Knowledge Graph (DAMCS) — Connected ---")
kg_stats = l1.memory.get_graph_stats_for_eureka()
print(f"  EUREKA stats: {kg_stats}")
viz = l1.memory.to_visualization_dict()
print(f"  Visualization: {len(viz['nodes'])} nodes, {len(viz['edges'])} edges")
published = l1.memory.publish_to_shared_board(threshold=0.5)
print(f"  Published to board: {len(published)} items")

# 5. EUREKA with feedback loop
print("\n--- 5. EUREKA Reward Refinement ---")
analyzer = TrajectoryAnalyzer()
trajectories = [
    {"score": 0.6, "steps_used": 15, "max_steps": 25, "actions": ["query_logs", "check_threat_intel", "classify_severity"], "evidence_found": ["ev1"], "iocs_found": ["ioc1"], "report_submitted": True},
    {"score": 0.3, "steps_used": 25, "max_steps": 25, "actions": ["examine_alert", "examine_alert", "examine_alert", "query_logs"], "evidence_found": [], "iocs_found": [], "report_submitted": False},
]
stats = analyzer.analyze_trajectories(trajectories)
print(f"  Mean score: {stats.mean_score:.3f}  timeout: {stats.timeout_rate:.0%}")
suggestions = analyzer.suggest_improvements(stats)
print(f"  Suggestions: {suggestions[:2]}")

eureka = EurekaRewardDesigner()
eureka.set_context("SOC Environment", "Investigate and respond to cybersecurity alerts")
reflection = eureka.reflect_and_analyze(
    trajectories,
    kg_stats=kg_stats,
    red_team_stats=rt.get_reward_summary(),
    overseer_violations=[{"severity": "warning", "agent_id": "test", "description": "test violation"}],
)
print(f"  Reflection (first 200 chars): {reflection[:200]}...")

# 6. CTDE Training
print("\n--- 6. CTDE Training ---")
trainer = CTDETrainer()
trainer.initialize_policies(["l1_triage", "l2_senior", "l3_lead"])
joint_obs = JointObservation(
    l1_obs={"evidence_collected": ["ev1", "ev2"]},
    l2_obs={"evidence_collected": ["ev1"]},
    l3_obs={"evidence_collected": []},
    global_state={"severity_classified": True},
)
critic_out = trainer.collect_training_step(
    joint_obs, {"l1": "query_logs", "l2": "check_threat_intel", "l3": "classify_severity"}, {"l1": 0.1, "l2": 0.05, "l3": 0.0}
)
print(f"  Value: {critic_out.value_estimate:.3f}  coordination: {critic_out.coordination_score:.3f}")
print(f"  Training stats: {trainer.get_training_summary()}")

# 7. H-MARL Skills
print("\n--- 7. H-MARL Skill Discovery ---")
discovery = SkillDiscovery()
skills = discovery.get_skill_summary()
print(f"  Skills: {len(skills)} discovered")
for s in skills[:3]:
    print(f"    - {s['name']} (mastery: {s['mastery']:.2f})")
policy = HierarchicalPolicy("l1_triage", DEFAULT_SOC_SKILLS)
skill = policy.select_skill({"evidence_collected": [], "steps_remaining": 20}, step=2, max_steps=25)
print(f"  Selected skill: {skill.name}")

# 8. α-Curriculum Scenario Selector
print("\n--- 8. Alpha-Curriculum Scenario Selector ---")
selector = AlphaCurriculumSelector()
selector.record_performance("easy", 0.9)
selector.record_performance("easy", 0.85)
selector.record_performance("medium", 0.5)
selector.record_performance("hard", 0.2)
selector.record_performance("expert", 0.1)
next_task = selector.select_next_task(["easy", "medium", "hard", "expert"])
print(f"  Next task: {next_task}")
print(f"  Curriculum order: {selector.get_curriculum_order(['easy', 'medium', 'hard', 'expert'])}")
print(f"  Optimal difficulty: {selector.get_optimal_difficulty():.2f}")

print("\n" + "=" * 60)
print("ALL INTEGRATION TESTS PASSED")
print("=" * 60)
