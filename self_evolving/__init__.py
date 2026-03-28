# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Self-Evolving Engine Package
# BSD-3-Clause License

"""
Self-Evolving Scenario Generation Engine.

Exports the core evolution engine classes and scenario generator
for procedurally generating, mutating, and adapting cybersecurity
scenarios based on agent performance.
"""

try:
    from .evolution_engine import (
        AgentPerformanceRecord,
        EvolutionEngine,
        EvolutionState,
        FitnessEvaluator,
        MutationOperator,
        ScenarioGenome,
    )
    from .scenario_generator import ScenarioGenerator
except ImportError:
    from self_evolving.evolution_engine import (
        AgentPerformanceRecord,
        EvolutionEngine,
        EvolutionState,
        FitnessEvaluator,
        MutationOperator,
        ScenarioGenome,
    )
    from self_evolving.scenario_generator import ScenarioGenerator

__all__ = [
    "AgentPerformanceRecord",
    "EvolutionEngine",
    "EvolutionState",
    "FitnessEvaluator",
    "MutationOperator",
    "ScenarioGenome",
    "ScenarioGenerator",
]
