"""
Self-Evolving Scenario Generation Engine

Implements:
1. α-Curriculum Reward (from GenEnv): R_env(p̂) = -|p̂ - α| where α≈0.5
   Rewards environment for generating scenarios in agent's "zone of proximal development"
2. POET-inspired mutation operators: parametric mutation of scenario attributes
3. Fitness-proportionate selection with novelty bonus
4. Difficulty calibration via Elo-like rating system

Mathematical Framework:
- Each scenario S has a difficulty vector d ∈ R^k (k dimensions of difficulty)
- Agent competence vector c ∈ R^k estimated from performance history
- α-Curriculum: optimal scenario difficulty where P(agent solves | S) ≈ α
- Mutation: S' = mutate(S, σ) where σ is mutation strength adapted by fitness
- Fitness: F(S) = -|success_rate(S) - α| + λ * novelty(S)
- Novelty: measured as distance to k-nearest scenarios in behavior space
"""

import copy
import hashlib
import json
import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# IMPORTANT: Use relative imports that work both ways
try:
    from ..tasks.base import (
        EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
    )
    from ..models import ContainmentAction, Severity, ThreatCategory
except ImportError:
    import sys, os
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    from tasks.base import (
        EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
    )
    from models import ContainmentAction, Severity, ThreatCategory


# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScenarioGenome:
    """
    Genetic representation of a scenario for evolution.
    Maps scenario parameters to a mutable genome vector.
    """
    # Core parameters (these get mutated)
    num_log_entries: int = 12        # How many log entries (complexity)
    num_critical_evidence: int = 5   # Critical evidence items to find
    num_iocs: int = 4                # Number of IOCs
    num_endpoints: int = 3           # Network endpoints
    num_users: int = 2               # User profiles
    num_threat_intel: int = 3        # Threat intel entries
    num_containment_targets: int = 3 # Things to contain
    max_steps: int = 25              # Steps allowed
    noise_ratio: float = 0.3        # Ratio of noise/decoy evidence
    correlation_depth: int = 2       # How many cross-source correlations
    escalation_required: bool = True
    multi_stage_attack: bool = False # Whether attack has multiple phases

    # Difficulty dimensions (0.0 = easiest, 1.0 = hardest)
    evidence_obscurity: float = 0.3   # How hidden is critical evidence
    ioc_complexity: float = 0.3       # Sophistication of IOCs
    containment_complexity: float = 0.3 # Number/precision of containment
    report_detail_required: float = 0.3 # How detailed report must be
    time_pressure: float = 0.3        # Steps vs required actions ratio

    # Metadata
    generation: int = 0
    parent_id: Optional[str] = None
    genome_id: str = ""

    def __post_init__(self):
        if not self.genome_id:
            self.genome_id = hashlib.md5(
                json.dumps(self.__dict__, default=str).encode()
            ).hexdigest()[:12]

    @property
    def difficulty_vector(self) -> List[float]:
        """k-dimensional difficulty vector."""
        return [
            self.evidence_obscurity,
            self.ioc_complexity,
            self.containment_complexity,
            self.report_detail_required,
            self.time_pressure,
        ]

    @property
    def aggregate_difficulty(self) -> float:
        """Single scalar difficulty score in [0, 1]."""
        return sum(self.difficulty_vector) / len(self.difficulty_vector)


@dataclass
class AgentPerformanceRecord:
    """Tracks agent performance for fitness evaluation."""
    scenario_id: str
    genome_id: str
    score: float
    steps_used: int
    max_steps: int
    evidence_found_ratio: float
    iocs_found_ratio: float
    correct_severity: bool
    correct_category: bool
    containment_score: float
    report_quality: float
    timestamp: float = 0.0


@dataclass
class EvolutionState:
    """Persistent state of the evolution engine."""
    generation: int = 0
    population: List[ScenarioGenome] = field(default_factory=list)
    archive: List[ScenarioGenome] = field(default_factory=list)  # Hall of fame
    performance_history: List[AgentPerformanceRecord] = field(default_factory=list)
    agent_elo: float = 1000.0  # Agent Elo rating
    scenario_elos: Dict[str, float] = field(default_factory=dict)  # Per-scenario Elo


# ═══════════════════════════════════════════════════════════════════
# Mutation Operators
# ═══════════════════════════════════════════════════════════════════

class MutationOperator:
    """
    POET-inspired parametric mutation operators for scenario genomes.

    Mutations are applied with adaptive strength σ based on the
    α-curriculum signal: if scenarios are too easy, increase difficulty;
    if too hard, decrease.
    """

    # Bounds for genome parameters
    PARAM_BOUNDS = {
        'num_log_entries': (6, 30),
        'num_critical_evidence': (3, 12),
        'num_iocs': (2, 10),
        'num_endpoints': (2, 8),
        'num_users': (1, 5),
        'num_threat_intel': (2, 8),
        'num_containment_targets': (2, 8),
        'max_steps': (15, 40),
        'noise_ratio': (0.0, 0.6),
        'correlation_depth': (1, 5),
        'evidence_obscurity': (0.0, 1.0),
        'ioc_complexity': (0.0, 1.0),
        'containment_complexity': (0.0, 1.0),
        'report_detail_required': (0.0, 1.0),
        'time_pressure': (0.0, 1.0),
    }

    @staticmethod
    def mutate(genome: ScenarioGenome, sigma: float = 0.15) -> ScenarioGenome:
        """
        Apply Gaussian mutation to genome parameters.

        σ (sigma) controls mutation strength:
        - Higher σ → more exploration (when agent is in comfort zone)
        - Lower σ → fine-tuning (when near optimal difficulty)
        """
        child = copy.deepcopy(genome)
        child.generation = genome.generation + 1
        child.parent_id = genome.genome_id

        # Mutate numeric parameters with Gaussian noise
        for param, (lo, hi) in MutationOperator.PARAM_BOUNDS.items():
            current = getattr(child, param)
            if isinstance(current, float):
                noise = random.gauss(0, sigma * (hi - lo))
                new_val = max(lo, min(hi, current + noise))
                setattr(child, param, round(new_val, 3))
            elif isinstance(current, int):
                noise = random.gauss(0, sigma * (hi - lo))
                new_val = max(lo, min(hi, round(current + noise)))
                setattr(child, param, int(new_val))

        # Flip boolean traits with small probability
        if random.random() < 0.15 * sigma:
            child.escalation_required = not child.escalation_required
        if random.random() < 0.15 * sigma:
            child.multi_stage_attack = not child.multi_stage_attack

        # Regenerate ID
        child.genome_id = hashlib.md5(
            json.dumps(child.__dict__, default=str).encode()
        ).hexdigest()[:12]

        return child

    @staticmethod
    def crossover(parent_a: ScenarioGenome, parent_b: ScenarioGenome) -> ScenarioGenome:
        """Uniform crossover between two parent genomes."""
        child = copy.deepcopy(parent_a)
        child.generation = max(parent_a.generation, parent_b.generation) + 1
        child.parent_id = f"{parent_a.genome_id}x{parent_b.genome_id}"

        for param in MutationOperator.PARAM_BOUNDS:
            if random.random() < 0.5:
                setattr(child, param, getattr(parent_b, param))

        if random.random() < 0.5:
            child.escalation_required = parent_b.escalation_required
        if random.random() < 0.5:
            child.multi_stage_attack = parent_b.multi_stage_attack

        child.genome_id = hashlib.md5(
            json.dumps(child.__dict__, default=str).encode()
        ).hexdigest()[:12]
        return child


# ═══════════════════════════════════════════════════════════════════
# Fitness & Selection
# ═══════════════════════════════════════════════════════════════════

class FitnessEvaluator:
    """
    Evaluates scenario fitness using α-Curriculum reward.

    Core formula: F(S) = -|p̂(S) - α| + λ * novelty(S) + β * info_gain(S)

    Where:
    - p̂(S) = estimated agent success probability on scenario S
    - α = target success rate (0.5 = zone of proximal development)
    - novelty(S) = average distance to k-nearest neighbors in archive
    - info_gain(S) = how much new the scenario teaches the agent
    """

    def __init__(self, alpha: float = 0.5, lambda_novelty: float = 0.2,
                 beta_info: float = 0.1, k_nearest: int = 5):
        self.alpha = alpha          # Target success rate
        self.lambda_novelty = lambda_novelty  # Novelty weight
        self.beta_info = beta_info  # Information gain weight
        self.k_nearest = k_nearest  # For novelty computation

    def compute_fitness(
        self,
        genome: ScenarioGenome,
        performance_records: List[AgentPerformanceRecord],
        archive: List[ScenarioGenome],
    ) -> float:
        """
        Compute composite fitness score for a scenario genome.

        Returns value in approximately [-1, 1] range.
        Higher is better (more useful for training).
        """
        # 1. α-Curriculum component
        alpha_reward = self._alpha_curriculum_reward(genome, performance_records)

        # 2. Novelty component
        novelty = self._compute_novelty(genome, archive)

        # 3. Information gain estimate
        info_gain = self._estimate_info_gain(genome, performance_records)

        fitness = alpha_reward + self.lambda_novelty * novelty + self.beta_info * info_gain
        return fitness

    def _alpha_curriculum_reward(
        self,
        genome: ScenarioGenome,
        records: List[AgentPerformanceRecord],
    ) -> float:
        """
        α-Curriculum: R = -|p̂ - α|

        Scenarios where the agent succeeds ~50% of the time are most useful
        for learning (zone of proximal development).
        """
        # Estimate success probability from performance records
        matching = [r for r in records if r.genome_id == genome.genome_id]
        if not matching:
            # No data — use difficulty as proxy
            # Assume harder scenarios have lower success probability
            estimated_p = 1.0 - genome.aggregate_difficulty
        else:
            estimated_p = sum(r.score for r in matching) / len(matching)

        return -abs(estimated_p - self.alpha)

    def _compute_novelty(
        self, genome: ScenarioGenome, archive: List[ScenarioGenome]
    ) -> float:
        """
        Novelty search: distance to k-nearest neighbors in difficulty space.
        Encourages diverse scenario population.
        """
        if not archive:
            return 1.0  # Maximum novelty if archive is empty

        gv = genome.difficulty_vector
        distances = []
        for other in archive:
            ov = other.difficulty_vector
            dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(gv, ov)))
            distances.append(dist)

        distances.sort()
        k = min(self.k_nearest, len(distances))
        avg_dist = sum(distances[:k]) / k if k > 0 else 0.0

        # Normalize to [0, 1] (max possible distance in unit hypercube is sqrt(k_dims))
        max_dist = math.sqrt(len(gv))
        return min(avg_dist / max_dist, 1.0)

    def _estimate_info_gain(
        self,
        genome: ScenarioGenome,
        records: List[AgentPerformanceRecord],
    ) -> float:
        """
        Estimate how much new information a scenario provides.
        Scenarios that expose agent weaknesses score higher.
        """
        if not records:
            return 0.5

        # Look at what the agent is weak at
        recent = records[-20:]  # Last 20 episodes

        weakness_dimensions = {
            'evidence_obscurity': 1.0 - (sum(r.evidence_found_ratio for r in recent) / len(recent)),
            'ioc_complexity': 1.0 - (sum(r.iocs_found_ratio for r in recent) / len(recent)),
            'containment_complexity': 1.0 - (sum(r.containment_score for r in recent) / len(recent)),
            'report_detail_required': 1.0 - (sum(r.report_quality for r in recent) / len(recent)),
        }

        # Scenarios that target agent weaknesses have higher info gain
        dv = genome.difficulty_vector
        dim_names = ['evidence_obscurity', 'ioc_complexity', 'containment_complexity',
                      'report_detail_required', 'time_pressure']

        info = 0.0
        for i, dim_name in enumerate(dim_names):
            if dim_name in weakness_dimensions:
                # Higher difficulty in weak dimensions = more info gain
                info += dv[i] * weakness_dimensions[dim_name]

        return info / len(dim_names) if dim_names else 0.0


# ═══════════════════════════════════════════════════════════════════
# Evolution Engine (Main Class)
# ═══════════════════════════════════════════════════════════════════

class EvolutionEngine:
    """
    Self-evolving environment engine using POET + α-Curriculum.

    Maintains a population of scenario genomes, evolves them based on
    agent performance, and provides the next scenario to train on.

    Usage:
        engine = EvolutionEngine(population_size=10, alpha=0.5)
        genome = engine.get_next_scenario()
        scenario = engine.genome_to_scenario(genome)
        # ... run agent on scenario ...
        engine.record_performance(genome, performance_record)
        engine.evolve()  # Create next generation
    """

    def __init__(
        self,
        population_size: int = 10,
        alpha: float = 0.5,
        mutation_sigma: float = 0.15,
        elite_fraction: float = 0.2,
        archive_size: int = 50,
    ):
        self.population_size = population_size
        self.mutation_sigma = mutation_sigma
        self.elite_fraction = elite_fraction
        self.archive_size = archive_size

        self.fitness_evaluator = FitnessEvaluator(alpha=alpha)
        self.state = EvolutionState()

        # Initialize population with diverse seeds
        self._initialize_population()

    def _initialize_population(self):
        """Create initial diverse population spanning difficulty space."""
        templates = [
            # Easy
            ScenarioGenome(num_log_entries=8, num_critical_evidence=3, num_iocs=2,
                          num_endpoints=2, max_steps=25, noise_ratio=0.1,
                          evidence_obscurity=0.1, ioc_complexity=0.1,
                          containment_complexity=0.1, time_pressure=0.1),
            # Medium
            ScenarioGenome(num_log_entries=12, num_critical_evidence=5, num_iocs=4,
                          num_endpoints=3, max_steps=25, noise_ratio=0.25,
                          evidence_obscurity=0.35, ioc_complexity=0.35,
                          containment_complexity=0.35, time_pressure=0.3),
            # Hard
            ScenarioGenome(num_log_entries=18, num_critical_evidence=7, num_iocs=6,
                          num_endpoints=4, max_steps=30, noise_ratio=0.4,
                          evidence_obscurity=0.6, ioc_complexity=0.6,
                          containment_complexity=0.6, time_pressure=0.5),
            # Expert
            ScenarioGenome(num_log_entries=25, num_critical_evidence=10, num_iocs=8,
                          num_endpoints=6, max_steps=35, noise_ratio=0.5,
                          multi_stage_attack=True,
                          evidence_obscurity=0.85, ioc_complexity=0.85,
                          containment_complexity=0.85, time_pressure=0.7),
        ]

        # Fill population by mutating templates
        self.state.population = []
        for i in range(self.population_size):
            template = templates[i % len(templates)]
            if i < len(templates):
                genome = copy.deepcopy(template)
            else:
                genome = MutationOperator.mutate(template, sigma=0.3)
            genome.genome_id = hashlib.md5(
                f"init_{i}_{json.dumps(genome.__dict__, default=str)}".encode()
            ).hexdigest()[:12]
            self.state.population.append(genome)

    def get_next_scenario_genome(self) -> ScenarioGenome:
        """
        Select the next scenario genome for the agent to train on.
        Uses fitness-proportionate selection favoring scenarios near α.
        """
        if not self.state.population:
            self._initialize_population()

        # Compute fitness for each genome
        fitnesses = []
        for genome in self.state.population:
            f = self.fitness_evaluator.compute_fitness(
                genome, self.state.performance_history, self.state.archive
            )
            fitnesses.append(f)

        # Softmax selection (temperature-based)
        temperature = 0.5
        max_f = max(fitnesses) if fitnesses else 0
        exp_f = [math.exp((f - max_f) / temperature) for f in fitnesses]
        total = sum(exp_f)
        probs = [e / total for e in exp_f]

        # Weighted random selection
        selected = random.choices(self.state.population, weights=probs, k=1)[0]
        return selected

    def record_performance(self, genome: ScenarioGenome, record: AgentPerformanceRecord):
        """Record agent performance on a scenario for fitness evaluation."""
        self.state.performance_history.append(record)

        # Update Elo ratings
        self._update_elo(genome, record)

        # Keep history bounded
        if len(self.state.performance_history) > 500:
            self.state.performance_history = self.state.performance_history[-300:]

    def evolve(self) -> List[ScenarioGenome]:
        """
        Evolve the scenario population using:
        1. Fitness evaluation
        2. Elite preservation
        3. Mutation + crossover
        4. Archive update (novelty-based hall of fame)

        Returns the new population.
        """
        self.state.generation += 1

        # Evaluate fitness
        scored = []
        for genome in self.state.population:
            f = self.fitness_evaluator.compute_fitness(
                genome, self.state.performance_history, self.state.archive
            )
            scored.append((genome, f))

        scored.sort(key=lambda x: x[1], reverse=True)

        # Elite preservation
        n_elite = max(1, int(self.population_size * self.elite_fraction))
        elites = [g for g, _ in scored[:n_elite]]

        # Add best to archive
        for genome, fitness in scored[:2]:
            if len(self.state.archive) < self.archive_size:
                self.state.archive.append(copy.deepcopy(genome))
            elif fitness > 0:  # Only archive reasonably fit scenarios
                # Replace least novel archive member
                self.state.archive.append(copy.deepcopy(genome))
                if len(self.state.archive) > self.archive_size:
                    # Remove least novel
                    novelties = [
                        self.fitness_evaluator._compute_novelty(g, self.state.archive)
                        for g in self.state.archive
                    ]
                    min_idx = novelties.index(min(novelties))
                    self.state.archive.pop(min_idx)

        # Adaptive mutation strength
        # If scenarios are too easy (high avg score), increase σ to find harder ones
        # If too hard (low avg score), decrease σ to fine-tune
        recent_scores = [r.score for r in self.state.performance_history[-20:]]
        if recent_scores:
            avg_score = sum(recent_scores) / len(recent_scores)
            # σ peaks when avg_score is far from α
            sigma = self.mutation_sigma * (1.0 + abs(avg_score - self.fitness_evaluator.alpha))
        else:
            sigma = self.mutation_sigma

        # Generate children
        new_population = list(elites)
        while len(new_population) < self.population_size:
            if random.random() < 0.7:
                # Mutation
                parent = random.choice(scored[:max(3, len(scored) // 2)])[0]
                child = MutationOperator.mutate(parent, sigma=sigma)
            else:
                # Crossover
                p1, p2 = random.sample(scored[:max(3, len(scored) // 2)], 2)
                child = MutationOperator.crossover(p1[0], p2[0])
                child = MutationOperator.mutate(child, sigma=sigma * 0.5)

            new_population.append(child)

        self.state.population = new_population[:self.population_size]
        return self.state.population

    def _update_elo(self, genome: ScenarioGenome, record: AgentPerformanceRecord):
        """
        Update Elo ratings for agent and scenario.

        Agent 'wins' if score > 0.7, 'loses' if score < 0.3, 'draw' otherwise.
        This gives a natural difficulty calibration system.
        """
        K = 32  # Elo K-factor

        agent_elo = self.state.agent_elo
        scenario_elo = self.state.scenario_elos.get(genome.genome_id, 1000.0)

        # Expected scores
        ea = 1.0 / (1.0 + 10 ** ((scenario_elo - agent_elo) / 400))
        es = 1.0 - ea

        # Actual outcome
        if record.score > 0.7:
            sa, ss = 1.0, 0.0  # Agent wins
        elif record.score < 0.3:
            sa, ss = 0.0, 1.0  # Scenario wins
        else:
            sa, ss = 0.5, 0.5  # Draw

        self.state.agent_elo = agent_elo + K * (sa - ea)
        self.state.scenario_elos[genome.genome_id] = scenario_elo + K * (ss - es)

    def get_evolution_stats(self) -> Dict[str, Any]:
        """Get statistics about the current evolution state."""
        recent = self.state.performance_history[-20:]
        return {
            "generation": self.state.generation,
            "population_size": len(self.state.population),
            "archive_size": len(self.state.archive),
            "total_episodes": len(self.state.performance_history),
            "agent_elo": round(self.state.agent_elo, 1),
            "avg_recent_score": round(
                sum(r.score for r in recent) / len(recent), 4
            ) if recent else None,
            "avg_difficulty": round(
                sum(g.aggregate_difficulty for g in self.state.population)
                / len(self.state.population), 3
            ) if self.state.population else None,
            "difficulty_range": {
                "min": round(min(g.aggregate_difficulty for g in self.state.population), 3),
                "max": round(max(g.aggregate_difficulty for g in self.state.population), 3),
            } if self.state.population else None,
        }
