"""Training runner for HF Spaces — runs GRPO training in a background thread
and writes reward_log.json that the Gradio dashboard reads."""
import json, os, sys, threading, time, re

os.environ["TORCHDYNAMO_DISABLE"] = "1"
os.environ["TORCH_COMPILE_DISABLE"] = "1"

REWARD_LOG_PATH = "/tmp/reward_log_live.json"
TRAIN_STATUS_PATH = "/tmp/train_status.json"

# Shared state
_training_thread = None
_stop_flag = threading.Event()


def _write_status(step, total, status, error=None):
    with open(TRAIN_STATUS_PATH, "w") as f:
        json.dump({"step": step, "total": total, "status": status,
                   "error": error, "ts": time.time()}, f)


def is_training():
    return _training_thread is not None and _training_thread.is_alive()


def get_status():
    if os.path.exists(TRAIN_STATUS_PATH):
        with open(TRAIN_STATUS_PATH) as f:
            return json.load(f)
    return {"step": 0, "total": 0, "status": "idle"}


def get_live_log():
    if os.path.exists(REWARD_LOG_PATH):
        with open(REWARD_LOG_PATH) as f:
            return json.load(f)
    return None


def stop_training():
    _stop_flag.set()
    return "⏹️ Stop signal sent..."


def start_training(model_name, max_steps, lr, num_gen):
    global _training_thread
    if is_training():
        return "⚠️ Training already running"
    _stop_flag.clear()
    _training_thread = threading.Thread(
        target=_train_loop,
        args=(model_name, int(max_steps), float(lr), int(num_gen)),
        daemon=True,
    )
    _training_thread.start()
    return f"🚀 Training started: {model_name}, {max_steps} steps"


def _train_loop(model_name, max_steps, lr, num_gen):
    """Actual GRPO training loop — mirrors the notebook cells."""
    try:
        _write_status(0, max_steps, "loading_model")

        import torch
        from unsloth import FastLanguageModel
        from trl import GRPOConfig, GRPOTrainer
        from datasets import Dataset
        from transformers import GenerationConfig

        # Import project modules
        sys.path.insert(0, os.path.dirname(__file__))
        from tasks import SCENARIOS, TASK_DEFINITIONS
        from training.ctde import CTDETrainer, CentralizedCritic, JointObservation
        from training.hmarl import HierarchicalPolicy, SkillDiscovery
        from alpha_curriculum import AlphaCurriculumSelector

        # ── Load model ──
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name, max_seq_length=2048, load_in_4bit=True,
            fast_inference=False, gpu_memory_utilization=0.7,
        )
        model = FastLanguageModel.get_peft_model(
            model, r=32, lora_alpha=64,  # Qwen3: alpha=2*rank
            target_modules=["q_proj","k_proj","v_proj","o_proj",
                            "gate_proj","up_proj","down_proj"],
        )
        FastLanguageModel.for_training(model)

        # ── System prompt ──
        SYSTEM_PROMPT = (
            "You are an expert SOC analyst performing incident response triage.\n"
            "Analyze the security alert thoroughly and provide a comprehensive investigation.\n\n"
            "IMPORTANT: Your analysis MUST be detailed. Include at minimum:\n"
            "- 3+ specific evidence observations in your reasoning\n"
            "- Correlation between log sources\n"
            "- Explicit threat actor TTP identification\n"
            "- Confidence assessment for your severity rating\n\n"
            "Format your response as:\n<think>\n[Your detailed reasoning — at least 300 words.]\n</think>\n\n"
            "<severity>[CRITICAL|HIGH|MEDIUM|LOW]</severity>\n"
            "<category>[malware|phishing|data_exfiltration|insider_threat|apt|ransomware|unauthorized_access]</category>\n"
            "<iocs>[comma-separated IOCs]</iocs>\n"
            "<mitre>[MITRE ATT&CK technique IDs]</mitre>\n"
            "<containment>[specific containment actions]</containment>\n"
            "<summary>[2-3 sentence executive summary]</summary>"
        )

        # ── Dataset ──
        prompts = []
        task_ids = list(SCENARIOS.keys())
        for tid in task_ids:
            scenario = SCENARIOS[tid]
            alert = f"ALERT: {scenario.description}\n\nLOGS:\n"
            for entry in scenario.log_entries[:8]:
                alert += f"[{entry.source}] {entry.content}\n"
            prompts.append({
                "prompt": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": alert},
                ],
                "task_id": tid,
            })
        dataset = Dataset.from_list(prompts * max(1, max_steps // len(prompts)))

        # ── Ground truth ──
        GROUND_TRUTH = {}
        for tid, sc in SCENARIOS.items():
            GROUND_TRUTH[tid] = {
                "severity": sc.severity if hasattr(sc, "severity") else "",
                "category": sc.category if hasattr(sc, "category") else "",
                "critical_iocs": list(sc.critical_iocs) if hasattr(sc, "critical_iocs") else [],
            }

        # ── Reward infrastructure ──
        REQUIRED_TAGS = ["severity", "category", "iocs", "containment", "summary"]
        SEVERITY_ORDER = ["low", "medium", "high", "critical"]
        ctde = CTDETrainer(n_agents=3, obs_dim=6, action_dim=5)
        centralized_critic = ctde.critic
        curriculum = AlphaCurriculumSelector()
        reward_log = {k: [] for k in ["step", "total", "format", "evidence", "severity",
                                       "containment", "efficiency", "category",
                                       "len_div", "ctde_bonus", "skill_bonus"]}

        # ── Reward functions (copied from notebook, patched) ──
        def format_reward_func(completions, **kw):
            rewards = []
            for c in completions:
                text = c[0]["content"] if isinstance(c, list) else c
                score = 0.0
                if "<think>" in text and "</think>" in text:
                    score += 0.15
                    tc = text.split("<think>")[1].split("</think>")[0]
                    if len(tc) > 100: score += 0.10
                    if text.find("<severity>") > text.find("</think>") > 0: score += 0.10
                else:
                    score -= 0.30
                for tag in REQUIRED_TAGS:
                    if f"<{tag}>" in text and f"</{tag}>" in text: score += 0.10
                    else: score -= 0.15
                if all(f"<{t}>" in text for t in REQUIRED_TAGS): score += 0.10
                rewards.append(max(-0.30, min(1.0, score)))
            return rewards

        def evidence_reward_func(completions, task_id, **kw):
            rewards = []
            for c, tid in zip(completions, task_id):
                text = (c[0]["content"] if isinstance(c, list) else c).lower()
                gt = GROUND_TRUTH.get(tid, {})
                iocs = gt.get("critical_iocs", [])
                if not iocs:
                    rewards.append(0.0); continue
                found = sum(1 for i in iocs if i.lower() in text)
                rewards.append(round(found / len(iocs), 4))
            return rewards

        def severity_reward_func(completions, task_id, **kw):
            rewards = []
            for c, tid in zip(completions, task_id):
                text = c[0]["content"] if isinstance(c, list) else c
                gt = GROUND_TRUTH.get(tid, {})
                expected = gt.get("severity", "").lower()
                if not expected or expected not in SEVERITY_ORDER:
                    rewards.append(0.0); continue
                m = re.search(r'<severity>\s*(\w+)\s*</severity>', text, re.I)
                predicted = m.group(1).lower() if m else None
                if not predicted:
                    rewards.append(-0.3); continue
                if predicted == expected:
                    rewards.append(1.0)
                elif predicted in SEVERITY_ORDER:
                    d = abs(SEVERITY_ORDER.index(predicted) - SEVERITY_ORDER.index(expected))
                    rewards.append(0.3 if d == 1 else 0.0)
                else:
                    rewards.append(-0.3)
            return rewards

        def containment_reward_func(completions, **kw):
            kws = ["isolate", "block", "quarantine", "disable", "revoke", "patch", "firewall"]
            rewards = []
            for c in completions:
                text = (c[0]["content"] if isinstance(c, list) else c).lower()
                found = sum(1 for k in kws if k in text)
                rewards.append(min(found * 0.15, 1.0))
            return rewards

        def efficiency_reward_func(completions, **kw):
            rewards = []
            for c in completions:
                text = c[0]["content"] if isinstance(c, list) else c
                length = len(text)
                sr = sum(1 for t in REQUIRED_TAGS if f"<{t}>" in text) / len(REQUIRED_TAGS)
                if length < 200: s = -0.3 if sr < 0.4 else 0.0
                elif length < 400: s = 0.3 + 0.4 * sr
                elif length <= 1500: s = 0.6 + 0.4 * sr
                elif length <= 2000: s = 0.5 + 0.3 * sr
                else: s = 0.0
                rewards.append(round(s, 3))
            return rewards

        def category_reward_func(completions, task_id, **kw):
            rewards = []
            for c, tid in zip(completions, task_id):
                text = c[0]["content"] if isinstance(c, list) else c
                gt = GROUND_TRUTH.get(tid, {}).get("category", "").lower()
                if not gt: rewards.append(0.0); continue
                m = re.search(r'<category>\s*(\w+)\s*</category>', text, re.I)
                rewards.append(1.0 if m and m.group(1).lower() == gt else 0.0)
            return rewards

        def length_diversity_reward(completions, **kw):
            lengths = [len(c[0]["content"] if isinstance(c, list) else c) for c in completions]
            ml = sum(lengths) / max(len(lengths), 1)
            sl = (sum((l - ml)**2 for l in lengths) / max(len(lengths), 1)) ** 0.5
            return [min(0.5, max(-0.3, ((l - ml) / sl) * 0.15)) if sl >= 50 else 0.0 for l in lengths]

        def composite_soc_reward(completions, **kwargs):
            rf = format_reward_func(completions, **kwargs)
            re_ = evidence_reward_func(completions, **kwargs)
            rs = severity_reward_func(completions, **kwargs)
            rc = containment_reward_func(completions, **kwargs)
            eff = efficiency_reward_func(completions, **kwargs)
            rcat = category_reward_func(completions, **kwargs)
            rld = length_diversity_reward(completions, **kwargs)
            W = {"fmt": 0.11, "evi": 0.19, "sev": 0.14, "cnt": 0.17,
                 "eff": 0.10, "cat": 0.09, "ldv": 0.05}
            composites = []
            for i in range(len(completions)):
                text = completions[i][0]["content"] if isinstance(completions[i], list) else completions[i]
                base = (W["fmt"]*rf[i] + W["evi"]*re_[i] + W["sev"]*rs[i] +
                        W["cnt"]*rc[i] + W["eff"]*eff[i] + W["cat"]*rcat[i] + W["ldv"]*rld[i])
                has_iocs = bool(re.findall(r'<iocs>(.+?)</iocs>', text, re.DOTALL))
                has_contain = "<containment>" in text
                joint_obs = JointObservation(
                    l1_obs={"evidence_collected": ["e1"] if "<think>" in text else [], "log_sources_queried": ["edr"] if has_iocs else []},
                    l2_obs={"evidence_collected": ["e2"] if has_iocs else [], "iocs_discovered": ["ioc1"] if has_iocs else [], "log_sources_queried": []},
                    l3_obs={"evidence_collected": ["e3"] if has_contain else [], "log_sources_queried": []},
                    global_state={"severity_classified": bool(re.search(r'<severity>', text)), "report_submitted": "<summary>" in text},
                )
                ctde_b = centralized_critic.forward(joint_obs).coordination_score * 0.08
                skill_b = 0.0
                tm = re.search(r'<think>(.*?)</think>', text, re.DOTALL)
                if tm:
                    tt = tm.group(1)
                    skill_b += min(len(re.findall(r'(?:therefore|because|this indicates|based on|analyzing)', tt, re.I)) * 0.008, 0.03)
                    skill_b += min(len(re.findall(r'(?:could be|possibly|alternatively|however)', tt, re.I)) * 0.01, 0.02)
                    skill_b = min(skill_b, 0.07)
                trunc = -0.5 if '</summary>' not in text and '</think>' not in text else 0.0
                total = base + ctde_b + skill_b + trunc
                composites.append(total)
            n = len(completions)
            for key, vals in [("format", rf), ("evidence", re_), ("severity", rs),
                              ("containment", rc), ("efficiency", eff), ("category", rcat),
                              ("len_div", rld), ("ctde_bonus", [0]*n), ("skill_bonus", [0]*n), ("total", composites)]:
                reward_log[key].append(sum(vals) / n)
            reward_log["step"].append(len(reward_log["step"]))
            # Write live
            with open(REWARD_LOG_PATH, "w") as f:
                json.dump(reward_log, f)
            _write_status(len(reward_log["step"]), max_steps, "training")
            return composites

        # ── GRPOConfig ──
        _write_status(0, max_steps, "configuring")
        training_args = GRPOConfig(
            learning_rate=lr, temperature=0.9, num_generations=num_gen,
            max_completion_length=1024, max_steps=max_steps,
            per_device_train_batch_size=1, gradient_accumulation_steps=num_gen,
            beta=0.04, loss_type="dr_grpo",
            logging_steps=1, save_steps=max(10, max_steps // 10),
            output_dir="soc_grpo_output", report_to="none",
            optim="adamw_8bit", warmup_ratio=0.1, lr_scheduler_type="cosine",
            seed=42,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
        )

        trainer = GRPOTrainer(
            model=model, tokenizer=tokenizer,
            reward_funcs=composite_soc_reward,
            args=training_args, train_dataset=dataset,
            generation_kwargs={"max_new_tokens": 1024, "stop_strings": ["</summary>"], "tokenizer": tokenizer},
        )

        # ── Train ──
        _write_status(0, max_steps, "training")
        ckpt = None
        if os.path.isdir("soc_grpo_output"):
            cks = [d for d in os.listdir("soc_grpo_output") if d.startswith("checkpoint-")]
            if cks:
                ckpt = os.path.join("soc_grpo_output", sorted(cks, key=lambda x: int(x.split('-')[1]))[-1])

        trainer.train(resume_from_checkpoint=ckpt)

        # ── Save ──
        _write_status(max_steps, max_steps, "saving")
        model.save_pretrained("soc_grpo_final")
        tokenizer.save_pretrained("soc_grpo_final")
        _write_status(max_steps, max_steps, "done")

    except Exception as e:
        _write_status(0, 0, "error", str(e))
        import traceback
        traceback.print_exc()
