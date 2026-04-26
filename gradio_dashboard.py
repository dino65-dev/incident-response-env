"""
GRPO SOC Training Dashboard — Gradio App
Visualizes reward curves, per-signal breakdowns, CTDE/H-MARL bonuses,
and α-Curriculum stats from the GRPO training notebook.

Supports:
  - Demo mode with synthetic data matching real training dynamics
  - Loading real reward_log JSON exported from Colab
"""

import gradio as gr
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import json
import os
import io
import train_runner

# ── Colour palette ──────────────────────────────────────────────────────────
COLORS = {
    "bg":          "#0f0f1a",
    "card":        "#1a1a2e",
    "accent":      "#6c63ff",
    "accent2":     "#00d2ff",
    "text":        "#e0e0e0",
    "text_dim":    "#8888aa",
    "green":       "#2ecc71",
    "red":         "#e74c3c",
    "orange":      "#f39c12",
    "purple":      "#9b59b6",
    "blue":        "#3498db",
    "teal":        "#1abc9c",
}

SIGNAL_KEYS   = ["format", "evidence", "severity", "containment", "efficiency", "category"]
SIGNAL_LABELS = ["Format/Phase", "Evidence/IOC", "Severity", "Containment", "Efficiency", "Category"]
SIGNAL_COLORS = [COLORS["red"], COLORS["green"], COLORS["blue"],
                 COLORS["purple"], COLORS["orange"], COLORS["teal"]]

# ── Helpers ─────────────────────────────────────────────────────────────────
def smooth(v, w=10):
    if len(v) < w:
        return list(v)
    return np.convolve(v, np.ones(w) / w, mode="valid").tolist()


def generate_demo_data(n_steps: int = 150) -> dict:
    """Synthetic reward_log matching real training dynamics."""
    rng = np.random.default_rng(42)
    log = {k: [] for k in ["step", "total", *SIGNAL_KEYS,
                            "len_div", "ctde_bonus", "skill_bonus"]}

    for t in range(n_steps):
        progress = t / n_steps
        # Simulate learning curve: noisy sigmoid
        base_skill = 1.0 / (1.0 + np.exp(-8 * (progress - 0.4)))
        noise = rng.normal(0, 0.12)

        fmt   = -0.30 + 1.25 * base_skill + rng.normal(0, 0.10)
        evi   = 0.10 + 0.70 * base_skill  + rng.normal(0, 0.12)
        sev   = -0.10 + 0.90 * base_skill + rng.normal(0, 0.15)
        cnt   = 0.05 + 0.65 * base_skill  + rng.normal(0, 0.10)
        eff   = 0.20 + 0.50 * base_skill  + rng.normal(0, 0.08)
        cat   = 0.00 + 0.80 * base_skill  + rng.normal(0, 0.14)
        ldv   = rng.normal(0, 0.05)
        ctde  = 0.01 + 0.06 * base_skill  + rng.normal(0, 0.01)
        skill = 0.005 + 0.04 * base_skill + rng.normal(0, 0.008)

        # Clip to realistic ranges
        fmt   = float(np.clip(fmt,   -0.30, 1.0))
        evi   = float(np.clip(evi,    0.0,  1.0))
        sev   = float(np.clip(sev,   -0.50, 1.0))
        cnt   = float(np.clip(cnt,    0.0,  1.0))
        eff   = float(np.clip(eff,   -0.30, 1.0))
        cat   = float(np.clip(cat,   -0.30, 1.0))
        ldv   = float(np.clip(ldv,   -0.30, 0.5))
        ctde  = float(np.clip(ctde,   0.0,  0.08))
        skill = float(np.clip(skill,  0.0,  0.07))

        W = {"fmt": 0.11, "evi": 0.19, "sev": 0.14,
             "cnt": 0.17, "eff": 0.10, "cat": 0.09, "ldv": 0.05}
        total = (W["fmt"] * fmt + W["evi"] * evi + W["sev"] * sev +
                 W["cnt"] * cnt + W["eff"] * eff + W["cat"] * cat +
                 W["ldv"] * ldv + ctde + skill)

        log["step"].append(t)
        log["total"].append(round(total, 4))
        log["format"].append(round(fmt, 4))
        log["evidence"].append(round(evi, 4))
        log["severity"].append(round(sev, 4))
        log["containment"].append(round(cnt, 4))
        log["efficiency"].append(round(eff, 4))
        log["category"].append(round(cat, 4))
        log["len_div"].append(round(ldv, 4))
        log["ctde_bonus"].append(round(ctde, 4))
        log["skill_bonus"].append(round(skill, 4))

    return log


def _dark_style(ax, title=""):
    """Apply consistent dark style to an axis."""
    ax.set_facecolor("#12122a")
    ax.set_title(title, fontweight="bold", color=COLORS["text"], fontsize=13, pad=10)
    ax.tick_params(colors=COLORS["text_dim"], labelsize=9)
    for spine in ax.spines.values():
        spine.set_color("#2a2a4a")
    ax.grid(True, alpha=0.15, color="#4a4a6a")
    ax.xaxis.label.set_color(COLORS["text_dim"])
    ax.yaxis.label.set_color(COLORS["text_dim"])


# ── Plot builders ───────────────────────────────────────────────────────────
def plot_composite(log, window):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "Composite Reward")
    raw = log["total"]
    ax.plot(raw, alpha=0.18, color=COLORS["accent2"], lw=0.6)
    s = smooth(raw, window)
    ax.plot(range(len(s)), s, color=COLORS["accent"], lw=2.5, label=f"Smoothed (w={window})")
    ax.set_xlabel("Step")
    ax.set_ylabel("Reward")
    ax.legend(facecolor=COLORS["card"], edgecolor="#3a3a5a", labelcolor=COLORS["text"], fontsize=9)
    fig.tight_layout()
    return fig


def plot_signals(log, window):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "Individual Reward Signals")
    for k, l, c in zip(SIGNAL_KEYS, SIGNAL_LABELS, SIGNAL_COLORS):
        if k in log and log[k]:
            s = smooth(log[k], window)
            ax.plot(range(len(s)), s, label=l, color=c, lw=2)
    ax.set_xlabel("Step")
    ax.set_ylabel("Reward")
    ax.legend(facecolor=COLORS["card"], edgecolor="#3a3a5a", labelcolor=COLORS["text"],
              fontsize=8, ncol=2)
    fig.tight_layout()
    return fig


def plot_bonuses(log, window):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "CTDE + H-MARL Bonuses")
    if "ctde_bonus" in log and log["ctde_bonus"]:
        s = smooth(log["ctde_bonus"], window)
        ax.plot(range(len(s)), s, color=COLORS["orange"], lw=2.5, label="CTDE Coordination")
    if "skill_bonus" in log and log["skill_bonus"]:
        s = smooth(log["skill_bonus"], window)
        ax.plot(range(len(s)), s, color=COLORS["purple"], lw=2.5, label="H-MARL Reasoning")
    if "len_div" in log and log["len_div"]:
        s = smooth(log["len_div"], window)
        ax.plot(range(len(s)), s, color=COLORS["teal"], lw=1.5, label="Length Diversity", alpha=0.7)
    ax.set_xlabel("Step")
    ax.set_ylabel("Bonus")
    ax.legend(facecolor=COLORS["card"], edgecolor="#3a3a5a", labelcolor=COLORS["text"], fontsize=9)
    fig.tight_layout()
    return fig


def plot_early_late(log):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "Early vs Late Rewards")
    raw = log["total"]
    n_cmp = min(50, len(raw) // 2)
    if n_cmp > 0:
        bp = ax.boxplot([raw[:n_cmp], raw[-n_cmp:]],
                        tick_labels=["First 50", "Last 50"], patch_artist=True,
                        medianprops=dict(color=COLORS["text"], lw=2),
                        whiskerprops=dict(color=COLORS["text_dim"]),
                        capprops=dict(color=COLORS["text_dim"]),
                        flierprops=dict(markerfacecolor=COLORS["text_dim"], marker=".", markersize=4))
        bp["boxes"][0].set_facecolor(COLORS["red"])
        bp["boxes"][0].set_alpha(0.7)
        bp["boxes"][1].set_facecolor(COLORS["green"])
        bp["boxes"][1].set_alpha(0.7)
        delta = np.mean(raw[-n_cmp:]) - np.mean(raw[:n_cmp])
        ax.annotate(f"Δ = {delta:+.4f}", xy=(1.5, np.mean(raw[-n_cmp:])),
                    fontsize=11, fontweight="bold",
                    color=COLORS["green"] if delta > 0 else COLORS["red"],
                    ha="center", va="bottom")
    ax.set_ylabel("Reward")
    fig.tight_layout()
    return fig


def plot_cumulative(log):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "Cumulative Reward")
    raw = log["total"]
    cum = np.cumsum(raw)
    ax.fill_between(range(len(cum)), cum, alpha=0.25, color=COLORS["accent2"])
    ax.plot(cum, color=COLORS["accent"], lw=2.5)
    ax.set_xlabel("Step")
    ax.set_ylabel("Cumulative")
    fig.tight_layout()
    return fig


def plot_heatmap(log):
    """Per-signal reward heatmap over training time."""
    fig, ax = plt.subplots(figsize=(9, 4.5))
    fig.patch.set_facecolor(COLORS["bg"])
    _dark_style(ax, "Reward Signal Heatmap")
    keys = [k for k in SIGNAL_KEYS if k in log and log[k]]
    if not keys:
        ax.text(0.5, 0.5, "No signal data available", ha="center", va="center",
                color=COLORS["text_dim"], fontsize=14, transform=ax.transAxes)
        fig.tight_layout()
        return fig

    # Build matrix: rows = signals, cols = steps (binned)
    n_bins = min(60, len(log[keys[0]]))
    mat = []
    labels = []
    for k in keys:
        data = np.array(log[k])
        # Bin into n_bins
        binned = [np.mean(chunk) for chunk in np.array_split(data, n_bins)]
        mat.append(binned)
        labels.append(dict(zip(SIGNAL_KEYS, SIGNAL_LABELS)).get(k, k))

    mat = np.array(mat)
    im = ax.imshow(mat, aspect="auto", cmap="RdYlGn", vmin=-0.5, vmax=1.0,
                   interpolation="bilinear")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9, color=COLORS["text"])
    ax.set_xlabel("Training Progress →")
    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.04)
    cbar.ax.tick_params(colors=COLORS["text_dim"], labelsize=8)
    fig.tight_layout()
    return fig


# ── Summary stats ───────────────────────────────────────────────────────────
def build_summary(log):
    raw = log["total"]
    if len(raw) < 10:
        return "Not enough data (need ≥ 10 steps)"
    first10 = np.mean(raw[:10])
    last10 = np.mean(raw[-10:])
    delta = last10 - first10
    lines = [
        f"## Training Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Total Steps** | {len(raw)} |",
        f"| **First 10 avg** | {first10:.4f} |",
        f"| **Last 10 avg** | {last10:.4f} |",
        f"| **Improvement** | {delta:+.4f} {'✅' if delta > 0 else '⚠️'} |",
        f"| **Peak reward** | {max(raw):.4f} (step {raw.index(max(raw))}) |",
        f"| **Min reward** | {min(raw):.4f} (step {raw.index(min(raw))}) |",
        f"| **Std (full)** | {np.std(raw):.4f} |",
        f"",
        f"### Per-Signal Trends",
        f"",
        f"| Signal | Start | End | Δ |",
        f"|--------|-------|-----|---|",
    ]
    all_keys = SIGNAL_KEYS + ["ctde_bonus", "skill_bonus", "len_div"]
    all_labels = SIGNAL_LABELS + ["CTDE Coord", "H-MARL Reasoning", "Length Diversity"]
    for k, l in zip(all_keys, all_labels):
        if k in log and len(log[k]) >= 10:
            v = log[k]
            s = np.mean(v[:10])
            e = np.mean(v[-10:])
            d = e - s
            emoji = "📈" if d > 0.01 else ("📉" if d < -0.01 else "➡️")
            lines.append(f"| {l} | {s:.3f} | {e:.3f} | {d:+.3f} {emoji} |")

    return "\n".join(lines)


# ── State ───────────────────────────────────────────────────────────────────
_current_log = generate_demo_data(150)


def _get_active_log():
    """Return live training log if running, else current static log."""
    live = train_runner.get_live_log()
    if live and live.get("total"):
        return live
    return _current_log


def load_json(file):
    global _current_log
    if file is None:
        return "No file uploaded"
    try:
        with open(file.name, "r") as f:
            data = json.load(f)
        if "total" not in data:
            return "\u274c JSON must contain a 'total' key with reward values"
        _current_log = data
        return f"\u2705 Loaded {len(data['total'])} steps from {os.path.basename(file.name)}"
    except Exception as e:
        return f"\u274c Error: {e}"


def use_demo():
    global _current_log
    _current_log = generate_demo_data(150)
    return "\u2705 Loaded 150-step demo data"


def handle_start(model_name, max_steps, lr, num_gen):
    return train_runner.start_training(model_name, max_steps, lr, num_gen)


def handle_stop():
    return train_runner.stop_training()


def poll_training_status():
    st = train_runner.get_status()
    status = st.get("status", "idle")
    step = st.get("step", 0)
    total = st.get("total", 0)
    err = st.get("error", "")
    if status == "idle":
        return "\u23f8\ufe0f  Idle — configure and start training"
    elif status == "loading_model":
        return "\u2b07\ufe0f  Loading model..."
    elif status == "configuring":
        return "\u2699\ufe0f  Configuring trainer..."
    elif status == "training":
        pct = (step / total * 100) if total else 0
        bar = '\u2588' * int(pct // 5) + '\u2591' * (20 - int(pct // 5))
        return f"\U0001f3cb\ufe0f  Training [{bar}] Step {step}/{total} ({pct:.0f}%)"
    elif status == "saving":
        return "\U0001f4be Saving model..."
    elif status == "done":
        return f"\u2705 Training complete! {total} steps finished."
    elif status == "error":
        return f"\u274c Error: {err}"
    return f"\u2753 {status}"


def refresh_all(window):
    w = int(window)
    log = _get_active_log()
    return (
        plot_composite(log, w),
        plot_signals(log, w),
        plot_bonuses(log, w),
        plot_early_late(log),
        plot_cumulative(log),
        plot_heatmap(log),
        build_summary(log),
    )


def auto_refresh(window):
    """Called by timer every 5s during training."""
    return refresh_all(window)


def export_json():
    path = os.path.join(os.path.dirname(__file__), "reward_log_export.json")
    with open(path, "w") as f:
        json.dump(_current_log, f, indent=2)
    return path


# ── CSS ─────────────────────────────────────────────────────────────────────
CUSTOM_CSS = """
.gradio-container {
    max-width: 1400px !important;
    background: #0f0f1a !important;
}
.gr-box, .gr-panel {
    border-color: #2a2a4a !important;
}
.header-banner {
    background: linear-gradient(135deg, #1a1a3e 0%, #0f0f2a 50%, #1a0a2e 100%);
    border: 1px solid #2a2a5a;
    border-radius: 16px;
    padding: 28px 36px;
    margin-bottom: 16px;
}
.header-banner h1 {
    background: linear-gradient(90deg, #6c63ff, #00d2ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-size: 2rem;
    margin: 0 0 6px 0;
}
.header-banner p {
    color: #8888bb;
    margin: 0;
    font-size: 0.95rem;
}
.stat-card {
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 12px;
    padding: 16px;
    text-align: center;
}
.stat-card h3 {
    color: #6c63ff;
    margin: 0 0 4px 0;
    font-size: 1.8rem;
}
.stat-card p {
    color: #8888aa;
    margin: 0;
    font-size: 0.85rem;
}
footer { display: none !important; }
"""


# ── Gradio UI ───────────────────────────────────────────────────────────────
def create_app():
    with gr.Blocks(
        title="GRPO SOC Training Dashboard",
        css=CUSTOM_CSS,
        theme=gr.themes.Base(
            primary_hue=gr.themes.colors.indigo,
            secondary_hue=gr.themes.colors.cyan,
            neutral_hue=gr.themes.colors.gray,
            font=gr.themes.GoogleFont("Inter"),
        ).set(
            body_background_fill="#0f0f1a",
            body_background_fill_dark="#0f0f1a",
            block_background_fill="#1a1a2e",
            block_background_fill_dark="#1a1a2e",
            block_border_color="#2a2a4a",
            block_border_color_dark="#2a2a4a",
            block_label_text_color="#8888bb",
            block_label_text_color_dark="#8888bb",
            block_title_text_color="#e0e0e0",
            block_title_text_color_dark="#e0e0e0",
            body_text_color="#e0e0e0",
            body_text_color_dark="#e0e0e0",
            button_primary_background_fill="#6c63ff",
            button_primary_background_fill_dark="#6c63ff",
            button_primary_text_color="#ffffff",
            input_background_fill="#12122a",
            input_background_fill_dark="#12122a",
            input_border_color="#3a3a5a",
            input_border_color_dark="#3a3a5a",
        ),
    ) as app:

        # Header
        gr.HTML("""
        <div class="header-banner">
            <h1>🛡️ GRPO SOC Training Dashboard</h1>
            <p>Self-Evolving Multi-Agent SOC Pipeline — Reward Curves, CTDE/H-MARL Bonuses, α-Curriculum</p>
        </div>
        """)

        # Controls row
        with gr.Row():
            with gr.Column(scale=2):
                upload_btn = gr.File(label="📂 Upload reward_log.json", file_types=[".json"])
            with gr.Column(scale=1):
                demo_btn = gr.Button("🧪 Load Demo Data", variant="secondary", size="lg")
            with gr.Column(scale=1):
                window_slider = gr.Slider(minimum=3, maximum=30, value=10, step=1,
                                          label="Smoothing Window")
            with gr.Column(scale=1):
                refresh_btn = gr.Button("🔄 Refresh Plots", variant="primary", size="lg")

        status_bar = gr.Textbox(value="✅ Demo data loaded (150 steps)", label="Status",
                                interactive=False, max_lines=1)

        # Main graphs
        with gr.Tabs():
            with gr.TabItem("\U0001f680 Training"):
                with gr.Row():
                    with gr.Column(scale=2):
                        model_input = gr.Textbox(
                            value="unsloth/Qwen3-4B",
                            label="Model Name (HuggingFace)",
                        )
                    with gr.Column(scale=1):
                        steps_input = gr.Number(value=100, label="Max Steps", precision=0)
                    with gr.Column(scale=1):
                        lr_input = gr.Number(value=5e-6, label="Learning Rate")
                    with gr.Column(scale=1):
                        gen_input = gr.Number(value=8, label="Num Generations", precision=0)
                with gr.Row():
                    start_btn = gr.Button("\U0001f680 Start Training", variant="primary", size="lg")
                    stop_btn = gr.Button("\u23f9\ufe0f Stop Training", variant="stop", size="lg")
                train_status = gr.Textbox(
                    value="\u23f8\ufe0f  Idle \u2014 configure and start training",
                    label="Training Status", interactive=False, max_lines=2,
                )
                gr.Markdown("*Graphs below auto-refresh every 5 seconds during training.*")

            with gr.TabItem("\U0001f4ca Overview"):
                with gr.Row():
                    composite_plot = gr.Plot(label="Composite Reward")
                    signals_plot = gr.Plot(label="Individual Signals")
                with gr.Row():
                    bonuses_plot = gr.Plot(label="CTDE + H-MARL Bonuses")
                    heatmap_plot = gr.Plot(label="Reward Heatmap")

            with gr.TabItem("\U0001f4c8 Comparison"):
                with gr.Row():
                    early_late_plot = gr.Plot(label="Early vs Late")
                    cumulative_plot = gr.Plot(label="Cumulative Reward")

            with gr.TabItem("\U0001f4cb Summary"):
                summary_md = gr.Markdown(value=build_summary(_current_log))
                export_btn = gr.Button("\U0001f4be Export reward_log.json", variant="secondary")
                export_file = gr.File(label="Download", visible=False)

        # Wire events
        all_outputs = [composite_plot, signals_plot, bonuses_plot,
                       early_late_plot, cumulative_plot, heatmap_plot, summary_md]

        refresh_btn.click(fn=refresh_all, inputs=[window_slider], outputs=all_outputs)

        upload_btn.change(fn=load_json, inputs=[upload_btn], outputs=[status_bar]).then(
            fn=refresh_all, inputs=[window_slider], outputs=all_outputs
        )

        demo_btn.click(fn=use_demo, outputs=[status_bar]).then(
            fn=refresh_all, inputs=[window_slider], outputs=all_outputs
        )

        export_btn.click(fn=export_json, outputs=[export_file]).then(
            fn=lambda: gr.update(visible=True), outputs=[export_file]
        )

        # Training controls
        start_btn.click(
            fn=handle_start,
            inputs=[model_input, steps_input, lr_input, gen_input],
            outputs=[train_status],
        )
        stop_btn.click(fn=handle_stop, outputs=[train_status])

        # Auto-refresh timer: polls every 5s, updates status + graphs
        timer = gr.Timer(value=5)
        timer.tick(fn=poll_training_status, outputs=[train_status])
        timer.tick(fn=auto_refresh, inputs=[window_slider], outputs=all_outputs)

        # Load initial plots
        app.load(fn=refresh_all, inputs=[window_slider], outputs=all_outputs)

    return app


if __name__ == "__main__":
    app = create_app()
    # Auto-detect HF Spaces: bind 0.0.0.0:7860 when deployed, localhost:7865 locally
    is_hf_space = os.environ.get("SPACE_ID") is not None
    app.launch(
        server_name="0.0.0.0" if is_hf_space else "127.0.0.1",
        server_port=7860 if is_hf_space else 7865,
        share=False,
    )
