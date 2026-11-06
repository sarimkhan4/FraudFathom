"""FraudFathom — explainable, rule-based digital fraud detection."""
from __future__ import annotations
import re
from datetime import datetime
import streamlit as st

from engine import run_prolog, parse_output, PrologUnavailable, PrologExecutionError
from detector import analyze_message, FLAGS, GROUPS, CHANNELS, PRESETS

st.set_page_config(page_title="FraudFathom", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap');
:root { --ink:#17243a; --muted:#62718a; --panel:#ffffff; --line:#e2e8f0; --accent:#176b59; }
html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
.stApp { background:#f5f8fc; color:var(--ink); }
h1,h2,h3 { font-family:'Manrope',sans-serif !important; letter-spacing:-.025em; color:#17243a; }
.block-container { max-width:1440px; padding-top:1.5rem; padding-bottom:3rem; }
[data-testid="stSidebar"] { background:#ffffff; border-right:1px solid #e2e8f0; }
[data-testid="stMetric"] { background:#ffffff; border:1px solid #e2e8f0; padding:16px 18px; border-radius:15px; box-shadow:0 2px 8px rgba(24,39,75,.04); }
[data-testid="stMetricValue"] { color:#176b59; }
div[data-testid="stVerticalBlockBorderWrapper"] { border-color:#e2e8f0 !important; background:#fff; border-radius:14px; }
.stButton>button[kind="primary"] { background:#176b59; border:0; color:white; font-weight:700; border-radius:11px; min-height:3rem; }
.stButton>button { border-radius:10px; border-color:#d5deea; }
.hero { padding:28px 30px; border:1px solid #dce8e4; border-radius:20px; background:linear-gradient(115deg,#e8f5f0,#ffffff 75%); margin-bottom:22px; }
.eyebrow { color:#176b59; font-size:.76rem; font-weight:800; letter-spacing:.13em; text-transform:uppercase; }
.hero h1 { font-size:2.55rem; margin:.35rem 0 .2rem; color:#142b27; }
.hero p { color:#526779; margin:0; max-width:760px; }
.panel { background:#ffffff; border:1px solid #e2e8f0; border-radius:16px; padding:18px 20px; box-shadow:0 2px 8px rgba(24,39,75,.035); }
.muted,.small-note { color:#62718a; }
.small-note { font-size:.84rem; }
.pill { display:inline-block; padding:5px 10px; border-radius:30px; background:#e7f4ef; color:#176b59; font-size:.78rem; margin:3px 4px 3px 0; }
div[data-testid="stAlert"] { border-radius:13px; }
</style>
""", unsafe_allow_html=True)

if "history" not in st.session_state: st.session_state.history = []
if "analysis_result" not in st.session_state: st.session_state.analysis_result = None
if "detected_flags" not in st.session_state: st.session_state.detected_flags = []

with st.sidebar:
    st.markdown("## 🛡️ FraudFathom")
    st.caption("DIGITAL FRAUD INTELLIGENCE")
    page = st.radio("Workspace", ["Dashboard", "Analyze a message", "Knowledge base", "About & methodology"], label_visibility="collapsed")
    st.divider()
    st.markdown("**Try a demo scenario**")
    for name, preset in PRESETS.items():
        if st.button(name, use_container_width=True):
            st.session_state.demo_preset = preset
            st.session_state.detected_flags = list(preset["flags"])
            st.session_state.demo_channel = preset["channel"]
            for flag in FLAGS:
                st.session_state[f"flag_{flag}"] = flag in preset["flags"]
            st.session_state.analysis_result = None
            st.rerun()
    st.divider()
    st.caption("AI method")
    st.markdown("**Rule-based expert system**  \nPython · Streamlit · SWI-Prolog")
    st.caption("Educational decision-support tool. It cannot verify whether a sender or message is genuinely fraudulent.")

def header():
    st.markdown("""
    <div class="hero">
      <div class="eyebrow">Pakistan-focused · Explainable AI</div>
      <h1>FraudFathom</h1>
      <p>Understand suspicious digital messages before you act. Explore warning signs, inspect the reasoning, and get practical next steps.</p>
    </div>""", unsafe_allow_html=True)

def risk_color(level):
    return {"critical":"#ff5d70","high":"#ff9d5c","medium":"#f5cf65","low":"#54d6a0"}.get(level,"#9eacc7")

def run_analysis(flags, channel, message=""):
    # An empty evidence set is still a valid baseline assessment. It should
    # produce a low-risk result with an explicit caution, not block the user.
    try:
        raw = run_prolog(flags, channel)
        result = parse_output(raw)
    except PrologUnavailable as exc:
        st.error(str(exc))
        st.info("Install SWI-Prolog, make sure the `swipl` command is available in PATH, then restart this application.")
        return
    except (PrologExecutionError, ValueError) as exc:
        st.error(f"Analysis could not be completed: {exc}")
        return
    result["input_flags"] = list(flags)
    result["channel"] = channel
    result["message"] = message
    result["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    st.session_state.analysis_result = result
    st.session_state.history.insert(0, result)
    st.session_state.history = st.session_state.history[:10]

def show_result(r):
    level = r["level"]
    color = risk_color(level)
    score_pct = min(100, round(r["score"] / 30 * 100))
    st.markdown(f"""
    <div class="panel" style="border-left:5px solid {color};">
      <div class="eyebrow">Assessment result</div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div><div style="font-size:2rem;font-weight:700;color:{color};text-transform:uppercase">{level} RISK</div>
        <div class="muted">Rule-based risk assessment · {r['created_at']}</div></div>
        <div style="text-align:right"><div style="font-size:2.2rem;font-weight:700">{r['score']}</div><div class="muted">weighted points</div></div>
      </div>
      <div style="height:9px;background:#263650;border-radius:9px;margin-top:16px;overflow:hidden">
        <div style="height:100%;width:{score_pct}%;background:{color};border-radius:9px"></div>
      </div>
      <div class="small-note" style="margin-top:8px">Visual scale is capped at 30 points; risk categories are determined by Prolog thresholds.</div>
    </div>""", unsafe_allow_html=True)
    left, right = st.columns([1.1, .9], gap="large")
    with left:
        st.subheader("🧩 Detected scam patterns")
        if not r["scams"]:
            st.info("No known scam pattern matched the selected evidence. This does not prove the message is safe.")
        for scam, rule_id, description in r["scams"]:
            with st.expander(f"{scam.replace('_',' ').title()} · {rule_id}", expanded=True):
                st.write(description)
                st.caption("Knowledge-base rule")
                st.code(r.get("rule_sources", {}).get(rule_id, "Rule source unavailable."), language="prolog")
        st.subheader("🧠 Derived reasoning signals")
        if r["flags"]:
            st.markdown("".join(f'<span class="pill">{x.replace("_"," ")}</span>' for x in r["flags"]), unsafe_allow_html=True)
        else: st.write("No intermediate signals derived.")
    with right:
        st.subheader("✅ Recommended next steps")
        if r["actions"]:
            for i, action in enumerate(r["actions"], 1):
                st.markdown(f"**{i}.** {action}")
        else:
            st.write("No additional action rule was triggered. Remain cautious.")
        st.subheader("Evidence supplied")
        st.write(", ".join(x.replace("_"," ") for x in r["input_flags"]) or "None")
        st.caption(f"Contact channel: {r['channel'].replace('_',' ').title()}")
        report = [
            "FRAUDFATHOM — ANALYSIS REPORT", f"Generated: {r['created_at']}",
            f"Risk level: {level.upper()}", f"Weighted points: {r['score']}",
            f"Channel: {r['channel']}", f"Message: {r.get('message') or '(not supplied)'}",
            "Evidence: " + ", ".join(r["input_flags"]),
            "Detected patterns: " + ", ".join(x[0] for x in r["scams"]),
            "Derived signals: " + ", ".join(r["flags"]),
            "Recommended actions:", *[f"- {a}" for a in r["actions"]],
            "", "Disclaimer: This is a rule-based educational assessment, not a verified fraud determination."
        ]
        st.download_button("⬇️ Download analysis report", "\n".join(report), file_name="fraudfathom-analysis.txt", mime="text/plain", use_container_width=True)

header()

if page == "Dashboard":
    st.markdown("### Security overview")
    a,b,c = st.columns(3)
    a.metric("Knowledge-base scam patterns", "16")
    b.metric("Scam classification rules", str(sum(1 for line in open(__file__.replace("app.py", "fraud_knowledge_base.pl"), encoding="utf-8") if line.strip().startswith("scam(") and ":-" in line)))
    c.metric("Recent analyses", len(st.session_state.history))
    st.markdown("")
    st.markdown("### How FraudFathom reasons")
    stages = st.columns(4)
    for col, n, title, desc in zip(stages, ["01","02","03","04"], ["Observe","Infer","Classify","Advise"], ["User reports warning signs or submits a message.","Prolog derives higher-level fraud signals.","Rules identify matching scam patterns and risk.","The system explains its findings and suggests actions."]):
        with col:
            st.markdown(f'<div class="panel"><div class="eyebrow">STEP {n}</div><h3>{title}</h3><div class="small-note">{desc}</div></div>', unsafe_allow_html=True)
    st.markdown("### Recent assessments")
    if not st.session_state.history:
        st.info("No assessments yet. Open **Analyze a message** or choose a demo scenario from the sidebar.")
    else:
        for item in st.session_state.history[:5]:
            st.markdown(f"- **{item['created_at']}** · {item['level'].upper()} risk · {item['score']} points · {len(item['scams'])} pattern(s) matched")

elif page == "Analyze a message":
    st.markdown("### Analyze a suspicious interaction")
    st.caption("Paste the message or describe what happened. Automatic extraction is keyword-based and may miss context; review the detected indicators before running the expert system. You can also analyze a normal message with no selected warning signs to establish a low-risk baseline.")
    message = st.text_area("Message / conversation text", height=150, placeholder="Example: Your bank account will be blocked. Reply with your OTP immediately...")
    channel_default = st.session_state.get("demo_channel", "whatsapp")
    channel = st.selectbox("Where did it reach you?", CHANNELS, index=CHANNELS.index(channel_default) if channel_default in CHANNELS else 2, format_func=lambda x:x.replace("_"," ").title())
    extracted = analyze_message(message) if message.strip() else {"flags": [], "evidence": {}}
    if message.strip():
        st.markdown("**Keyword-based indicators found**")
        if extracted["flags"]:
            for flag in extracted["flags"]:
                st.markdown(f"- `{flag}` — {extracted['evidence'][flag]}")
        else:
            st.info("No configured keyword patterns were detected. You can still select indicators manually, or run the analysis to get a no-indicator baseline result.")
    preset_flags = set(st.session_state.get("detected_flags", []))
    selected = set(extracted["flags"]) | preset_flags
    if st.session_state.get("_checkbox_message") != message:
        for flag in FLAGS:
            st.session_state[f"flag_{flag}"] = flag in selected
        st.session_state["_checkbox_message"] = message
    st.markdown("### Review warning signs")
    st.caption("Select every sign that applies. Automatic suggestions are preselected, but you remain in control.")
    selected_flags = []
    cols = st.columns(2)
    for i, (group, items) in enumerate(GROUPS.items()):
        with cols[i % 2]:
            with st.container(border=True):
                st.markdown(f"**{group}**")
                for flag, label in items.items():
                    checked = st.checkbox(label, key=f"flag_{flag}")
                    if checked: selected_flags.append(flag)
    if st.button("🔍 Analyze with expert system", type="primary", use_container_width=True):
        # Always include automatically extracted indicators. Streamlit checkbox
        # widget keys can retain an earlier value across reruns, so relying only
        # on selected_flags can accidentally discard fresh message detections.
        evidence_flags = sorted(set(selected_flags) | set(extracted["flags"]))
        run_analysis(evidence_flags, channel, message)
    if st.session_state.analysis_result:
        st.divider()
        show_result(st.session_state.analysis_result)

elif page == "Knowledge base":
    st.markdown("### Knowledge base explorer")
    st.write("The Prolog knowledge base contains 63 scam-classification rules, 26 signal-derivation clauses, and 11 advice rules (100 documented inference/advice clauses in total), plus facts, weights and risk thresholds.")
    for group, items in GROUPS.items():
        with st.expander(group):
            for flag, label in items.items():
                st.markdown(f"- **{flag}** — {label}")
    st.markdown("### Inference pipeline")
    st.code("""Observed facts (Python input)
        ↓
Derived signals (Prolog rules)
        ↓
Scam classification (scam/2 rules)
        ↓
Weighted risk score and risk level
        ↓
Advice rules + explanation""")
    st.markdown("### Risk thresholds")
    st.table({"Risk level":["Low","Medium","High","Critical"],"Weighted points":["0–2","3–6","7–11","12+"],"Interpretation":["Few configured indicators","Some warning signs","Multiple or serious warning signs","Strong combination of warning signs"]})

else:
    st.markdown("### About this project")
    st.write("FraudFathom is an explainable, rule-based expert system designed as an educational decision-support prototype for common digital fraud patterns relevant to Pakistan.")
    st.markdown("### Technology stack")
    st.table({"Component":["User interface","Application logic","Knowledge representation","Inference engine"],"Technology":["Streamlit","Python","Prolog facts and IF–THEN rules","SWI-Prolog"]})
    st.markdown("### AI concepts demonstrated")
    st.markdown("- **Knowledge representation:** facts, predicates and rules.\n- **Inference:** Prolog goal resolution, unification and backtracking.\n- **Rule-based classification:** scam patterns inferred from combinations of evidence.\n- **Explainability:** fired rule IDs and intermediate signals.\n- **Decision support:** weighted risk score and rule-triggered recommendations.")
    st.markdown("### Limitations and responsible use")
    st.markdown("- This is not a trained machine-learning model and does not learn from new messages.\n- Text extraction uses a small keyword/phrase dictionary; it is not semantic NLP.\n- The risk score is a heuristic, not a calibrated probability of fraud.\n- A low score does not establish that a message is safe.\n- Rules and reporting guidance should be validated against current official sources before real-world deployment.")
    st.markdown("### Setup")
    st.code("python -m venv .venv\n# activate the environment\npip install -r requirements.txt\n# install SWI-Prolog separately and ensure `swipl` is on PATH\nstreamlit run app.py", language="bash")
