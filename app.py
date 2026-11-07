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
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

/* ============ FraudFathom UI theme ============
   Colours are neutral translucent layers + two accents, so the same
   stylesheet reads correctly on Streamlit's light AND dark themes.   */
:root {
  --ff-teal:#14b8a6; --ff-indigo:#6366f1; --ff-rose:#f43f5e;
  --ff-grad:linear-gradient(135deg,#14b8a6 0%,#6366f1 100%);
  --ff-glass:rgba(127,127,127,.085);
  --ff-glass-2:rgba(127,127,127,.15);
  --ff-line:rgba(127,127,127,.28);
  --ff-glow:0 20px 44px -26px rgba(20,184,166,.75);
}
.stApp :is(p,li,label,button,input,textarea,td,th,summary,a,small) { font-family:'Plus Jakarta Sans',system-ui,-apple-system,'Segoe UI',sans-serif; }
.stApp :is(h1,h2,h3,h4) { font-family:'Space Grotesk','Plus Jakarta Sans',sans-serif !important; letter-spacing:-.02em; }
.stApp {
  background-image:
    radial-gradient(900px 520px at 6% -8%, rgba(20,184,166,.18), transparent 62%),
    radial-gradient(820px 520px at 100% -4%, rgba(99,102,241,.17), transparent 62%),
    radial-gradient(700px 480px at 50% 112%, rgba(244,63,94,.07), transparent 65%);
  background-attachment:fixed;
}
[data-testid="stHeader"] { background:transparent; }
.block-container { max-width:1360px; padding-top:1.6rem; padding-bottom:3.5rem; }
hr { border-color:var(--ff-line) !important; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] { border-right:1px solid var(--ff-line); background-image:linear-gradient(180deg,rgba(20,184,166,.10),rgba(99,102,241,.07) 60%,transparent); }
[data-testid="stSidebar"] h2 { font-size:1.55rem; background:var(--ff-grad); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] { letter-spacing:.06em; }
[data-testid="stSidebar"] [data-testid="stRadioOption"], [data-testid="stSidebar"] label[data-baseweb="radio"] {
  padding:10px 14px; margin:3px 0; border-radius:12px; border:1px solid transparent; transition:all .18s ease; width:100%; }
[data-testid="stSidebar"] [data-testid="stRadioOption"]:hover, [data-testid="stSidebar"] label[data-baseweb="radio"]:hover { background:var(--ff-glass-2); }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"], [data-testid="stSidebar"] [data-testid="stRadioOption"]:has(input:checked) {
  background:linear-gradient(120deg,rgba(20,184,166,.24),rgba(99,102,241,.20)); border-color:rgba(20,184,166,.55); font-weight:700; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child { display:none; }

/* ---------- hero ---------- */
.hero { position:relative; overflow:hidden; display:flex; align-items:center; gap:26px; padding:32px 36px; margin-bottom:26px;
  border:1px solid var(--ff-line); border-radius:26px; box-shadow:var(--ff-glow); backdrop-filter:blur(10px);
  background:linear-gradient(120deg,rgba(20,184,166,.22),rgba(99,102,241,.17) 58%,rgba(244,63,94,.10)); }
.hero::after { content:""; position:absolute; right:-70px; top:-80px; width:300px; height:300px; border-radius:50%; background:radial-gradient(circle,rgba(99,102,241,.38),transparent 66%); pointer-events:none; }
.hero-mark { flex:0 0 auto; width:74px; height:74px; display:grid; place-items:center; font-size:2.2rem; border-radius:22px; background:var(--ff-grad); box-shadow:0 14px 30px -12px rgba(99,102,241,.8); }
.hero-body { position:relative; z-index:1; }
.eyebrow { color:var(--ff-teal); font-size:.74rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
.hero h1 { font-size:3.1rem; line-height:1.05; margin:.3rem 0 .45rem; padding:0; font-weight:700;
  background:var(--ff-grad); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
.hero p { margin:0; max-width:760px; opacity:.78; line-height:1.55; }
.chips { margin-top:14px; }
.chip { display:inline-block; padding:4px 12px; margin:0 6px 4px 0; border-radius:30px; font-size:.74rem; font-weight:600; border:1px solid var(--ff-line); background:var(--ff-glass); }

/* ---------- cards ---------- */
.stApp [data-testid="stMarkdownContainer"] h3 { padding-top:1.1rem; }
.panel { background:var(--ff-glass); border:1px solid var(--ff-line); border-radius:18px; padding:20px 22px; backdrop-filter:blur(8px); transition:transform .2s ease, border-color .2s ease, box-shadow .2s ease; }
.panel:hover { transform:translateY(-3px); border-color:rgba(20,184,166,.6); box-shadow:var(--ff-glow); }
.stApp .panel h3 { margin:.25rem 0 .35rem; padding:0; font-size:1.35rem; }
.muted,.small-note { opacity:.7; }
.small-note { font-size:.84rem; line-height:1.5; }
.pill { display:inline-block; padding:5px 12px; margin:3px 5px 3px 0; border-radius:30px; font-size:.78rem; font-weight:600; border:1px solid rgba(20,184,166,.5); background:rgba(20,184,166,.14); }

[data-testid="stMetric"] { position:relative; overflow:hidden; background:var(--ff-glass); border:1px solid var(--ff-line); padding:18px 20px; border-radius:18px; }
[data-testid="stMetric"]::before { content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--ff-grad); }
[data-testid="stMetricValue"] { font-family:'Space Grotesk',sans-serif; font-weight:700; background:var(--ff-grad); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
[data-testid="stVerticalBlockBorderWrapper"], [data-testid="stLayoutWrapper"] > [data-testid="stVerticalBlock"] { border-color:var(--ff-line) !important; background:var(--ff-glass); border-radius:18px; }
[data-testid="stExpander"] { border:1px solid var(--ff-line) !important; border-radius:16px !important; background:var(--ff-glass); overflow:hidden; }
div[data-testid="stAlert"] { border-radius:14px; border:1px solid var(--ff-line); }
[data-testid="stCode"], [data-testid="stTable"] { border-radius:14px; overflow:hidden; border:1px solid var(--ff-line); }

/* ---------- inputs ---------- */
[data-baseweb="textarea"], [data-baseweb="select"] > div, [data-baseweb="base-input"] { border-radius:14px !important; border:1px solid var(--ff-line) !important; background-color:var(--ff-glass) !important; transition:border-color .18s, box-shadow .18s; }
[data-baseweb="textarea"]:focus-within, [data-baseweb="select"] > div:focus-within { border-color:var(--ff-teal) !important; box-shadow:0 0 0 3px rgba(20,184,166,.25); }
[data-testid="stCheckbox"] label:has(input:checked) > div:nth-of-type(1) { background-color:var(--ff-teal) !important; border-color:var(--ff-teal) !important; }

/* ---------- buttons ---------- */
.stButton>button, [data-testid="stDownloadButton"]>button { border-radius:12px; border:1px solid var(--ff-line); background:var(--ff-glass); transition:all .18s ease; }
.stButton>button:hover, [data-testid="stDownloadButton"]>button:hover { border-color:var(--ff-teal); transform:translateY(-1px); box-shadow:0 10px 22px -14px rgba(20,184,166,.9); }
.stButton>button[kind="primary"], [data-testid="stBaseButton-primary"] { background:var(--ff-grad); border:0; color:#fff; font-weight:700; letter-spacing:.01em; min-height:3.1rem; border-radius:14px; box-shadow:var(--ff-glow); }
.stButton>button[kind="primary"] p, [data-testid="stBaseButton-primary"] p { color:#fff; }
.stButton>button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover { filter:brightness(1.08); transform:translateY(-2px); }

/* ---------- assessment result ---------- */
.result { position:relative; overflow:hidden; border:1px solid var(--ff-line); border-radius:22px; padding:24px 28px; margin-bottom:8px;
  background:linear-gradient(120deg,color-mix(in srgb,var(--rc) 20%,transparent),var(--ff-glass) 70%); box-shadow:0 22px 46px -30px var(--rc); }
.result::before { content:""; position:absolute; left:0; top:0; bottom:0; width:6px; background:var(--rc); }
.result-top { display:flex; align-items:center; justify-content:space-between; gap:14px; flex-wrap:wrap; }
.result-level { font-family:'Space Grotesk',sans-serif; font-size:2.3rem; font-weight:700; text-transform:uppercase; color:var(--rc); line-height:1.1; margin:.2rem 0; }
.result-score { text-align:right; }
.result-score .num { font-family:'Space Grotesk',sans-serif; font-size:2.8rem; font-weight:700; line-height:1; }
.track { height:11px; border-radius:11px; margin-top:18px; overflow:hidden; background:var(--ff-glass-2); }
.fill { height:100%; border-radius:11px; background:linear-gradient(90deg,color-mix(in srgb,var(--rc) 55%,transparent),var(--rc)); box-shadow:0 0 14px var(--rc); }

@media (max-width:768px) { .hero { flex-direction:column; align-items:flex-start; padding:24px; } .hero h1 { font-size:2.3rem; } .result-score { text-align:left; } }
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
      <div class="hero-mark">🛡️</div>
      <div class="hero-body">
        <div class="eyebrow">Pakistan-focused · Explainable AI</div>
        <h1>FraudFathom</h1>
        <p>Understand suspicious digital messages before you act. Explore warning signs, inspect the reasoning, and get practical next steps.</p>
        <div class="chips"><span class="chip">Rule-based</span><span class="chip">SWI-Prolog inference</span><span class="chip">Transparent rules</span></div>
      </div>
    </div>""", unsafe_allow_html=True)

def risk_color(level):
    return {"critical":"#e11d48","high":"#ea580c","medium":"#d19a06","low":"#059669"}.get(level,"#7c8aa5")

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
    <div class="result" style="--rc:{color}">
      <div class="result-top">
        <div>
          <div class="eyebrow">Assessment result</div>
          <div class="result-level">{level} RISK</div>
          <div class="muted">Rule-based risk assessment · {r['created_at']}</div>
        </div>
        <div class="result-score"><div class="num">{r['score']}</div><div class="muted">weighted points</div></div>
      </div>
      <div class="track"><div class="fill" style="width:{score_pct}%"></div></div>
      <div class="small-note" style="margin-top:10px">Visual scale is capped at 30 points; risk categories are determined by Prolog thresholds.</div>
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
            st.markdown(f'<div class="panel step"><div class="eyebrow">STEP {n}</div><h3>{title}</h3><div class="small-note">{desc}</div></div>', unsafe_allow_html=True)
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