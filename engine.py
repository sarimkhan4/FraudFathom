"""Safe, validated bridge between Python and SWI-Prolog."""
from pathlib import Path
import shutil
import subprocess
import re

KB_PATH = Path(__file__).with_name("fraud_knowledge_base.pl")

class PrologUnavailable(RuntimeError): pass
class PrologExecutionError(RuntimeError): pass

def run_prolog(flags, channel):
    swipl = shutil.which("swipl")
    if not swipl:
        raise PrologUnavailable("SWI-Prolog was not found. Install SWI-Prolog and add `swipl` to your system PATH.")
    from detector import FLAGS, CHANNELS
    unknown = set(flags) - set(FLAGS)
    if unknown: raise ValueError(f"Unsupported evidence flags: {', '.join(sorted(unknown))}")
    if channel not in CHANNELS: raise ValueError("Unsupported contact channel.")
    facts = list(dict.fromkeys(flags))
    facts.append(f"channel({channel})")
    goal = f"maplist(assertz,[{','.join(facts)}]),run"
    try:
        proc = subprocess.run(
            [swipl, "-q", "-s", str(KB_PATH), "-g", goal, "-t", "halt"],
            capture_output=True, text=True, timeout=15, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise PrologExecutionError("The Prolog inference process timed out.") from exc
    if proc.returncode != 0:
        raise PrologExecutionError((proc.stderr or proc.stdout or "Unknown Prolog execution error").strip())
    return proc.stdout

def parse_output(output):
    result = {"score":0, "level":"low", "flags":[], "scams":[], "actions":[], "rule_sources":{}}
    for line in output.splitlines():
        parts = line.split("|", 3)
        if not parts: continue
        if parts[0] == "SCORE" and len(parts) >= 2: result["score"] = int(parts[1])
        elif parts[0] == "LEVEL" and len(parts) >= 2: result["level"] = parts[1]
        elif parts[0] == "FLAG" and len(parts) >= 2: result["flags"].append(parts[1])
        elif parts[0] == "SCAM" and len(parts) >= 4: result["scams"].append((parts[1],parts[2],parts[3]))
        elif parts[0] == "ACTION" and len(parts) >= 2: result["actions"].append(parts[1])
    if result["level"] not in {"low","medium","high","critical"}:
        raise ValueError("Prolog returned an invalid risk level.")
    # Attach the exact source clauses for every matched rule ID.
    try:
        for line in KB_PATH.read_text(encoding="utf-8").splitlines():
            for _, rule_id, _ in result["scams"]:
                if line.strip().startswith("scam(") and re.search(rf",\s*{re.escape(rule_id)}\s*\)", line):
                    result["rule_sources"][rule_id] = line.strip()
    except OSError:
        pass
    return result
