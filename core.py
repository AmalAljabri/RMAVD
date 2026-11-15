import os, re, json, time
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import ollama

# RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", '/content/results'))
RESULTS_DIR = Path(__file__).resolve().parent / "results"
EXP1_PATH, EXP2_PATH = RESULTS_DIR / "exp1_results.json", RESULTS_DIR / "exp2_results.json"


CONTEXT_LINES = 3

OLLAMA_HOST = 'http://localhost:11434'

MODEL_AGENT1 = 'qwen2.5-coder:14b'

MODEL_AGENT2 = 'deepseek-coder-v2:16b'

LLM_OPTS_AGENT1 = {'temperature': 0.2, 'num_ctx': 6144, 'num_predict': 700}

LLM_OPTS_AGENT2 = {'temperature': 0.1, 'num_ctx': 6144, 'num_predict': 500}

AGENT1_SYSTEM = 'ROLE:\nYou are an expert security code auditor.\n\nTASK:\nDetect potential security vulnerabilities in a Python repository. You receive one chunk of a file at a time.\n\nRULES:\n- Report EVERY vulnerability you can find in the chunk. Missing a real vulnerability is worse than a borderline report.\n- Lines marked \'|\' are the chunk. Lines marked \':\' are context only (3 lines above and below).\n- Use the line number from the left column. Report the line of the dangerous sink or of the hard-coded value.\n- One finding per vulnerability. Never invent code that is not shown.\n- The CWE must come from this list (vulnerability class = CWE): broken_access_control = CWE-639; broken_authentication = CWE-287; code_injection = CWE-94; command_injection = CWE-78; csrf = CWE-352; denial_of_service = CWE-400; dom_xss = CWE-79; hardcoded_credentials = CWE-798; idor = CWE-639; insecure_cookie = CWE-614; insecure_deserialization = CWE-502; mass_assignment = CWE-915; missing_access_control = CWE-862; missing_authentication = CWE-306; missing_authorization = CWE-862; missing_rate_limiting = CWE-307; open_redirect = CWE-601; path_traversal = CWE-22; plaintext_password_storage = CWE-256; reflected_xss = CWE-79; security_misconfiguration = CWE-16; sensitive_data_exposure = CWE-200; sql_injection = CWE-89; ssrf = CWE-918; ssti = CWE-1336; stored_xss = CWE-79; weak_cryptography = CWE-328; xpath_injection = CWE-643; xss = CWE-79; xxe = CWE-611\n- If there is no vulnerability, return {"findings": []}.\n- confidence_score 1.0 only if both the user-controlled source and the dangerous sink are visible in the chunk; otherwise use 0.5 to 0.8.\n\nFEW-SHOT EXAMPLES:\n### Example 1: CWE-94 (code_injection)\n```python\n     117 |     return """\n     118 |     <html>\n     119 |        <link rel= "stylesheet" type= "text/css" href="/static/styles/board.css"">\n>>>  120 |        <body>""" + "Result: " + (str(eval(expression)).replace(\'\\n\', \'\\n<br>\')  if expression else "") + """\n     121 |           <form action = "/evaluate" method = "POST">\n     122 |              <h1> Hello Folks! Give us your problem. We will provide you the best mathematical solution. </h1>\n     123 |              <p><h3>Enter expression to evaluate</h3></p>\n```\n**Vulnerable:** Arbitrary Python code execution via eval(). User input from request.form[\'expression\'] (line 116) is passed directly to eval() on line 120 with no sanitization: str(eval(expression)). An attacker can \n\n### Example 2: CWE-79 (reflected_xss)\n```python\n     117 |     return """\n     118 |     <html>\n     119 |        <link rel= "stylesheet" type= "text/css" href="/static/styles/board.css"">\n>>>  120 |        <body>""" + "Result: " + (str(eval(expression)).replace(\'\\n\', \'\\n<br>\')  if expression else "") + """\n     121 |           <form action = "/evaluate" method = "POST">\n     122 |              <h1> Hello Folks! Give us your problem. We will provide you the best mathematical solution. </h1>\n     123 |              <p><h3>Enter expression to evaluate</h3></p>\n```\n**Vulnerable:** The result of eval(expression) is concatenated directly into an HTML response string without any output encoding or escaping. Even if eval() only returns data (not code execution), any HTML/JS in the \n\n### Example 3: CWE-78 (command_injection)\n```python\n     137 |     return """\n     138 |     <html>\n     139 |     <link rel= "stylesheet" type= "text/css" href="/static/styles/board.css"">\n>>>  140 |        <body>""" + "Result:\\n<br>\\n" + (rp("nslookup " + address).replace(\'\\n\', \'\\n<br>\')  if address else "") + """\n     141 |           <form action = "/lookup" method = "POST">\n     142 |              <h1> Hello Folks!Are you searching for ip address?Just write and search.</h1>\n     143 |              <p><h3>Enter address to lookup</h3></p>\n```\n**Vulnerable:** OS command injection via unsanitized user input. The address parameter from request.form[\'address\'] (line 136) is concatenated directly into a shell command: rp(\'nslookup \' + address). The rp function\n\n### Example 4: CWE-611 (xxe)\n```python\n     154 |     parsed_xml = None\n     155 |     if request.method == \'POST\':\n     156 |         xml = request.form[\'xml\']\n>>>  157 |         parser = etree.XMLParser(no_network=False, dtd_validation=True)\n>>>  158 |         try:\n>>>  159 |             doc = etree.fromstring(str(xml), parser)\n     160 |             parsed_xml = etree.tostring(doc)\n     161 |         except:\n     162 |            pass\n```\n**Vulnerable:** XML External Entity (XXE) injection. The XML parser is created with etree.XMLParser(no_network=False, dtd_validation=True) on line 157, explicitly enabling network access and DTD validation. User-supp\n\nSTRUCTURED CHAIN-OF-THOUGHT:\nAnalyze the code using these steps:\n1. Find dangerous sinks (SQL, shell, eval/exec, file paths, deserialization, templates, crypto, secrets, redirects, outgoing requests).\n2. Find user-controlled inputs (request data, input(), argv, files, environment).\n3. Trace the input to the sink and look for sanitization.\n4. Choose the CWE and a confidence score between 0.0 and 1.0.\n\nOUTPUT FORMAT:\nReturn JSON only:\n{\n  "findings": [\n    {\n      "cwe": "CWE-89",\n      "vulnerability_class": "sql_injection",\n      "line_number": 0,\n      "code_snippet": "the vulnerable line",\n      "evidence": "source -> sink, one short sentence",\n      "confidence_score": 0.0\n    }\n  ]\n}'

AGENT2_SYSTEM = 'ROLE:\nYou are an expert security triage engineer acting as a false-positive reducer.\n\nTASK:\nReview Agent 1 findings and determine whether each finding is a real vulnerability or a false positive trap.\n\nRULES:\n- Judge only the line marked >>> using the code shown. Quote code in your reason, never repeat Agent 1\'s text alone.\n- Answer "real" ONLY IF all four tests pass:\n  1. SOURCE: untrusted input (request data, user input, argv, files, network) reaches the line, visible in the code.\n     Not required for hard-coded secrets, weak crypto, debug mode, missing CSRF or missing authentication.\n  2. SINK: the line is dangerous in the way it is used.\n  3. NO DEFENSE: no parameterization, escaping, validation, allow-list or safe API on the path.\n  4. CWE: the reported CWE matches what the code does.\n- Answer "false_positive" only when there is sufficient evidence that no real vulnerability exists or the CWE is incorrect.\n- Do not automatically reject constants, configurations, environment variables, test files, or findings with invisible sources.\n- Hard-coded secrets and insecure configurations may be real vulnerabilities.\n- Confidence: above 0.8 only with a concrete quoted proof. If you are unsure, lower the confidence and explain what evidence is missing.\n- Keep finding_id unchanged.\n\nFEW-SHOT EXAMPLES:\n### Example 1: looks like CWE-89 but is SAFE\n```python\n      47 |     else:\n      48 |         name = request.form[\'username\']\n      49 |         passw = request.form[\'password\']\n>>>   50 |         user = User.query.filter_by(username=name, password=passw).first()\n      51 |         if user:\n      52 |             session[\'logged_in\'] = True\n      53 |             return redirect(url_for(\'home\'))\n```\n**NOT vulnerable:** The login query uses SQLAlchemy ORM\'s filter_by() method: User.query.filter_by(username=name, password=passw).first(). Although user input (name, passw) flows directly into the query, SQLAlchemy\'s ORM\n\n### Example 2: looks like CWE-798 but is SAFE\n```python\n      16 | app.config[\'SQLALCHEMY_DATABASE_URI\'] = \'sqlite:///test.db\'\n      17 | db = SQLAlchemy(app)\n      18 | \n>>>   19 | CONFIG = {\n>>>   20 |     \'app_name\': \'Damn Vulnerable Flask Application\'\n>>>   21 | }\n      22 | class User(db.Model):\n      23 |     """ Create user table """\n      24 |     id = db.Column(db.Integer, primary_key=True)\n```\n**NOT vulnerable:** The CONFIG dictionary contains a hardcoded \'app_name\' string: CONFIG = {\'app_name\': \'Damn Vulnerable Flask Application\'}. While this looks like it could be a configuration with sensitive values, it on\n\nSTRUCTURED CHAIN-OF-THOUGHT:\nEvaluate each finding using:\n1. Source: where does the value come from, and is it user-controlled?\n2. Sink: is the line dangerous as written?\n3. Defense: is there sanitization, parameterization or validation before the sink?\n4. CWE: does the reported CWE match the code?\n5. Decide, then give a calibrated confidence between 0.0 and 1.0.\n\nOUTPUT FORMAT:\nReturn JSON only:\n{\n  "findings": [\n    {\n      "finding_id": "...",\n      "decision": "real" | "false_positive",\n      "confidence_score": 0.0,\n      "reason": "one short sentence quoting the code"\n    }\n  ]\n}'

CWE_CLASS = {'CWE-1004': 'security_misconfiguration', 'CWE-1021': 'security_misconfiguration', 'CWE-113': 'http_header_injection', 'CWE-117': 'log_injection', 'CWE-1333': 'denial_of_service', 'CWE-1336': 'ssti', 'CWE-1395': 'vulnerable_dependency', 'CWE-16': 'security_misconfiguration', 'CWE-20': 'business_logic_flaw', 'CWE-200': 'sensitive_data_exposure', 'CWE-204': 'credential_enumeration', 'CWE-209': 'sensitive_data_exposure', 'CWE-215': 'security_misconfiguration', 'CWE-22': 'path_traversal', 'CWE-235': 'http_parameter_pollution', 'CWE-256': 'sensitive_data_exposure', 'CWE-259': 'hardcoded_credentials', 'CWE-284': 'broken_access_control', 'CWE-287': 'broken_authentication', 'CWE-295': 'improper_certificate_validation', 'CWE-306': 'missing_authentication', 'CWE-307': 'missing_rate_limiting', 'CWE-312': 'sensitive_data_exposure', 'CWE-319': 'security_misconfiguration', 'CWE-321': 'hardcoded_credentials', 'CWE-326': 'security_misconfiguration', 'CWE-327': 'weak_cryptography', 'CWE-328': 'weak_cryptography', 'CWE-329': 'weak_cryptography', 'CWE-330': 'insecure_random', 'CWE-338': 'insecure_randomness', 'CWE-345': 'broken_authentication', 'CWE-347': 'broken_authentication', 'CWE-352': 'csrf', 'CWE-354': 'weak_cryptography', 'CWE-362': 'race_condition', 'CWE-384': 'session_fixation', 'CWE-400': 'denial_of_service', 'CWE-434': 'unrestricted_file_upload', 'CWE-489': 'security_misconfiguration', 'CWE-502': 'insecure_deserialization', 'CWE-521': 'password_complexity_bypass', 'CWE-522': 'sensitive_data_exposure', 'CWE-525': 'security_misconfiguration', 'CWE-532': 'sensitive_data_exposure', 'CWE-565': 'insecure_session', 'CWE-598': 'sensitive_data_exposure', 'CWE-601': 'open_redirect', 'CWE-611': 'xxe', 'CWE-613': 'missing_authentication', 'CWE-614': 'insecure_cookie', 'CWE-615': 'sensitive_data_exposure', 'CWE-639': 'idor', 'CWE-640': 'weak_password_recovery', 'CWE-643': 'xpath_injection', 'CWE-674': 'denial_of_service', 'CWE-693': 'security_misconfiguration', 'CWE-73': 'arbitrary_file_write', 'CWE-770': 'denial_of_service', 'CWE-78': 'command_injection', 'CWE-79': 'reflected_xss', 'CWE-798': 'hardcoded_credentials', 'CWE-807': 'broken_access_control', 'CWE-829': 'supply_chain', 'CWE-862': 'missing_access_control', 'CWE-89': 'sql_injection', 'CWE-915': 'mass_assignment', 'CWE-916': 'sensitive_data_exposure', 'CWE-918': 'ssrf', 'CWE-922': 'sensitive_data_exposure', 'CWE-94': 'code_injection', 'CWE-942': 'cors_misconfiguration', 'CWE-943': 'nosql_injection'}

COLORS = {'exp1': '#355C7D', 'exp2': '#548C78', 'gt': '#D6B66A', 'tp': '#548C78', 'fp': '#C17C5A', 'fn': '#8A83A8', 'tn': '#D6B66A'}

METRIC_COLS = ['precision', 'recall', 'accuracy', 'f1']

METRIC_LABELS = ['Precision', 'Recall', 'Accuracy', 'F1-score']

STYLE = {'font.size': 10, 'axes.titlesize': 12, 'axes.titleweight': 'bold', 'axes.spines.top': False, 'axes.spines.right': False, 'axes.grid': True, 'grid.alpha': 0.25, 'grid.linestyle': '--'}

client = ollama.Client(host=OLLAMA_HOST)


def norm_cwe(x):
    """'CWE-89', 89, 'cwe_89' -> 'CWE-89' (first number found, empty string if none)."""
    m = re.search(r"\d+", str(x))
    return f"CWE-{int(m.group())}" if m else ""


def cwe_set(x):
    """acceptable_cwes in any format (list, numpy array, JSON text, plain text) -> set of 'CWE-n'."""
    if x is None:
        return set()
    if hasattr(x, "tolist"):
        x = x.tolist()
    if isinstance(x, (list, tuple, set)):
        return {norm_cwe(e) for e in x if norm_cwe(e)}
    return {f"CWE-{int(n)}" for n in re.findall(r"\d+", str(x))}


def llm_json(model, system, user, opts):
    """One chat call that must return a JSON object (3 attempts)."""
    for attempt in range(3):
        o = dict(opts)
        if attempt:
            o["temperature"], o["repeat_penalty"] = 0.5, 1.15
        try:
            r = client.chat(model=model, format="json", options=o,
                            messages=[{"role": "system", "content": system},
                                      {"role": "user", "content": user}])
            return json.loads(r["message"]["content"])
        except Exception:
            continue
    return {}


def split_chunks(n_lines, size=40):
    """Split a file of n_lines into consecutive (start, end) chunks."""
    return [(s, min(s + size - 1, n_lines)) for s in range(1, n_lines + 1, size)]


def chunk_text(lines, start, end):
    """Chunk lines marked '|' plus CONTEXT_LINES context lines above and below marked ':'."""
    s, e = max(1, start - CONTEXT_LINES), min(len(lines), end + CONTEXT_LINES)
    return "\n".join(f"{i:4d} {'|' if start <= i <= end else ':'} {lines[i - 1][:200]}" for i in range(s, e + 1))


def is_test_path(path):
    return bool(re.search(r"(^|/)(tests?|testing)(/|$)|(^|/)test_[^/]*\.py$|_tests?\.py$|(^|/)conftest\.py$|(^|/)seed", path))


def text_color(hex_color):
    """Dark text on light colors, white text on dark colors."""
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return "#222222" if 0.299 * r + 0.587 * g + 0.114 * b > 150 else "white"


def agent1_scan_chunk(repo_id, file, lines, start, end):
    """Agent 1 on one chunk. Returns a list of findings with verified line numbers."""
    shown_s, shown_e = max(1, start - CONTEXT_LINES), min(len(lines), end + CONTEXT_LINES)
    user = f"FILE: {file}\nCHUNK: lines {start}-{end}\n\n```python\n{chunk_text(lines, start, end)}\n```\n\nReturn JSON only."
    data = llm_json(MODEL_AGENT1, AGENT1_SYSTEM, user, LLM_OPTS_AGENT1)
    raw = data.get("findings", []) if isinstance(data, dict) else []
    findings = []
    for f in raw if isinstance(raw, list) else []:
        if not isinstance(f, dict) or not norm_cwe(f.get("cwe")):
            continue
        try:
            model_line = int(f.get("line_number"))
        except (TypeError, ValueError):
            model_line = None
        snippet = str(f.get("code_snippet") or "").strip().splitlines()[0:1]
        hits = [i for i in range(shown_s, shown_e + 1) if snippet and len(snippet[0].strip()) >= 6 and snippet[0].strip() in lines[i - 1]]
        if hits:
            line = min(hits, key=lambda i: abs(i - (model_line or hits[0])))
        elif model_line and shown_s <= model_line <= shown_e:
            line = model_line
        else:
            continue
        try:
            conf = min(max(float(f.get("confidence_score", 0.5)), 0.0), 1.0)
        except (TypeError, ValueError):
            conf = 0.5
        findings.append({"repo_id": repo_id, "file_name": file, "line_number": line, "cwe": norm_cwe(f["cwe"]),
                         "vulnerability_class": str(f.get("vulnerability_class", "")),
                         "code_snippet": lines[line - 1].strip()[:300],
                         "evidence": str(f.get("evidence", ""))[:300], "confidence_score": conf})
    return findings


def agent1_scan_repo(repo_id, repo_dir, progress=None):
    """Agent 1 on a whole repository: every .py file, every chunk. Returns the de-duplicated findings."""
    repo_dir = Path(repo_dir)
    # files = sorted(repo_dir.rglob("*.py"))
    files = [p for p in sorted(repo_dir.rglob("*.py"))
         if not is_test_path(str(p.relative_to(repo_dir)).replace("\\", "/"))]
    found = []
    for k, path in enumerate(files, 1):
        rel = str(path.relative_to(repo_dir)).replace("\\", "/")
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for start, end in split_chunks(len(lines)):
            found += agent1_scan_chunk(repo_id, rel, lines, start, end)
        if progress:
            progress("agent1", k, len(files))
    unique = {}
    for f in sorted(found, key=lambda x: -x["confidence_score"]):
        unique.setdefault((f["file_name"], f["line_number"], f["cwe"]), f)
    findings = sorted(unique.values(), key=lambda x: (x["file_name"], x["line_number"]))
    for i, f in enumerate(findings, 1):
        f["finding_id"] = f"{repo_id}:{f['file_name']}:{f['line_number']}:{f['cwe']}:{i}"
    return findings


def agent2_review(repo_dir, finding, ctx=10):
    """Agent 2 on one finding. Returns {finding_id, decision, confidence_score, reason}."""
    lines = (Path(repo_dir) / finding["file_name"]).read_text(encoding="utf-8", errors="ignore").splitlines()
    line = finding["line_number"]
    s, e = max(1, line - ctx), min(len(lines), line + ctx)
    code_block = "\n".join(f"{'>>>' if i == line else '   '} {i:4d} | {lines[i - 1][:200]}" for i in range(s, e + 1))
    user = (f"FILE: {finding['file_name']}\n"
            f"FINDING: finding_id={finding['finding_id']} | {finding['cwe']} ({finding['vulnerability_class']}) at line {line}\n"
            f"AGENT 1 EVIDENCE: {finding['evidence']}\n\n```python\n{code_block}\n```\n\nReturn JSON only.")
    data = llm_json(MODEL_AGENT2, AGENT2_SYSTEM, user, LLM_OPTS_AGENT2)
    items = data.get("findings", []) if isinstance(data, dict) else []
    item = next((x for x in items if isinstance(x, dict)), None) if isinstance(items, list) else None
    if item is None:                                   # no usable answer: Agent 3 will keep Agent 1's result
        return None
    decision = "real" if str(item.get("decision", "")).lower().startswith("real") else "false_positive"
    try:
        conf = min(max(float(item.get("confidence_score", 0.5)), 0.0), 1.0)
    except (TypeError, ValueError):
        conf = 0.5
    return {"finding_id": finding["finding_id"], "decision": decision, "confidence_score": conf,
            "reason": str(item.get("reason", ""))[:300]}


def agent2_review_all(repo_dir, findings, progress=None):
    reviews = []
    for k, f in enumerate(findings, 1):
        r = agent2_review(repo_dir, f)
        if r:
            reviews.append(r)
        if progress:
            progress("agent2", k, len(findings))
    return reviews


def agent3_judge(a1_findings, a2_reviews):
    """Rule-based final decision for every Agent 1 finding."""
    reviews = {r["finding_id"]: r for r in a2_reviews}
    final = []
    for f in a1_findings:
        r, c1 = reviews.get(f["finding_id"]), f["confidence_score"]
        if r is None:
            decision, why = "real", "No Agent 2 review: Agent 1 result kept."
        elif r["decision"] == "real":
            decision, why = "real", "Agent 1 and Agent 2 agree it is real."
        elif c1 > r["confidence_score"]:
            decision, why = "real", f"Agents disagree: Agent 1 is more confident ({c1:.2f} > {r['confidence_score']:.2f})."
        else:
            decision, why = "false_positive", f"Agents disagree: Agent 2 is at least as confident ({r['confidence_score']:.2f} >= {c1:.2f})."
        final.append({**f, "decision": decision, "judge_reason": why,
                      "a2_decision": r["decision"] if r else None,
                      "a2_confidence": r["confidence_score"] if r else None,
                      "a2_reason": r["reason"] if r else None})
    return final


def scan_repo(repo_id, repo_dir, agents=3, progress=None, a1_findings=None):
    """agents=1: Agent 1 only. agents=3: Agent 1 -> Agent 2 -> Agent 3.
    progress(stage, done, total) is called while the agents work.
    Pass a1_findings to re-use an earlier Agent 1 run (Experiment 2 re-uses Experiment 1)."""
    t0 = time.time()
    findings = a1_findings if a1_findings is not None else agent1_scan_repo(repo_id, repo_dir, progress)
    out = {"repo_id": repo_id, "agent1_findings": findings, "agent2_reviews": [], "agent3_final": []}
    if agents == 1:
        out["predictions"] = findings
    else:
        out["agent2_reviews"] = agent2_review_all(repo_dir, findings, progress)
        out["agent3_final"] = agent3_judge(findings, out["agent2_reviews"])
        out["predictions"] = [f for f in out["agent3_final"] if f["decision"] == "real"]
    out["latency"] = time.time() - t0
    return out


def gt_cwes(gt):
    """acceptable_cwes of a ground-truth entry (falls back to primary_cwe)."""
    return set(gt.get("acceptable_norm") or []) or cwe_set(gt.get("acceptable_cwes")) or {norm_cwe(gt.get("primary_cwe"))}


def match_rfc(pred, gt, tol=10):
    """Same file + CWE in acceptable_cwes + line within +-10 of the entry range."""
    if str(pred["file_name"]).lstrip("./") != str(gt["file"]).lstrip("./"):
        return False
    if norm_cwe(pred["cwe"]) not in gt_cwes(gt):
        return False
    return gt["start_line"] - tol <= int(pred["line_number"]) <= gt["end_line"] + tol

def evaluate_repos(results):
    total = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for r in results:
        c = evaluate_rfc(r["predictions"], r["gt_entries"])
        for k in total:
            total[k] += c[k]
    return total
def evaluate_rfc(predictions, gt_entries):
    """Every ground-truth entry is consumed once.
    Matched real entry = TP | matched trap or no match = FP | real entry never matched = FN | trap never hit = TN."""
    used, tp, fp = set(), 0, 0
    for pred in predictions:
        hits = [i for i, g in enumerate(gt_entries) if i not in used and match_rfc(pred, g)]
        real = [i for i in hits if gt_entries[i]["is_vulnerable"]]
        if real:
            tp += 1
            used.add(real[0])
        else:
            fp += 1
            if hits:
                used.add(hits[0])
    fn = sum(1 for i, g in enumerate(gt_entries) if i not in used and g["is_vulnerable"])
    tn = sum(1 for i, g in enumerate(gt_entries) if i not in used and not g["is_vulnerable"])
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def compute_metrics(tp, fp, fn, tn):
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    total = tp + fp + fn + tn
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "accuracy": round((tp + tn) / total, 4) if total else 0,
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0}


def load_json(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def load_results():
    return load_json(EXP1_PATH, []), load_json(EXP2_PATH, [])


def build_tables(e1, e2):
    """Metrics, CWE distribution and per-repo tables for the repositories present in both experiments."""
    common = sorted({r["repo_id"] for r in e1} & {r["repo_id"] for r in e2})
    e1 = [r for r in e1 if r["repo_id"] in common]
    e2 = [r for r in e2 if r["repo_id"] in common]
    collect = lambda res: ([p for r in res for p in r["predictions"]], [g for r in res for g in r["gt_entries"]])
    p1, g1 = collect(e1)
    p2, g2 = collect(e2)
    # m1, m2 = compute_metrics(**evaluate_rfc(p1, g1)), compute_metrics(**evaluate_rfc(p2, g2))
    m1, m2 = compute_metrics(**evaluate_repos(e1)), compute_metrics(**evaluate_repos(e2))
    # lat1, lat2 = sum(r["latency"] for r in e1), sum(r["latency"] for r in e2)
    lat1 = sum(r["latency"] for r in e1)
    lat2 = lat1 + sum(r["latency"] for r in e2)

    rows = ["TP", "FP", "FN", "TN", "precision", "recall", "accuracy", "f1"]
    table1 = pd.DataFrame({"Exp1 (Agent 1)": [m1[k] for k in rows], "Exp2 (A1+A2+A3)": [m2[k] for k in rows]}, index=rows)
    table1["Delta"] = (table1["Exp2 (A1+A2+A3)"] - table1["Exp1 (Agent 1)"]).round(4)
    table1.loc["latency (s)"] = [round(lat1, 1), round(lat2, 1), round(lat2 - lat1, 1)]

    dist = pd.DataFrame({"Exp1": Counter(norm_cwe(p["cwe"]) for p in p1),
                         "Exp2": Counter(norm_cwe(p["cwe"]) for p in p2),
                         "Ground truth": Counter(norm_cwe(g["primary_cwe"]) for g in g1 if g["is_vulnerable"])})
    dist = dist.fillna(0).astype(int).sort_values("Ground truth", ascending=False)
    dist.insert(0, "Class", [CWE_CLASS.get(c, "") for c in dist.index])

    per_repo = []
    a, b = {r["repo_id"]: r for r in e1}, {r["repo_id"]: r for r in e2}
    for repo in common:
        x = compute_metrics(**evaluate_rfc(a[repo]["predictions"], a[repo]["gt_entries"]))
        y = compute_metrics(**evaluate_rfc(b[repo]["predictions"], b[repo]["gt_entries"]))
        per_repo.append({"Repo": repo, "Exp1 Precision": x["precision"], "Exp1 Recall": x["recall"], "Exp1 F1": x["f1"],
                         "Exp2 Precision": y["precision"], "Exp2 Recall": y["recall"], "Exp2 F1": y["f1"]})
    return {"common": common, "m1": m1, "m2": m2, "table1": table1, "dist": dist, "per_repo": pd.DataFrame(per_repo)}


def fig_metrics(T):
    with plt.rc_context(STYLE):
        fig, ax = plt.subplots(figsize=(9, 4.6))
        x, w = np.arange(len(METRIC_COLS)), 0.38
        for off, m, col, lab in [(-w / 2, T["m1"], COLORS["exp1"], "Exp1 (Agent 1)"), (w / 2, T["m2"], COLORS["exp2"], "Exp2 (A1+A2+A3)")]:
            vals = [m[c] for c in METRIC_COLS]
            bars = ax.bar(x + off, vals, w, label=lab, color=col, edgecolor="white", zorder=3)
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}", ha="center", fontsize=9, fontweight="bold", color="#333333")
        ax.set_xticks(x); ax.set_xticklabels(METRIC_LABELS); ax.set_ylim(0, 1.1)
        ax.set_ylabel("Score"); ax.set_title("Metrics Comparison"); ax.legend()
        fig.tight_layout()
    return fig


def fig_confusion(T):
    with plt.rc_context(STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(10, 4.4))
        for ax, m, title in [(axes[0], T["m1"], "(a) Exp1 (Agent 1)"), (axes[1], T["m2"], "(b) Exp2 (A1+A2+A3)")]:
            cells = [[("TP", m["TP"], COLORS["tp"]), ("FN", m["FN"], COLORS["fn"])],
                     [("FP", m["FP"], COLORS["fp"]), ("TN", m["TN"], COLORS["tn"])]]
            for i in range(2):
                for j in range(2):
                    lab, v, col = cells[i][j]
                    ax.add_patch(plt.Rectangle((j, i), 1, 1, facecolor=col, edgecolor="white", linewidth=3))
                    ax.text(j + .5, i + .55, str(v), ha="center", va="center", fontsize=22, fontweight="bold", color=text_color(col))
                    ax.text(j + .5, i + .28, lab, ha="center", va="center", fontsize=11, fontweight="bold", color=text_color(col))
            ax.set_xlim(0, 2); ax.set_ylim(0, 2); ax.invert_yaxis(); ax.grid(False)
            ax.set_xticks([.5, 1.5]); ax.set_xticklabels(["Predicted +", "Predicted -"])
            ax.set_yticks([.5, 1.5]); ax.set_yticklabels(["Actual +", "Actual -"]); ax.set_title(title)
        fig.tight_layout()
    return fig


def fig_distribution(T, per_panel=12):
    """Every CWE (ground truth + predictions), vertical bars, `per_panel` CWEs per row so nothing is cut."""
    d = T["dist"].sort_values(["Ground truth", "Exp1", "Exp2"], ascending=False)
    parts = [d.iloc[i:i + per_panel] for i in range(0, len(d), per_panel)]
    ymax = max(1, int(d[["Ground truth", "Exp1", "Exp2"]].to_numpy().max())) * 1.18
    series = [("Ground truth", "Ground truth", COLORS["gt"]), ("Exp1", "Exp1 (Agent 1)", COLORS["exp1"]),
              ("Exp2", "Exp2 (A1+A2+A3)", COLORS["exp2"])]
    with plt.rc_context(STYLE):
        fig, axes = plt.subplots(len(parts), 1, figsize=(14, 4.3 * len(parts)), squeeze=False)
        for ax, part in zip(axes[:, 0], parts):
            x, w = np.arange(len(part)), 0.26
            for off, (key, label, col) in zip((-w, 0, w), series):
                bars = ax.bar(x + off, part[key], w, label=label, color=col, edgecolor="white", zorder=3)
                for b, v in zip(bars, part[key]):
                    if v > 0:
                        ax.text(b.get_x() + b.get_width() / 2, v + ymax * 0.01, str(int(v)), ha="center", va="bottom", fontsize=8, color="#333333")
            ax.set_xticks(x)
            ax.set_xticklabels([f"{c}\n{k.replace('_', chr(10))}" for c, k in zip(part.index, part["Class"])], fontsize=8.5)
            ax.set_xlim(-0.6, per_panel - 0.4); ax.set_ylim(0, ymax); ax.set_ylabel("Findings")
        handles, labels = axes[0, 0].get_legend_handles_labels()
        fig.suptitle(f"CWE Distribution (all {len(d)} CWEs)", fontsize=13, fontweight="bold")
        fig.legend(handles, labels, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 0.965), frameon=False)
        fig.tight_layout(rect=[0, 0, 1, 0.94])
    return fig


def fig_stacked(T):
    with plt.rc_context(STYLE):
        fig, ax = plt.subplots(figsize=(8, 5.2))
        x, bottom = np.arange(2), np.zeros(2)
        for k in ["TP", "FP", "FN", "TN"]:
            vals = [T["m1"][k], T["m2"][k]]
            col = COLORS[k.lower()]
            bars = ax.bar(x, vals, 0.55, bottom=bottom, label=k, color=col, edgecolor="white", linewidth=2, zorder=3)
            for i, (b, v) in enumerate(zip(bars, vals)):
                if v > 0:
                    ax.text(b.get_x() + b.get_width() / 2, bottom[i] + v / 2, f"{k}\n{v}", ha="center", va="center", fontsize=9, fontweight="bold", color=text_color(col))
            bottom += np.array(vals)
        ax.set_xticks(x); ax.set_xticklabels(["Exp1 (Agent 1)", "Exp2 (A1+A2+A3)"], fontweight="bold")
        ax.set_ylabel("Count"); ax.set_title("Confusion Matrix Components"); ax.legend(ncol=4, loc="upper right")
        ax.set_ylim(0, max(bottom) * 1.15 if max(bottom) else 1)
        fig.tight_layout()
    return fig


def fig_per_repo(T):
    d = T["per_repo"]
    if len(d) < 2:
        return None
    with plt.rc_context(STYLE):
        fig, ax = plt.subplots(figsize=(11, 4.8))
        x = np.arange(len(d))
        ax.plot(x, d["Exp1 F1"], "o-", lw=2.5, ms=9, color=COLORS["exp1"], mfc="white", mew=2, label="Exp1 (Agent 1)")
        ax.plot(x, d["Exp2 F1"], "s--", lw=2.5, ms=9, color=COLORS["exp2"], label="Exp2 (A1+A2+A3)")
        ax.set_xticks(x); ax.set_xticklabels(d["Repo"], rotation=45, ha="right", fontsize=9)
        ax.set_ylim(0, 1); ax.set_ylabel("F1-score"); ax.set_title("F1-score per Repository"); ax.legend()
        fig.tight_layout()
    return fig


def fig_radar(T):
    with plt.rc_context(STYLE):
        fig, ax = plt.subplots(figsize=(6.4, 6.4), subplot_kw=dict(polar=True))
        ang = np.linspace(0, 2 * np.pi, len(METRIC_COLS), endpoint=False).tolist()
        ang += ang[:1]
        for m, col, mk, lab in [(T["m1"], COLORS["exp1"], "o-", "Exp1 (Agent 1)"), (T["m2"], COLORS["exp2"], "s-", "Exp2 (A1+A2+A3)")]:
            v = [m[c] for c in METRIC_COLS] + [m[METRIC_COLS[0]]]
            ax.plot(ang, v, mk, lw=2, color=col, label=lab)
            ax.fill(ang, v, alpha=.18, color=col)
        ax.set_xticks(ang[:-1]); ax.set_xticklabels(METRIC_LABELS)
        ax.set_ylim(0, 1); ax.set_title("Metrics Radar", pad=20); ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.1))
        fig.tight_layout()
    return fig


ALL_FIGURES = [('Metrics comparison', fig_metrics), ('Confusion matrices', fig_confusion), ('CWE distribution', fig_distribution), ('TP / FP / FN / TN', fig_stacked), ('F1 per repository', fig_per_repo), ('Metrics radar', fig_radar)]
