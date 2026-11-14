import os, re, sys, html, shutil, subprocess, time
from pathlib import Path
sys.path.insert(0, os.getcwd())
import matplotlib
matplotlib.use("Agg")
import pandas as pd
import requests
import streamlit as st
import core


st.set_page_config(page_title="Multi-Agent Vulnerability Detection", layout="wide")

tab1, tab2 = st.tabs([
    "📊  DATA EVALUATION DASHBOARD",
    "🔍  MULTI-AGENT DETECTION"
])


st.markdown("""
<style>
/* Make both tabs equal width */
.stTabs [data-baseweb="tab-list"] {
    display: flex !important;
    width: 100% !important;
    gap: 12px !important;
}

/* Style each tab button */
.stTabs button[data-baseweb="tab"] {
    flex: 1 1 50% !important;
    width: 50% !important;
    height: 70px !important;
    justify-content: center !important;
    border-radius: 12px !important;
    border: 2px solid #64748b !important;
    background: #1e293b !important;
    color: white !important;
    font-size: 17px !important;
    font-weight: bold !important;
}

/* Selected tab */
.stTabs button[data-baseweb="tab"][aria-selected="true"] {
    background: #2563eb !important;
    border-color: #60a5fa !important;
    color: white !important;
}

/* Hide default indicator */
.stTabs [data-baseweb="tab-highlight"] {
    display: none !important;
}
</style>
""", unsafe_allow_html=True)


with tab1:
    st.title("Data evaluation dashboard")
    st.caption("Match rule: same file + CWE in acceptable_cwes + line within ±10. Exp1 = Agent 1 only, Exp2 = Agents 1+2+3.")

    e1, e2 = core.load_results()

    if not e1 or not e2:
        st.warning(f"No results found in {core.RESULTS_DIR}. Run Experiment 1 and Experiment 2 first.")
    else:
        T = core.build_tables(e1, e2)
        st.success(f"Repositories compared: {len(T['common'])}")

        st.subheader("Table 1. Metrics comparison")
        st.dataframe(T["table1"])

        st.subheader("Table 2. CWE distribution (top 15)")
        st.dataframe(T["dist"].head(15))

        st.subheader("Table 3. Per-repository performance")
        st.dataframe(T["per_repo"], hide_index=True)

        st.subheader("Figures")
        cols = st.columns(2)
        for i, (name, fn) in enumerate(core.ALL_FIGURES):
            fig = fn(T)
            if fig is not None:
                cols[i % 2].pyplot(fig)

with tab2:
    st.title("Multi-agent vulnerability detection")

    def validate(url):
        m = re.match(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url.strip())
        if not m:
            return None, "Invalid URL. Expected: https://github.com/<owner>/<repo>"
        owner, repo = m.groups()
        try:
            r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", timeout=15)
        except Exception as e:
            return None, f"Could not reach GitHub: {e}"
        if r.status_code == 404:
            return None, "Repository not found or it is private. Only public repositories are allowed."
        if r.status_code != 200:
            return None, f"GitHub API returned status {r.status_code} (rate limit?). Try again later."
        if r.json().get("private"):
            return None, "The repository is private."
        return {"owner": owner, "repo": repo, "name": f"{owner}/{repo}"}, None

    def clone_py_files(info):
        """Shallow clone, keep only the .py files (nothing is executed)."""
        raw = Path("mvd_work/raw") / info["repo"]
        dest = Path("mvd_work/extracted") / info["repo"]
        for p in (raw, dest):
            shutil.rmtree(p, ignore_errors=True)
        raw.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1",
             f"https://github.com/{info['owner']}/{info['repo']}.git", str(raw)],
            check=True, capture_output=True, timeout=600,
            env=dict(os.environ, GIT_TERMINAL_PROMPT="0")
        )
        skip = {
            ".git", "venv", ".venv", "env", "node_modules",
            "site-packages", "__pycache__", "build", "dist"
        }
        n = 0
        for py in raw.rglob("*.py"):
            rel = py.relative_to(raw)
            if not any(p in skip for p in rel.parts) and not py.is_symlink():
                (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(py, dest / rel)
                n += 1
        shutil.rmtree(raw, ignore_errors=True)
        return dest, n

    url = st.text_input(
        "Public GitHub repository URL",
        placeholder="https://github.com/owner/repo"
    )

    mode = st.radio(
        "Agents",
        ["Agent 1 only", "All three agents (1 + 2 + 3)"],
        horizontal=True
    )
    agents = 1 if mode == "Agent 1 only" else 3

    if st.button("Start scan", type="primary"):
        info, error = validate(url)

        if error:
            st.error(error)

        else:
            with st.spinner(f"Cloning {info['name']} and extracting .py files..."):
                try:
                    repo_dir, n_files = clone_py_files(info)
                except Exception as e:
                    st.error(f"Clone failed: {e}")
                    repo_dir, n_files = None, 0

            if repo_dir is not None:
                if n_files == 0:
                    st.warning("No Python files found in this repository.")

                else:
                    bar, t0 = st.progress(0.0, text="Starting..."), time.time()
                    weight = {
                        "agent1": (0.0, 1.0 if agents == 1 else 0.6),
                        "agent2": (0.6, 0.4)
                    }

                    def progress(stage, done, total):
                        start, span = weight[stage]
                        bar.progress(
                            min(1.0, start + span * done / max(total, 1)),
                            text=f"{'Agent 1 scanning files' if stage == 'agent1' else 'Agent 2 reviewing findings'}: {done}/{total}  ({time.time() - t0:.0f}s)"
                        )

                    st.session_state["scan"] = {
                        "res": core.scan_repo(info["name"], repo_dir, agents, progress),
                        "dir": str(repo_dir),
                        "agents": agents,
                        "name": info["name"],
                        "files": n_files
                    }
                    bar.progress(1.0, text="Done")

    if "scan" not in st.session_state:
        st.info("Enter a public GitHub repository URL and click Start scan to begin.")
    else:
        scan = st.session_state["scan"]
        res = scan["res"]

        st.divider()
        st.subheader(f"Results: {scan['name']}")

        rows = (
            res["agent1_findings"]
            if scan["agents"] == 1
            else res["agent3_final"]
        )

        if scan["agents"] == 3 and not st.checkbox(
            "Show findings rejected by Agent 3",
            value=False
        ):
            rows = [r for r in rows if r["decision"] == "real"]

        c = st.columns(3)
        c[0].metric("Python files", scan["files"])
        c[1].metric("Agent 1 findings", len(res["agent1_findings"]))
        c[2].metric("Final vulnerabilities", len(res["predictions"]))

        if not rows:
            st.success("No vulnerabilities found.")

        else:
            rows = sorted(
                rows,
                key=lambda r: (
                    -r["confidence_score"],
                    r["file_name"],
                    r["line_number"]
                )
            )

            table = pd.DataFrame([
                {
                    "CWE": r["cwe"],
                    "Class": core.CWE_CLASS.get(r["cwe"], r["vulnerability_class"]),
                    "File": r["file_name"],
                    "Line": r["line_number"],
                    "Agent 1 confidence": round(r["confidence_score"], 2),
                    "Decision": r.get("decision", "reported by Agent 1")
                }
                for r in rows
            ])

            st.markdown("**Click a row to see the code around it and the reasons.**")

            try:
                event = st.dataframe(
                    table,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row"
                )
                chosen = event.selection.rows[0] if event.selection.rows else None

            except TypeError:
                chosen = st.selectbox(
                    "Finding",
                    range(len(table)),
                    format_func=lambda i: f"{table.CWE[i]}  {table.File[i]}:{table.Line[i]}"
                )

            st.download_button(
                "Download table (CSV)",
                table.to_csv(index=False).encode(),
                "findings.csv",
                "text/csv"
            )

            if chosen is not None:
                f = rows[chosen]

                st.divider()
                st.subheader(
                    f"{f['cwe']}  {core.CWE_CLASS.get(f['cwe'], f['vulnerability_class'])}"
                )
                st.caption(f"{f['file_name']}:{f['line_number']}")

                left, right = st.columns([3, 2])

                with left:
                    lines = (
                        Path(scan["dir"]) / f["file_name"]
                    ).read_text(
                        encoding="utf-8",
                        errors="ignore"
                    ).splitlines()

                    s = max(1, f["line_number"] - 10)
                    e = min(len(lines), f["line_number"] + 10)

                    html_rows = []

                    for i in range(s, e + 1):
                        hot = (
                            "background:rgba(230,57,70,.25);"
                            "border-left:4px solid #E63946;"
                            if i == f["line_number"]
                            else "border-left:4px solid transparent;"
                        )

                        html_rows.append(
                            f"<div style='{hot}padding:0 8px;white-space:pre;"
                            f"font-family:monospace;font-size:13px'>"
                            f"<span style='opacity:.5'>{i:4d}</span>  "
                            f"{html.escape(lines[i - 1])}</div>"
                        )

                    st.markdown("**Code around the finding (±10 lines)**")
                    st.markdown(
                        "<div style='overflow-x:auto;border:1px solid "
                        "rgba(128,128,128,.35);border-radius:6px;padding:6px 0'>"
                        + "".join(html_rows)
                        + "</div>",
                        unsafe_allow_html=True
                    )

                with right:
                    st.markdown("**Agent 1: reason**")
                    st.write(f["evidence"] or "-")
                    st.caption(f"confidence {f['confidence_score']:.2f}")

                    if scan["agents"] == 3:
                        st.markdown("**Agent 2: review**")

                        if f["a2_decision"]:
                            st.write(
                                f"{f['a2_decision']} "
                                f"({f['a2_confidence']:.2f}): {f['a2_reason']}"
                            )
                        else:
                            st.write("No review returned.")

                        st.markdown("**Agent 3: decision**")
                        st.write(f"{f['decision']}: {f['judge_reason']}")
