# RMAVD: A Repository-Level Multi-Agent Framework for Software Vulnerability Detection

RMAVD detects vulnerabilities in Python repositories with three agents. 

## Agents

| Agent | Role | Model |
|---|---|---|
| Agent 1: Vulnerability Detector | Scans every `.py` file in 40-line chunks (3 context lines) and reports CWE, class, line, snippet, evidence, and confidence as JSON | `qwen2.5-coder:14b` via Ollama |
| Agent 2: False Positive Reducer | Reviews one finding at a time with ±10 lines of code context, using SOURCE, SINK, NO DEFENSE, and CWE tests | `deepseek-coder-v2:16b` via Ollama |
| Agent 3: Judge | Rule-based decision, no LLM | none |

## Dataset

[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark): 26 intentionally vulnerable Python repositories.

**Matching rule:** a finding matches an entry when the file is the same, the CWE is among the acceptable CWEs of the entry, and the line is within ±10 lines. Each entry is matched only once.

## Repository contents

| File | Description |
|---|---|
| `RMAVD_Framework.ipynb` | The three agents, Exp1 and Exp2, and the metrics |
| `RMAVD_analysis_local.ipynb` | Extended analysis: F2/F3, bootstrap over repositories, error analysis, Judge threshold sensitivity, split-half validation |
| Streamlit app | Page 1: evaluation dashboard. Page 2: scanner for public GitHub repositories |

## Results (25 test repositories)

<table>
  <tr>
    <td><img src="figs/metrics_comparison.png" alt="Metrics comparison"><br><sub>(a) Evaluation metrics</sub></td>
    <td><img src="figs/confusion_matrix.png" alt="Confusion matrices"><br><sub>(b) Confusion matrices</sub></td>
  </tr>
</table>

## Application

<table>
  <tr>
    <td><img src="figs/screenshot1.png" alt="Scan progress, Agent 1 only"><br><sub>(a) Scan progress, Agent 1 only</sub></td>
    <td><img src="figs/screenshot2.png" alt="Findings table of Agent 1"><br><sub>(b) Findings table of Agent 1</sub></td>
  </tr>
  <tr>
    <td><img src="figs/screenshot3.png" alt="Finding details, Agent 1"><br><sub>(c) Finding details with the reason of Agent 1</sub></td>
    <td><img src="figs/screenshot4.png" alt="Scan progress, three agents"><br><sub>(d) Scan progress, all three agents</sub></td>
  </tr>
  <tr>
    <td><img src="figs/screenshot5.png" alt="Findings table after review"><br><sub>(e) Findings table after Agent 2 and Agent 3</sub></td>
    <td><img src="figs/screenshot6.png" alt="Finding details, three agents"><br><sub>(f) Finding details with the decisions of the three agents</sub></td>
  </tr>
</table>

## Citation

Aljabri, A. and Aljuhani, A., "RMAVD: A Repository-Level Multi-Agent Framework for Software Vulnerability Detection," Taibah University.
