# Scenario prompt baselines

This protocol compares two fixed prompt variants for the same scenario-generation cases:

- **B0 direct:** `prompts/baselines/b0_direct.txt`, a concise instruction-only prompt.
- **B1 few-shot:** `prompts/baselines/b1_few_shot.txt`, the same task framing plus one attack and one benign formatting example.

The cases and caller-supplied constraints are versioned in `configs/baseline_cases.json`. Each attempt is evaluated against the scenario JSON Schema, the existing semantic `validate_spec` checks, and caller constraint values. The report records validity rate, individual errors, generated specifications, model name, and mean latency. Repeat runs with the same cases and model to estimate variability; record the model identifier and keep reports with experiment artifacts.

Run from the repository root after configuring `XAI_API_KEY` (or `GROK_API_KEY`):

```powershell
$env:PYTHONPATH = "src"
python scripts/evaluate_prompt_baselines.py --repetitions 3
```

To use the repository virtual environment on Windows:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe scripts/evaluate_prompt_baselines.py --repetitions 3
```

The script writes a JSON report under `data/reports/`, which is ignored by Git. This initial baseline measures format and scenario validity plus latency. It does not establish realism, ATT&CK-label correctness, model utility, token cost, or critic effectiveness. Do not treat LLM-proposed technique labels as independently verified ground truth.
