# End-to-end backend workflow (no UI)

`scripts/run_end_to_end.py` connects structured input through the final fine-tuning
files. The request contract is `configs/end_to_end_request.schema.json`; an
example is in `configs/end_to_end_request.example.json`.

The runner requires a reference JSONL file, Defender training JSONL containing
both benign and malicious events, and a scenario-disjoint held-out JSONL file.
Those inputs are required evidence for reference realism and L4 held-out model
utility. It does not invent these datasets or call an incomplete validation a
pass. The structured request requires at least three scenarios and both labels
so scenario-grouped train/validation/test splits can be created.

```powershell
.venv\Scripts\python.exe scripts\run_end_to_end.py `
  configs\end_to_end_request.example.json `
  --reference data\reference\lmd2022_normal_process_creation.jsonl `
  --training data\training\defender_train.jsonl `
  --heldout data\training\defender_heldout.jsonl `
  --output-root data\final
```

The runner first evaluates the Defender on held-out events. If it finds false
positives or false negatives, the Adversary proposes up to three targeted
scenarios, which re-enter the same Planner, Scenario, Critic, Simulator, and
validation path. For each user and adversarial scenario, the runner plans,
generates, and critiques with a bounded retry count, enforces caller
constraints, simulates only accepted specifications, and checks emitted event
types and L1-L2 pipeline results. It then evaluates reference realism across
the combined candidate set, measures Defender performance before and after
augmenting training, and builds the consolidated L1-L4 report. Rejected drafts
and failed candidates remain in the run report and are excluded from accepted
telemetry.

Only a four-layer validated candidate dataset is written as
`telemetry/synthetic_events.jsonl`. The same run then converts it into
`fine_tuning/train.jsonl`, `validation.jsonl`, and `test.jsonl`, plus dataset
metadata and diversity, reference-quality, and validation reports. If a gate
fails, the run report explains why and no fine-tuning-ready final dataset is
published. Critic evaluation is over scenario specifications; deterministic
telemetry validators and ground-truth-derived targets validate the emitted
events and training pairs. Human review remains an explicit manual step.

The runner uses local Ollama by default and does not need an API key. Start
Ollama and ensure the default `llama3.2:latest` model is installed, or choose another
local model with `--model`. Use `--provider grok` only when you want the xAI
hosted API. The result still depends on the supplied reference, training, and
held-out datasets and configured acceptance thresholds. A process-creation
reference comparison needs at least the
configured minimum sample size (30 by default); too few generated events will
leave L3 incomplete and block final promotion. The example therefore requests
20 scenarios. Review the generated report before treating a successful run as
research evidence.
