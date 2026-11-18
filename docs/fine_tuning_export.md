# Telemetry to fine-tuning JSONL

The export format is chat fine-tuning JSONL. Each row has exactly one `messages`
array with system, user, and assistant messages, matching the schema in
`src/synthetic_data/schemas/fine_tuning_chat.schema.json`.

The converter emits five task types: event classification, log interpretation,
ATT&CK technique identification, parent-child process analysis, and threat
explanation. Answers are constructed from canonical event fields and the
simulator's ground-truth labels. Ground-truth labels and event identities are
kept out of the user telemetry input; labels appear only in expected responses.
Scenario event sequences provide context when multiple events share a scenario.

The exporter requires a `.meta.json` manifest with an explicit four-layer
`validated` decision, all L1-L4 statuses passed, a matching SHA-256 checksum,
and the expected event count. It refuses unvalidated or modified source files.
Converted examples are checked against the chat schema, non-empty content,
classification-label consistency, exact duplicate detection, and scenario
split isolation. Expected responses are deterministic templates; this avoids
invented facts, but it does not replace expert review of telemetry realism or
ATT&CK labels. No separate LLM Critic review is run by default.

Splits are assigned by scenario ID (falling back to run ID), so examples from
the same scenario cannot cross train, validation, and test. At least three
distinct scenario groups are required. Default ratios are 80/10/10 and the
seed is recorded for reproducibility.

```powershell
.venv\Scripts\python.exe scripts\export_finetuning_dataset.py `
  data\final\validated_events.jsonl `
  --dataset-root data\final `
  --seed 17
```

The command writes:

```text
data/final/
├── telemetry/synthetic_events.jsonl
├── fine_tuning/{train,validation,test}.jsonl
└── reports/{quality_report,dataset_metadata}.json
```

The command will not create this output from a draft or incomplete four-layer
dataset. Add more validated scenarios if fewer than three independent scenario
groups are available.
