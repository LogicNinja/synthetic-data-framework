# Dataset diversity benchmark

Run a dataset-level diversity report against canonical event JSONL:

```powershell
.venv\Scripts\python.exe scripts\benchmark_dataset_diversity.py data\generated\dataset.jsonl --output data\reports\diversity.json
```

The report includes semantic exact event duplicates and their rate (IDs and
timestamps are excluded), near-duplicate event pairs, event-type distribution,
ATT&CK label coverage and frequency, unique scenario fingerprints, repeated
scenario fingerprints, near-duplicate scenario pairs, and scenario behavior
feature counts. `label_distribution` reports benign versus malicious classes;
`technique_coverage` and `technique_distribution` report ATT&CK labels.
Scenario grouping uses scenario ID plus run ID; fingerprints
use ordered event semantics. The configurable near-duplicate threshold uses
Jaccard similarity over event type, source, executable names, event code,
technique labels, and scenario event-type transitions.

These are descriptive dataset metrics, not pass/fail quality thresholds.
Repeated event patterns are reported separately from literal event-ID
collisions, which the dataset store already rejects. The Critic's existing
near-duplicate comparison remains useful during generation; this benchmark
measures the assembled dataset.
