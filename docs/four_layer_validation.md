# Four-layer validation and acceptance criteria

`PipelineReport.ok` means the simulator passed its provenance/schema/domain checks and completed a JSONL round-trip. It does **not** mean the dataset passed the four-layer acceptance gate. `PipelineReport.validated` is true only when all four layers below pass.

| Layer | Checks | Acceptance rule |
|---|---|---|
| **L1 Internal provenance** | Each event is linked to a recorded action; event IDs and ground-truth labels match the action trace. | Zero provenance errors. |
| **L2 Structural and logical** | Canonical schema, event consistency checks, JSONL round-trip, selected Sigma rule loading and evaluation support. | Zero schema/logic errors; round-trip passes; all selected rules load; unsupported Sigma evaluations stay within configured maximum. |
| **L3 Domain and reference realism** | Domain consistency checks, accepted Critic review, reference comparison sample size and process-image distribution similarity. | Zero domain errors; Critic accepts; reference comparison evaluates at or above configured minimum sample size and similarity. |
| **L4 Model utility** | Held-out Defender macro-F1 and change versus the pre-augmentation baseline. | Macro-F1 meets its configured minimum and change meets the configured minimum delta. |

Warnings are retained in the report and do not fail a layer unless an explicit criterion says otherwise. Missing required evidence produces `not_run`; it blocks `validated`. Any failed check makes the final decision `rejected`. Four passing layers produce `validated`.

The initial thresholds are in `configs/validation_criteria.json`: 30 reference events, 0.50 reference similarity, zero unsupported Sigma evaluations, 0.70 held-out macro-F1, and no regression from baseline. These are starting engineering thresholds, not research-calibrated constants.

The reference similarity and unsupported Sigma counts are reported as warnings, not hard data-validity failures. The current reference comparator measures only process-image frequencies, and the available LMD reference is normal-only; mixing malicious events into it makes the score unsuitable as a release gate. Unsupported Sigma modifiers indicate incomplete detection-rule coverage, not malformed simulator output. L1 provenance, L2 schema/event logic and round-trip checks, L3 domain checks plus Critic review, and L4 held-out utility remain gates. Calibrate a class-matched reference benchmark and rule-coverage policy before using those measurements as hard gates for research claims.

## Consolidated report

`build_four_layer_report` in `src/synthetic_data/validation/four_layer.py` combines validator results, Critic acceptance, reference realism, and utility metrics into one JSON-serializable report. `run_pipeline` stores that report in the dataset manifest. Requests to save to the `final` dataset are staged under `generated`; promotion to `final` occurs only when the four-layer report is validated.

The CLI writes a consolidated report under `data/reports/` by default:

```powershell
python -m synthetic_data.pipeline.runner s2_wmi_powershell --reference data/reference/lmd2022_normal_process_creation.jsonl
```

Without a Critic decision and a held-out utility report, the CLI correctly reports `incomplete`. `AdaptiveFeedbackCycle` supplies the Critic result and held-out utility stage during a feedback round. Reference realism remains descriptive and currently compares process-image distributions only; human expert review is still a separate quality measure.
