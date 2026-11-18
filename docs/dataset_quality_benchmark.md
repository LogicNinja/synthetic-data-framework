# Dataset quality and Critic benchmark

## Reference fidelity

`benchmark_dataset_quality` compares synthetic and reference event distributions for:

- event type and source
- process image and parent image
- parent-child process relationships
- source channel and event code
- command-line shape (executable and flags only; raw argument values are not retained)
- event-type frequencies per run and ordered event-type bigrams/trigrams

Each feature reports total variation distance (0 means matching empirical
distributions; 1 means disjoint) and similarity (1 minus distance). The report
also includes the dataset diversity metrics. Results are descriptive and
sample-size dependent; they do not prove authenticity.

## Generator, Critic, and feedback cohorts

Create three JSONL cohorts with the same request cases, model, settings, and
generation budget:

- `generator`: raw generation without Critic filtering
- `critic`: generated samples after Critic acceptance filtering
- `feedback`: samples after Critic feedback and bounded regeneration

Use identical reference telemetry for each cohort. Attach aggregate workflow
metadata for each cohort to report acceptance rate, generation latency, and
Critic rubric scores. The Critic rates accuracy, diversity, realism,
consistency, and completeness from 1 to 5. For an unbiased quality-score
comparison, apply the same Critic rubric to all cohorts, including the raw
generator baseline as a post-hoc measurement only; it does not filter that
cohort. The report distinguishes Critic acceptance from whether filtering was
applied and how many samples were kept. It reports the supplied score mean and
leaves it null when no scores are supplied.

```powershell
.venv\Scripts\python.exe scripts\benchmark_dataset_quality.py `
  --reference data\reference\reference.jsonl `
  --variant generator=data\benchmark\generator.jsonl `
  --variant critic=data\benchmark\critic.jsonl `
  --variant feedback=data\benchmark\feedback.jsonl `
  --metadata generator=data\benchmark\generator-metadata.json `
  --metadata critic=data\benchmark\critic-metadata.json `
  --metadata feedback=data\benchmark\feedback-metadata.json `
  --output data\reports\quality-benchmark.json
```

The report gives each cohort's diversity and reference-fidelity metrics,
acceptance counts/rate, generation latency, numeric quality score when
provided, and deltas against the raw generator baseline. It does not claim
Critic improvement unless measured results show it. Token usage and monetary
cost remain excluded from this project scope; the API wrapper also does not
currently expose provider usage metadata.

To reduce selection bias, retain rejected candidates in the `critic` cohort's
metadata even though only accepted events are in its JSONL. Keep case IDs and
run settings with the report so cohorts can be checked for matched inputs.
