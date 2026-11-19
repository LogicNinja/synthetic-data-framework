# Advanced generation integrations

## Planner, RAG, Scenario Agent, Critic

The executable workflow is `scripts/run_agent_workflow.py`. It calls a Planner Agent, retrieves local evidence with BM25 over project docs, Sysmon references, and selected process-creation Sigma rules, generates a scenario spec, then asks a Critic Agent for a structured accept/revise/reject decision. Invalid specs are rejected by deterministic code before the Critic model is called. Revisions are capped at three attempts by default.

Evidence excerpts are passed as data with source paths. Text found inside evidence is never treated as model instructions. The workflow report labels dataset validation as `not_run`; critic acceptance is not a substitute for provenance, structural, domain, or model-utility validation.

The workflow defaults to local Ollama (`llama3.2:latest`) and needs no API key. Use `--provider grok` to select the hosted xAI client:

```powershell
python scripts/run_agent_workflow.py "Simulate WMI starting PowerShell" --coverage-gap "WMI parent-child coverage"
```

Choose another local model with `--model llama3.2:latest` or `--model phi3:mini`.

## DSPy prompt optimization

Install the optional extra with `pip install -e ".[dspy]"`. `DSPyScenarioProgram` uses xAI's OpenAI-compatible chat endpoint and can bootstrap few-shot demonstrations from trusted request/spec pairs. Its metric requires valid scenario specs and scores label/action agreement. Supply trusted training examples and evaluate on a separate held-out set; do not optimize and report on the same examples.

```python
from synthetic_data.agents.dspy_scenario import DSPyScenarioProgram

program = DSPyScenarioProgram(api_key="...", model="grok-4.7")
program.compile_with_examples(trusted_training_examples)
```

## Multimodal input

The Grok Responses client accepts up to five local PNG, JPEG, WebP, or GIF references (5 MiB each). Planner, Scenario, and Critic can receive the same image references. Images are encoded as data URLs for the request. The prompts treat image text as untrusted evidence. The optional local quantized text backend does not support images.

```powershell
python scripts/run_agent_workflow.py "Create a scenario from this event-flow diagram" --image .\docs\flow.png
```

## Quantized local inference

`TransformersQuantizedClient` is an optional 4-bit/8-bit bitsandbytes backend for instruction-tuned causal models on compatible CUDA systems. Install `pip install -e ".[quantized-linux]"` on Linux with a matching CUDA-enabled PyTorch build. Windows support depends on the selected bitsandbytes and CUDA builds; the current Windows development environment has no Torch/CUDA stack, so local quantized inference is not runtime-verified here. The adapter validates returned objects against the requested JSON Schema.

RAG currently uses a local BM25 index rather than a vector database. This avoids embedding-model and database setup for the repository's current small reference corpus; a vector backend can be added if semantic-retrieval evaluation shows a measurable benefit.

## Defender and Adversary feedback

`DefenderModel` uses a TF-IDF/logistic-regression classifier. It uses scikit-learn when installed and a small deterministic native implementation otherwise. Install `pip install -e ".[defender]"` to select the scikit-learn backend. Features include process and event behavior; event IDs, timestamps, host/run/scenario IDs, technique labels, provenance, and existing detection results are excluded to reduce leakage. Labels are event-level: an event with action-level technique labels is malicious, otherwise benign. Train and held-out datasets must be separated by scenario or environment. The model rejects overlapping event and scenario IDs during evaluation.

Install the classifier with `pip install -e ".[defender]"`. `AdversaryAgent` receives held-out false-negative/false-positive summaries and returns bounded scenario requests linked to the failure event IDs. It receives an allowlisted feature summary rather than raw events or command lines.

`AdaptiveFeedbackCycle` implements one full round: train, evaluate held-out data, generate failure-linked proposals, run the Planner/Scenario/Critic workflow, pass critic-accepted specs through the existing L1-L3 pipeline, augment training only with pipeline-passing events, retrain, and reevaluate against the same held-out set. It reports the macro-F1 delta without promising an improvement.

Run with scenario/environment-separated JSONL files:

```powershell
pip install -e ".[defender]"
python scripts/run_adaptive_feedback.py data/train.jsonl data/heldout.jsonl
```

When failures are present, this command uses the selected local Ollama model by default for Adversary, Planner, Scenario, and Critic calls. Select Grok with `--provider grok` and configure its API key if desired. Generated samples enter the augmented training set only after critic acceptance and L1-L3 pipeline success. The held-out utility result is recorded after retraining.
