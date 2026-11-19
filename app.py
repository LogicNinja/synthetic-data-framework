"""One-click UI for simulator-generated, validated telemetry datasets."""

from __future__ import annotations

from copy import deepcopy
import json
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from synthetic_data.agents.critic_agent import CriticAgent
from synthetic_data.agents.ollama_client import OllamaClient
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.config.settings import CONFIG_DIR, DATA_DIR, DOCS_DIR, KNOWLEDGE_DIR
from synthetic_data.pipeline.end_to_end import run_end_to_end
from synthetic_data.pipeline.runner import DEFAULT_RULE_DIR, load_rules, run_pipeline
from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever
from synthetic_data.scenarios.spec import load_builtin_spec
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.validation.four_layer import load_validation_criteria


PURPLE = "#16032f"
LILAC = "#c59cff"
MINT = "#afd58b"
MINIMUM_EVENT_COUNT = 30
REQUEST_PATH = CONFIG_DIR / "end_to_end_request.example.json"


def _inject_styles() -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Trispace:wght@400;500;600;700&display=swap');
        .stApp {{ background: radial-gradient(circle at 88% -8%, #4d2184 0, transparent 22%), {PURPLE}; color: white; }}
        html, body, [class*="css"], .stMarkdown, p, label {{ font-family: 'Trispace', monospace !important; }}
        h1, h2, h3 {{ color: white !important; letter-spacing: .04em; }}
        .hero {{ max-width: 920px; margin: 9vh auto 0; padding: 2.4rem; text-align: center; border: 1px solid #7540c6; border-radius: 22px; background: linear-gradient(135deg, #2a0955, #15012e); }}
        .hero h1 {{ margin: 0; font-size: 2.6rem; }}
        .hero p {{ margin: .8rem 0 0; color: #e9ddff; line-height: 1.7; }}
        .stButton > button, .stDownloadButton > button {{ min-height: 3.25rem; font-family: 'Trispace', monospace; font-weight: 700; background: {LILAC}; color: #120025; border: 1px solid #f2eaff; border-radius: 10px; }}
        .stButton > button:hover, .stDownloadButton > button:hover {{ background: {MINT}; color: #0c2413; border-color: white; }}
        .result {{ max-width: 920px; margin: 1.5rem auto; padding: 1.25rem; text-align: center; border-radius: 16px; background: {LILAC}; color: #120025; }}
        .result * {{ color: #120025 !important; }}
        .stAlert {{ color: #120025; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _simulator_events(
    *,
    spec_name: str,
    count: int,
    group: str,
    rules: list[dict],
    failed_rules: int,
    benign: bool = False,
) -> list:
    """Create scenario-disjoint, labeled events using only the simulator."""
    events = []
    for index in range(count):
        spec = deepcopy(load_builtin_spec(spec_name))
        scenario_id = f"UI_{group}_{index + 1:03d}"
        spec["scenario_id"] = scenario_id
        spec["hostname"] = f"WS-{group[:12]}-{index + 1:03d}"
        if benign:
            spec["label"] = "benign"
            spec["description"] = "Routine administrative process activity."
            for step in spec["steps"]:
                step["technique_labels"] = []
        report = run_pipeline(
            spec,
            rules,
            run_id=f"ui-{group.lower()}-{index + 1:03d}",
            rules_failed_to_load=failed_rules,
            critic_accepted=True,
            validation_criteria=load_validation_criteria(CONFIG_DIR / "validation_criteria.json"),
        )
        if not report.ok or not report.saved_path:
            raise RuntimeError("Simulator seed data did not pass its required checks.")
        events.extend(read_jsonl(report.saved_path))
    return events


def _build_simulator_evaluation_sets(rules: list[dict], failed_rules: int) -> tuple[list, list, list]:
    """Build independent simulator-only reference, training, and held-out sets."""
    reference = _simulator_events(
        spec_name="s3_cmd_powershell", count=15, group="REFERENCE", rules=rules, failed_rules=failed_rules, benign=True
    )
    training = [
        *_simulator_events(spec_name="s2_wmi_powershell", count=8, group="TRAIN_ATTACK", rules=rules, failed_rules=failed_rules),
        *_simulator_events(spec_name="s3_cmd_powershell", count=8, group="TRAIN_BENIGN", rules=rules, failed_rules=failed_rules, benign=True),
    ]
    heldout = [
        *_simulator_events(spec_name="s3_cmd_powershell", count=4, group="HELDOUT_ATTACK", rules=rules, failed_rules=failed_rules),
        *_simulator_events(spec_name="s3_cmd_powershell", count=4, group="HELDOUT_BENIGN", rules=rules, failed_rules=failed_rules, benign=True),
    ]
    return reference, training, heldout


def _generate_dataset() -> dict:
    """Use Ollama for scenario design and the simulator for every telemetry set."""
    if not DEFAULT_RULE_DIR.is_dir() or not REQUEST_PATH.is_file():
        raise FileNotFoundError("Required project resources are unavailable.")

    request = json.loads(REQUEST_PATH.read_text(encoding="utf-8"))
    rules, failed_rules = load_rules(DEFAULT_RULE_DIR)
    reference, training, heldout = _build_simulator_evaluation_sets(rules, failed_rules)

    # Bound each local-model call so an unavailable Ollama process cannot
    # hold the user-facing generation job indefinitely.
    client = OllamaClient(timeout_seconds=90)
    workflow = GenerationWorkflow(
        PlannerAgent(client),
        ScenarioAgent(
            client,
            retriever=LocalBM25Retriever([DOCS_DIR, KNOWLEDGE_DIR / "windows_refs", DEFAULT_RULE_DIR]),
        ),
        CriticAgent(client),
        max_attempts=1,
    )
    run_root = DATA_DIR / "final" / datetime.now(timezone.utc).strftime("ui-%Y%m%dT%H%M%SZ")
    result = run_end_to_end(
        request,
        workflow=workflow,
        reference_events=reference,
        training_events=training,
        heldout_events=heldout,
        output_root=run_root,
        rules=rules,
        rules_failed_to_load=failed_rules,
        validation_criteria=load_validation_criteria(CONFIG_DIR / "validation_criteria.json"),
        minimum_final_event_count=MINIMUM_EVENT_COUNT,
    )
    if not result.complete or not result.final_telemetry_path:
        raise RuntimeError("A dataset was not published because it did not meet the required checks.")
    return {"dataset_path": result.final_telemetry_path, "event_count": result.report["validated_event_count"]}


def _readable_dataset_bytes(dataset_path: str) -> bytes:
    events = [event.to_dict() for event in read_jsonl(dataset_path)]
    return (json.dumps(events, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    st.set_page_config(page_title="Synthetic Security Dataset Studio", page_icon="✦", layout="wide")
    _inject_styles()
    st.markdown(
        f"""
        <section class="hero">
          <h1>✦ SYNTHETIC DATASET STUDIO</h1>
          <p>Create a validated Windows security telemetry dataset with at least {MINIMUM_EVENT_COUNT} entries.</p>
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.write("")
    _, action, _ = st.columns([1, 2, 1])
    with action:
        generate_clicked = st.button("GENERATE DATASET", use_container_width=True, type="primary")

    if generate_clicked:
        with st.spinner("Creating your dataset…"):
            try:
                st.session_state["generated_dataset"] = _generate_dataset()
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
                st.error(f"We couldn't publish a dataset: {error}")

    dataset = st.session_state.get("generated_dataset")
    if dataset:
        path = Path(dataset["dataset_path"])
        if not path.is_file():
            st.error("Your dataset was created, but it is no longer available to download.")
            return
        st.markdown(
            f'<div class="result"><strong>YOUR {dataset["event_count"]}-ENTRY DATASET IS READY</strong><br>Download the dataset below.</div>',
            unsafe_allow_html=True,
        )
        _, download, _ = st.columns([1, 2, 1])
        with download:
            st.download_button("DOWNLOAD DATASET (.JSONL)", path.read_bytes(), path.name, "application/jsonl", use_container_width=True)
            st.download_button("DOWNLOAD READABLE COPY (.JSON)", _readable_dataset_bytes(str(path)), path.with_suffix(".json").name, "application/json", use_container_width=True)


if __name__ == "__main__":
    main()
