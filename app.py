"""Presentation-styled Streamlit UI for the synthetic telemetry framework."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import streamlit as st

from synthetic_data.config.settings import CONFIG_DIR
from synthetic_data.pipeline.runner import DEFAULT_RULE_DIR, load_rules, run_pipeline
from synthetic_data.scenarios.spec import SPEC_DIR, load_builtin_spec
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.four_layer import load_validation_criteria


PURPLE = "#16032f"
VIOLET = "#8135ed"
LILAC = "#c59cff"
MINT = "#afd58b"


def _inject_styles() -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Trispace:wght@400;500;600;700&display=swap');
        .stApp {{ background: radial-gradient(circle at 88% -8%, #4d2184 0, transparent 22%), {PURPLE}; color: white; }}
        html, body, [class*="css"], .stMarkdown, p, label, input, textarea {{ font-family: 'Trispace', monospace !important; }}
        h1, h2, h3 {{ color: white !important; letter-spacing: .04em; }}
        [data-testid="stSidebar"] {{ background: #210642; border-right: 1px solid #6231a1; }}
        [data-testid="stSidebar"] * {{ color: white !important; }}
        .hero {{ padding: 1.2rem 1.4rem; border: 1px solid #7540c6; border-radius: 18px; background: linear-gradient(135deg, #2a0955, #15012e); }}
        .hero h1 {{ margin: 0; font-size: 2.35rem; }}
        .hero p {{ margin: .4rem 0 0; color: #e9ddff; }}
        .step-card {{ min-height: 132px; padding: 1rem; border-radius: 16px; background: {VIOLET}; color: white; border: 1px solid #d4b5ff; }}
        .step-card h3 {{ margin: 0 0 .35rem; font-size: 1rem; }}
        .step-card p {{ color: white; font-size: .82rem; }}
        .light-card {{ padding: 1rem; border-radius: 14px; background: {LILAC}; color: #120025; }}
        .light-card * {{ color: #120025 !important; }}
        .stButton > button {{ font-family: 'Trispace', monospace; font-weight: 700; background: {LILAC}; color: #120025; border: 1px solid #f2eaff; border-radius: 9px; }}
        .stButton > button:hover {{ background: {MINT}; color: #0c2413; border-color: white; }}
        .stTabs [data-baseweb="tab"] {{ color: white; font-family: 'Trispace', monospace; font-weight: 700; }}
        .stTabs [aria-selected="true"] {{ color: {LILAC}; border-bottom-color: {LILAC}; }}
        [data-testid="stMetric"] {{ background: #2c0d59; padding: .7rem; border-radius: 12px; border: 1px solid #6636a5; }}
        [data-testid="stMetric"] * {{ color: white !important; }}
        .stAlert {{ color: #120025; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _ollama_available() -> bool:
    try:
        with urlopen("http://127.0.0.1:11434/api/tags", timeout=1.5) as response:
            return response.status == 200
    except (URLError, OSError):
        return False


@st.cache_data(show_spinner=False)
def _scenario_names() -> list[str]:
    return sorted(path.stem for path in SPEC_DIR.glob("*.json"))


def _run_validated_scenario(scenario_name: str) -> tuple[dict, list[dict]]:
    rules, failed_rules = load_rules(DEFAULT_RULE_DIR)
    report = run_pipeline(
        load_builtin_spec(scenario_name),
        rules,
        run_id=datetime.now(timezone.utc).strftime("ui-%Y%m%dT%H%M%SZ"),
        rules_failed_to_load=failed_rules,
        critic_accepted=True,
        validation_criteria=load_validation_criteria(CONFIG_DIR / "validation_criteria.json"),
    )
    events = read_jsonl(report.saved_path) if report.saved_path else []
    return asdict(report), [event.to_dict() for event in events]


def _dataset_files(kind: str) -> list[Path]:
    root = DatasetStore.DATASET_TYPES[kind]
    return sorted(root.glob("*.jsonl")) if root.is_dir() else []


def main() -> None:
    st.set_page_config(page_title="Synthetic Security Dataset Studio", page_icon="✦", layout="wide")
    _inject_styles()

    st.markdown(
        """
        <section class="hero">
          <h1>✦ SYNTHETIC DATASET STUDIO</h1>
          <p>Windows endpoint telemetry • Ground-truth simulation • Four-layer validation</p>
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.write("")

    columns = st.columns(4)
    steps = [
        ("01  PLAN", "Coverage gaps and hard cases"),
        ("02  SCENARIO", "Generate attack and benign look-alikes"),
        ("03  VALIDATE", "L1 provenance → L4 utility"),
        ("04  EXPORT", "Validated JSONL and triage data"),
    ]
    for column, (title, text) in zip(columns, steps):
        column.markdown(f'<div class="step-card"><h3>{title}</h3><p>{text}</p></div>', unsafe_allow_html=True)

    st.write("")
    simulator_tab, data_tab, agent_tab = st.tabs(["SIMULATOR + VALIDATION", "DATASET EXPLORER", "AGENT WORKFLOW"])

    with simulator_tab:
        st.subheader("Run a simulator-backed scenario")
        st.caption("This path works without Ollama. It emits traceable events and runs the deterministic L1–L3 checks.")
        left, right = st.columns([2, 1])
        with left:
            scenario_name = st.selectbox("Scenario specification", _scenario_names(), format_func=lambda name: name.replace("_", " ").title())
        with right:
            st.write("")
            run_clicked = st.button("RUN PIPELINE", use_container_width=True)

        if run_clicked:
            if not DEFAULT_RULE_DIR.is_dir():
                st.error("Sigma rules are unavailable. Run: git submodule update --init --recursive")
            else:
                with st.spinner("Simulating events and checking validation gates…"):
                    try:
                        report, events = _run_validated_scenario(scenario_name)
                    except (OSError, ValueError) as error:
                        st.exception(error)
                    else:
                        st.session_state["latest_report"] = report
                        st.session_state["latest_events"] = events

        report = st.session_state.get("latest_report")
        events = st.session_state.get("latest_events", [])
        if report:
            metrics = st.columns(4)
            metrics[0].metric("Events", report["event_count"])
            metrics[1].metric("Sigma rules", report["rules_loaded"])
            metrics[2].metric("L1 errors", len(report["provenance_errors"]))
            metrics[3].metric("L2 errors", len(report["schema_errors"]))
            validation = report.get("validation_report") or {}
            status = validation.get("decision", "incomplete").upper()
            st.markdown(f'<div class="light-card"><strong>VALIDATION STATUS: {status}</strong><br>Final promotion requires every applicable L1–L4 gate to pass.</div>', unsafe_allow_html=True)
            st.subheader("Generated event log")
            st.dataframe(events, use_container_width=True, hide_index=True)
            st.download_button("DOWNLOAD JSONL", "".join(json.dumps(item) + "\n" for item in events), f"{report['scenario_id']}.jsonl", "application/json")
            with st.expander("Full pipeline report"):
                st.json(report)

    with data_tab:
        st.subheader("Stored datasets")
        kind = st.radio("Dataset type", ["generated", "final", "reference"], horizontal=True)
        datasets = _dataset_files(kind)
        if not datasets:
            st.info(f"No {kind} JSONL datasets found yet.")
        else:
            selected = st.selectbox("Dataset", datasets, format_func=lambda path: path.name)
            event_rows = [event.to_dict() for event in read_jsonl(selected)]
            st.dataframe(event_rows, use_container_width=True, hide_index=True)
            st.download_button("DOWNLOAD SELECTED DATASET", selected.read_bytes(), selected.name, "application/json")

    with agent_tab:
        st.subheader("Planner → Scenario → Critic → Adversary")
        available = _ollama_available()
        status_text = "Ollama service detected" if available else "Ollama is not reachable at http://127.0.0.1:11434"
        (st.success if available else st.warning)(status_text)
        st.markdown(
            '<div class="light-card"><strong>Demo-safe mode</strong><br>Use the Simulator + Validation tab while a model is unavailable. The completed end-to-end backend remains available through <code>scripts/run_end_to_end.py</code> once Ollama and its model are ready.</div>',
            unsafe_allow_html=True,
        )
        st.code("python scripts/run_end_to_end.py configs/end_to_end_request.example.json --reference <reference.jsonl> --training <train.jsonl> --heldout <heldout.jsonl> --output-root data/final", language="powershell")
        st.caption("The full workflow requires reference, training, and held-out telemetry so it can enforce reference realism and held-out Defender utility.")


if __name__ == "__main__":
    main()
