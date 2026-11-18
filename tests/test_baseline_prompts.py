from synthetic_data.evaluation.baseline_prompts import evaluate_prompt_baselines


SCHEMA = {
    "type": "object",
    "required": ["scenario_id", "hostname", "username", "label", "steps"],
    "properties": {
        "scenario_id": {"type": "string"},
        "hostname": {"type": "string"},
        "username": {"type": "string"},
        "label": {"enum": ["malicious", "benign"]},
        "steps": {"type": "array"},
    },
}

CASE = {
    "case_id": "benign_process",
    "request": "Simulate a benign process.",
    "constraints": {
        "scenario_id": "BASELINE_TEST",
        "hostname": "WS-TEST-001",
        "username": "test_user",
        "label": "benign",
    },
}

VALID_SPEC = {
    "scenario_id": "BASELINE_TEST",
    "hostname": "WS-TEST-001",
    "username": "test_user",
    "label": "benign",
    "steps": [
        {
            "action": "start_process",
            "process_id": "100",
            "image": "C:\\Windows\\System32\\notepad.exe",
            "command_line": "notepad.exe",
            "original_file_name": "NOTEPAD.EXE",
            "timestamp": "2026-01-01T10:00:00+00:00",
        }
    ],
}


def test_prompt_evaluation_reports_validity_and_latency():
    report = evaluate_prompt_baselines(
        cases=[CASE],
        prompts={"b0": "system"},
        schema=SCHEMA,
        generate_json=lambda **_: VALID_SPEC,
        model="fake-model",
    )

    assert report["summary"]["b0"]["attempts"] == 1
    assert report["summary"]["b0"]["valid_attempts"] == 1
    assert report["summary"]["b0"]["valid_rate"] == 1.0
    assert len(report["summary"]["b0"]["prompt_sha256"]) == 64
    assert report["results"][0]["spec"] == VALID_SPEC


def test_prompt_evaluation_rejects_constraint_mismatch():
    wrong = {**VALID_SPEC, "hostname": "OTHER-HOST"}
    report = evaluate_prompt_baselines(
        cases=[CASE],
        prompts={"b0": "system"},
        schema=SCHEMA,
        generate_json=lambda **_: wrong,
        model="fake-model",
    )

    assert report["summary"]["b0"]["valid_rate"] == 0.0
    assert "constraint: hostname did not match caller value" in report["results"][0]["errors"]


def test_prompt_evaluation_records_generation_errors():
    def fail(**_):
        raise RuntimeError("offline")

    report = evaluate_prompt_baselines(
        cases=[CASE],
        prompts={"b0": "system"},
        schema=SCHEMA,
        generate_json=fail,
        model="fake-model",
    )

    assert report["summary"]["b0"]["valid_rate"] == 0.0
    assert report["results"][0]["errors"][0].startswith("generation: RuntimeError")
