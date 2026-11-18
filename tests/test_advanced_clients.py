import base64
import json

import pytest

from synthetic_data.agents.client import GrokConfig, GrokResponsesClient
from synthetic_data.agents.dspy_scenario import scenario_quality_metric
from synthetic_data.agents.quantized_client import parse_json_object


def test_grok_client_encodes_local_image_as_responses_input(monkeypatch, tmp_path):
    image = tmp_path / "reference.png"
    image_bytes = b"test-image-bytes"
    image.write_bytes(image_bytes)
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "output": [{
                    "type": "message",
                    "content": [{"type": "output_text", "text": "{}"}],
                }]
            }).encode()

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = GrokResponsesClient(
        GrokConfig(api_key="test", model="fake", base_url="https://example.test")
    )
    client.generate_json(
        system_prompt="system",
        user_prompt="read reference",
        schema_name="test",
        schema={"type": "object"},
        image_paths=[image],
    )
    content = captured["payload"]["input"][1]["content"]
    assert content[0]["type"] == "input_text"
    assert content[1]["type"] == "input_image"
    assert content[1]["image_url"].endswith(base64.b64encode(image_bytes).decode())


def test_grok_client_enforces_image_count_limit(tmp_path):
    client = GrokResponsesClient(
        GrokConfig(api_key="test", model="fake", base_url="https://example.test")
    )
    image = tmp_path / "reference.png"
    image.write_bytes(b"x")
    with pytest.raises(ValueError, match="At most"):
        client.generate_json(
            system_prompt="system",
            user_prompt="text",
            schema_name="test",
            schema={},
            image_paths=[image] * 6,
        )


def test_local_quantized_client_json_extraction():
    assert parse_json_object('prefix\n{"value": 3}\nsuffix') == {"value": 3}
    with pytest.raises(ValueError, match="no valid JSON"):
        parse_json_object("not json")


def test_dspy_metric_requires_valid_spec_and_rewards_matching_actions():
    gold = {
        "scenario_id": "GOLD",
        "hostname": "WS-1",
        "username": "user",
        "label": "benign",
        "steps": [{
            "action": "start_process",
            "process_id": "1",
            "image": "C:\\Windows\\System32\\notepad.exe",
            "command_line": "notepad.exe",
            "original_file_name": "NOTEPAD.EXE",
            "timestamp": "2026-01-01T00:00:00+00:00",
        }],
    }
    prediction = type("Prediction", (), {"scenario_json": json.dumps(gold)})()
    example = type("Example", (), {"scenario_json": json.dumps(gold)})()
    assert scenario_quality_metric(example, prediction) == 1.0

