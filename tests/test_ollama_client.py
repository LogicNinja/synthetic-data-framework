import json

from synthetic_data.agents.ollama_client import OllamaClient


def test_ollama_client_sends_json_schema_and_parses_structured_response(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"message": {"content": '{"label":"benign"}'}}).encode()

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = OllamaClient(model="test-model", host="http://localhost:11434")
    result = client.generate_json(
        system_prompt="system",
        user_prompt="user",
        schema_name="test_schema",
        schema={"type": "object", "properties": {"label": {"type": "string"}}},
    )
    assert result == {"label": "benign"}
    assert captured["payload"]["model"] == "test-model"
    assert captured["payload"]["format"]["type"] == "object"
    assert captured["payload"]["stream"] is False
