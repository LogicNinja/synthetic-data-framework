import pytest

from synthetic_data.defender.model import (
    DefenderModel,
    event_feature_text,
    event_label_from_ground_truth,
)


def event(event_id, label, image, command_line="secret argument"):
    return {
        "event_id": event_id,
        "event_source": "windows_process_creation",
        "event_type": "process_start",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host_id": "WS-USER-SPECIFIC",
        "run_id": "run-unique",
        "origin": "synthetic",
        "ground_truth_labels": ["T1059.001"] if label == "malicious" else [],
        "detection_results": [{"rule_id": "leak", "matched": True}],
        "provenance": {"scenario_id": f"S-{event_id}"},
        "process": {
            "image": image,
            "command_line": command_line,
            "parent_image": "C:\\Windows\\explorer.exe",
        },
    }


class FakeEstimator:
    classes_ = ["benign", "malicious"]

    def fit(self, features, labels):
        self.training_features = features
        self.training_labels = labels
        return self

    def predict_proba(self, features):
        return [[0.9, 0.1] if "WmiPrvSE" in text else [0.1, 0.9] for text in features]


def test_event_features_exclude_truth_identity_and_detector_fields():
    sample = event("e1", "malicious", "C:\\Windows\\System32\\WmiPrvSE.exe")
    features = event_feature_text(sample)
    assert "WmiPrvSE" in features
    assert "T1059.001" not in features
    assert "WS-USER-SPECIFIC" not in features
    assert "run-unique" not in features
    assert "leak" not in features
    assert event_label_from_ground_truth(sample) == "malicious"


def test_defender_reports_false_negative_and_false_positive_and_blocks_leakage():
    train = [
        event("train-1", "malicious", "C:\\Windows\\System32\\powershell.exe"),
        event("train-2", "benign", "C:\\Windows\\System32\\notepad.exe"),
    ]
    heldout = [
        event("test-fn", "malicious", "C:\\Windows\\System32\\WmiPrvSE.exe"),
        event("test-fp", "benign", "C:\\Windows\\System32\\notepad.exe"),
    ]
    model = DefenderModel(estimator=FakeEstimator()).fit(train)
    report = model.evaluate(heldout)

    assert report["confusion_matrix"] == {
        "true_positive": 0,
        "false_positive": 1,
        "true_negative": 0,
        "false_negative": 1,
    }
    assert report["false_negatives"][0]["event_id"] == "test-fn"
    assert report["false_positives"][0]["event_id"] == "test-fp"
    assert "command_line" not in report["false_negatives"][0]["feature_summary"]
    with pytest.raises(ValueError, match="overlap training IDs"):
        model.evaluate([train[0]])
    repeated_scenario = event("test-other-event", "benign", "notepad.exe")
    repeated_scenario["provenance"]["scenario_id"] = train[0]["provenance"]["scenario_id"]
    with pytest.raises(ValueError, match="overlap training scenarios"):
        model.evaluate([repeated_scenario])


def test_default_defender_trains_and_scores_heldout_data():
    train = [
        event("train-m1", "malicious", "powershell.exe", "powershell.exe -encodedcommand"),
        event("train-m2", "malicious", "cmd.exe", "cmd.exe /c powershell.exe -nop"),
        event("train-b1", "benign", "notepad.exe", "notepad.exe"),
        event("train-b2", "benign", "calc.exe", "calc.exe"),
    ]
    heldout = [
        event("test-m1", "malicious", "powershell.exe", "powershell.exe -encodedcommand"),
        event("test-b1", "benign", "notepad.exe", "notepad.exe"),
    ]
    model = DefenderModel()
    model.fit(train)
    report = model.evaluate(heldout)
    assert report["sample_count"] == 2
    assert report["macro_f1"] == 1.0
    assert report["model_backend"] == model.backend
    assert model.backend in {
        "native-tfidf-logistic-regression",
        "scikit-learn-tfidf-logistic-regression",
    }
