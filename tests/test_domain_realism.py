from synthetic_data.validation.domain_realism import validate_domain_realism


def make_process_event(
    event_id="e1",
    timestamp="2026-01-01T10:00:00Z",
    process_guid="pg-1",
    parent_process_guid=None,
):
    return {
        "event_id": event_id,
        "host_id": "host-1",
        "event_type": "process_creation",
        "timestamp": timestamp,
        "process": {
            "image": "C:\\Windows\\System32\\cmd.exe",
            "process_id": "100",
            "process_guid": process_guid,
            "parent_process_guid": parent_process_guid,
        },
    }


def make_file_event(
    event_id="e2",
    timestamp="2026-01-01T10:01:00Z",
    event_type="file_creation",
    activity="creation",
    file_path="C:\\Temp\\sample.txt",
    file_size=100,
):
    return {
        "event_id": event_id,
        "host_id": "host-1",
        "event_type": event_type,
        "timestamp": timestamp,
        "extensions": {
            "file_activity": {
                "activity": activity,
                "file_path": file_path,
                "file_size": file_size,
            }
        },
    }


def test_valid_process_and_file_events_pass():
    events = [
        make_process_event(),
        make_file_event(),
    ]

    report = validate_domain_realism(events)

    assert report.event_count == 2
    assert report.ok
    assert report.errors == []


def test_invalid_timestamp_is_reported():
    event = make_process_event(timestamp="not-a-timestamp")

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("timestamp must be" in error for error in report.errors)


def test_naive_timestamp_is_reported():
    event = make_process_event(timestamp="2026-01-01T10:00:00")

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("timestamp must be" in error for error in report.errors)


def test_out_of_order_timestamps_are_reported():
    events = [
        make_process_event(timestamp="2026-01-01T10:02:00Z"),
        make_file_event(timestamp="2026-01-01T10:01:00Z"),
    ]

    report = validate_domain_realism(events)

    assert not report.ok
    assert any("timestamp ordering is inconsistent" in error for error in report.errors)


def test_missing_process_object_is_reported():
    event = {
        "event_id": "e1",
        "host_id": "host-1",
        "event_type": "process_creation",
        "timestamp": "2026-01-01T10:00:00Z",
    }

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("requires a process object" in error for error in report.errors)


def test_missing_process_fields_are_reported():
    event = make_process_event()
    event["process"]["image"] = ""

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("process.image" in error for error in report.errors)


def test_duplicate_process_guids_are_reported():
    events = [
        make_process_event(event_id="e1", process_guid="same-guid"),
        make_process_event(
            event_id="e2",
            timestamp="2026-01-01T10:01:00Z",
            process_guid="same-guid",
        ),
    ]

    report = validate_domain_realism(events)

    assert not report.ok
    assert any("duplicate process_guid" in error for error in report.errors)


def test_unresolved_parent_process_guid_is_warning():
    event = make_process_event(parent_process_guid="missing-parent")

    report = validate_domain_realism([event])

    assert report.ok
    assert any("does not refer to a process" in warning for warning in report.warnings)


def test_file_event_missing_extensions_is_reported():
    event = {
        "event_id": "e1",
        "host_id": "host-1",
        "event_type": "file_creation",
        "timestamp": "2026-01-01T10:00:00Z",
    }

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("extensions must be an object" in error for error in report.errors)


def test_file_event_invalid_file_size_is_reported():
    event = make_file_event(file_size=-1)

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("file_size must be" in error for error in report.errors)


def test_file_event_activity_mismatch_is_reported():
    event = make_file_event(
        event_type="file_creation",
        activity="modification",
    )

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("activity should be" in error for error in report.errors)


def test_file_modification_event_passes():
    event = make_file_event(
        event_type="file_modification",
        activity="modification",
        file_size=250,
    )

    report = validate_domain_realism([event])

    assert report.ok
    assert report.errors == []
def test_missing_host_id_is_error():
    event = make_process_event()
    event["host_id"] = ""

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("host_id" in error for error in report.errors)


def test_non_string_host_id_is_error():
    event = make_process_event()
    event["host_id"] = 123

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("host_id" in error for error in report.errors)


def test_invalid_process_id_is_error():
    event = make_process_event()
    event["process"]["process_id"] = ""

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("process.process_id" in error for error in report.errors)


def test_boolean_process_id_is_error():
    event = make_process_event()
    event["process"]["process_id"] = True

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("process.process_id" in error for error in report.errors)


def test_missing_process_guid_is_error():
    event = make_process_event()
    event["process"]["process_guid"] = ""

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("process.process_guid" in error for error in report.errors)


def test_parent_process_can_be_outside_event_batch():
    child = make_process_event(parent_process_guid="external-parent-guid")

    report = validate_domain_realism([child])

    assert report.ok
    assert any(
        "does not refer to a process in this event batch" in warning
        for warning in report.warnings
    )


def test_parent_process_reference_on_same_host_resolves():
    parent = make_process_event(
        event_id="parent",
        process_guid="parent-guid",
    )
    child = make_process_event(
        event_id="child",
        timestamp="2026-01-01T10:01:00Z",
        process_guid="child-guid",
        parent_process_guid="parent-guid",
    )

    report = validate_domain_realism([parent, child])

    assert report.ok
    assert report.warnings == []


def test_process_cannot_be_its_own_parent():
    event = make_process_event(
        process_guid="same-guid",
        parent_process_guid="same-guid",
    )

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("cannot be its own parent" in error for error in report.errors)


def test_invalid_file_path_is_error():
    event = make_file_event(file_path="C:\\Temp\\bad\x00file.txt")

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("file_path" in error for error in report.errors)


def test_file_size_boolean_is_error():
    event = make_file_event(file_size=True)

    report = validate_domain_realism([event])

    assert not report.ok
    assert any("file_size" in error for error in report.errors)
