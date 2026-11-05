"""Manage canonical datasets across project data locations."""

import os
import tempfile
from pathlib import Path
from typing import Iterable

from synthetic_data.config.settings import (
    GENERATED_DATA_DIR,
    FINAL_DATA_DIR,
    REFERENCE_DATA_DIR,
)
from synthetic_data.models.event import CanonicalEvent
from synthetic_data.serialization.event_serializer import (
    write_jsonl,
    read_jsonl,
)


class DatasetStore:
    """Manage canonical datasets across project data locations."""

    DATASET_TYPES = {
        "generated": GENERATED_DATA_DIR,
        "reference": REFERENCE_DATA_DIR,
        "final": FINAL_DATA_DIR,
    }

    @classmethod
    def get_dataset_path(
        cls,
        dataset_type: str,
        filename: str,
    ) -> Path:
        """Resolve a dataset path while preventing directory traversal."""
        if dataset_type not in cls.DATASET_TYPES:
            raise ValueError(
                f"Unknown dataset type: {dataset_type}. "
                f"Expected one of {list(cls.DATASET_TYPES)}."
            )

        if Path(filename).name != filename or filename in {".", ".."}:
            raise ValueError("Filename must not contain directory components.")

        if not filename.endswith(".jsonl"):
            raise ValueError("Dataset filename must end with '.jsonl'.")

        return cls.DATASET_TYPES[dataset_type] / filename

    @classmethod
    def save(
        cls,
        events: Iterable[CanonicalEvent],
        dataset_type: str,
        filename: str,
    ) -> Path:
        """Save events atomically, rejecting duplicate or conflicting IDs."""
        event_list = list(events)
        events_by_id: dict[str, dict] = {}

        # Validate event IDs and detect duplicates before writing anything.
        for event in event_list:
            event_id = event.event_id
            event_content = event.to_dict()

            if event_id in events_by_id:
                if events_by_id[event_id] == event_content:
                    raise ValueError(
                        f"Duplicate event_id {event_id!r}: "
                        "identical event content."
                    )

                raise ValueError(
                    f"Conflicting event_id {event_id!r}: "
                    "event content differs."
                )

            events_by_id[event_id] = event_content

        path = cls.get_dataset_path(dataset_type, filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        os.close(file_descriptor)

        temporary_path = Path(temporary_name)

        try:
            write_jsonl(event_list, temporary_path)
            os.replace(temporary_path, path)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise

        return path

    @classmethod
    def load(
        cls,
        dataset_type: str,
        filename: str,
    ) -> list[CanonicalEvent]:
        """Load events from a dataset location."""
        path = cls.get_dataset_path(dataset_type, filename)

        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        return read_jsonl(path)