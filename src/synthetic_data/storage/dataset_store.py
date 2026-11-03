
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
        """Save events to a dataset location and return its path."""
        path = cls.get_dataset_path(dataset_type, filename)
        write_jsonl(events, path)
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
