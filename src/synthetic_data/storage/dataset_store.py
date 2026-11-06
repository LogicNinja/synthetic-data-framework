"""Manage canonical datasets across project data locations."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from synthetic_data.config.settings import (
    GENERATED_DATA_DIR,
    FINAL_DATA_DIR,
    REFERENCE_DATA_DIR,
)
from synthetic_data.models.event import CanonicalEvent
from synthetic_data.serialization.event_serializer import (
    read_jsonl,
    write_jsonl,
)


class DatasetStore:
    """Manage canonical datasets and their metadata manifests."""

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

    @staticmethod
    def _get_manifest_path(dataset_path: Path) -> Path:
        """Return the sidecar metadata path for a dataset."""
        return dataset_path.with_suffix(dataset_path.suffix + ".meta.json")

    @staticmethod
    def _write_json_atomically(data: dict[str, Any], destination: Path) -> None:
        """Write JSON to a temporary file and atomically replace the destination."""
        destination.parent.mkdir(parents=True, exist_ok=True)

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(file_descriptor)
        temporary_path = Path(temporary_name)

        try:
            with temporary_path.open("w", encoding="utf-8", newline="\n") as file:
                json.dump(data, file, indent=2, sort_keys=True, ensure_ascii=False)
                file.write("\n")

            os.replace(temporary_path, destination)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise

    @classmethod
    def save(
        cls,
        events: Iterable[CanonicalEvent],
        dataset_type: str,
        filename: str,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """
        Save events and a metadata manifest.

        Optional caller metadata can include scenario details, labels, or
        generation configuration. It is stored under the manifest's
        ``metadata`` key.
        """
        path = cls.get_dataset_path(dataset_type, filename)
        manifest_path = cls._get_manifest_path(path)
        event_list = list(events)

        # Reject duplicate IDs before writing anything.
        events_by_id: dict[str, dict[str, Any]] = {}

        for event in event_list:
            event_content = event.to_dict()
            event_id = event.event_id

            if event_id in events_by_id:
                previous_content = events_by_id[event_id]

                if previous_content == event_content:
                    raise ValueError(
                        f"Duplicate event_id '{event_id}' with identical event content."
                    )

                raise ValueError(
                    f"Conflicting event_id '{event_id}': event content differs."
                )

            events_by_id[event_id] = event_content

        path.parent.mkdir(parents=True, exist_ok=True)

        # Stage the JSONL dataset before replacing the existing file.
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        os.close(file_descriptor)
        temporary_dataset_path = Path(temporary_name)

        try:
            write_jsonl(event_list, temporary_dataset_path)

            dataset_bytes = temporary_dataset_path.read_bytes()
            checksum = hashlib.sha256(dataset_bytes).hexdigest()

            manifest = {
                "dataset_filename": path.name,
                "event_count": len(event_list),
                "run_ids": sorted({event.run_id for event in event_list}),
                "schema_versions": sorted(
                    {event.schema_version for event in event_list}
                ),
                "sha256": checksum,
                "metadata": metadata or {},
            }

            # Write the manifest to its own temporary file.
            file_descriptor, manifest_temp_name = tempfile.mkstemp(
                prefix=f".{manifest_path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            os.close(file_descriptor)
            temporary_manifest_path = Path(manifest_temp_name)

            try:
                with temporary_manifest_path.open(
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as file:
                    json.dump(
                        manifest,
                        file,
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                    file.write("\n")

                # Replace both staged files. Each replacement is atomic.
                os.replace(temporary_dataset_path, path)
                os.replace(temporary_manifest_path, manifest_path)

            except BaseException:
                temporary_manifest_path.unlink(missing_ok=True)
                raise

        except BaseException:
            temporary_dataset_path.unlink(missing_ok=True)
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

    @classmethod
    def load_metadata(
        cls,
        dataset_type: str,
        filename: str,
    ) -> dict[str, Any]:
        """Load the metadata manifest for a dataset."""
        path = cls.get_dataset_path(dataset_type, filename)
        manifest_path = cls._get_manifest_path(path)

        if not manifest_path.exists():
            raise FileNotFoundError(f"Dataset metadata not found: {manifest_path}")

        with manifest_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    @classmethod
    def verify_metadata(
        cls,
        dataset_type: str,
        filename: str,
    ) -> bool:
        """Verify the dataset bytes against the checksum in its manifest."""
        path = cls.get_dataset_path(dataset_type, filename)

        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        manifest = cls.load_metadata(dataset_type, filename)
        actual_checksum = hashlib.sha256(path.read_bytes()).hexdigest()

        return actual_checksum == manifest.get("sha256")
