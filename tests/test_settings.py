
from synthetic_data.config.settings import (
    PROJECT_ROOT,
    EVENT_SCHEMA_PATH,
    EVENT_SCHEMA_VERSION,
    DATA_DIR,
    DOCS_DIR,
    KNOWLEDGE_DIR,
)


def test_project_directories_exist():
    assert PROJECT_ROOT.exists()
    assert DATA_DIR.exists()
    assert DOCS_DIR.exists()
    assert KNOWLEDGE_DIR.exists()


def test_event_schema_path_exists():
    assert EVENT_SCHEMA_PATH.exists()


def test_event_schema_version():
    assert EVENT_SCHEMA_VERSION == "1.0.0"
