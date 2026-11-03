
from pathlib import Path


# Project root: synthetic-data-framework/
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Main project directories
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"
KNOWLEDGE_DIR = PROJECT_ROOT / "knowledge"
CONFIG_DIR = PROJECT_ROOT / "configs"

# Source directories
SRC_DIR = PROJECT_ROOT / "src"
PACKAGE_DIR = SRC_DIR / "synthetic_data"

# Schema configuration
SCHEMA_DIR = PACKAGE_DIR / "schemas"
EVENT_SCHEMA_PATH = SCHEMA_DIR / "event.schema.json"
EVENT_SCHEMA_VERSION = "1.0.0"

# Dataset directories
GENERATED_DATA_DIR = DATA_DIR / "generated"
FINAL_DATA_DIR = DATA_DIR / "final"
REFERENCE_DATA_DIR = DATA_DIR / "reference"
REPORTS_DIR = DATA_DIR / "reports"

# Default output format
DEFAULT_DATA_FORMAT = "jsonl"

# Project settings
PROJECT_NAME = "synthetic-data-framework"
DEFAULT_ENCODING = "utf-8"

