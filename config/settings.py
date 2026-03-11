import json
from pathlib import Path


def load_config() -> dict:
    config_path = Path(__file__).resolve().parent / "config.json"

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)
