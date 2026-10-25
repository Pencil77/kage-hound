"""
Configuration manager for KageHound.
Loads settings from TOML configuration files and environment variables.
"""

import os
from pathlib import Path

import tomllib
from pydantic import BaseModel, Field

DEFAULT_IGNORE_PATHS = [
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".tox",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "kage_hound.egg-info",
    ".egg-info",
    ".cache",
    ".gemini",
    ".local",
    ".infisical",
    ".ssh",
]


class KageHoundConfig(BaseModel):
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    intelx_api_key: str | None = None
    entropy_threshold: float = 4.3
    entropy_min_length: int = 16
    ignore_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    custom_rules_file: str | None = None
    plugins_dir: str | None = None


def load_config(custom_path: str | None = None) -> KageHoundConfig:
    """
    Load configuration from provided path, local .kagehound.toml, or ~/.config/kagehound/config.toml.
    Environment variables take precedence.
    """
    config_dict = {}

    paths_to_check = []
    if custom_path:
        paths_to_check.append(Path(custom_path))
    paths_to_check.extend(
        [
            Path(".kagehound.toml"),
            Path("kagehound.toml"),
            Path.home() / ".config" / "kagehound" / "config.toml",
        ]
    )

    for p in paths_to_check:
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    config_dict = tomllib.load(f)
                break
            except Exception:
                pass

    # Extract nested sections if present
    data = config_dict.get("kagehound", config_dict)

    # Environment variable overrides
    telegram_token = os.environ.get("TELEGRAM_GENERIC_BOT_TOKEN") or os.environ.get(
        "TELEGRAM_BOT_TOKEN"
    )
    telegram_chat = os.environ.get("TELEGRAM_OWNER_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")
    intelx_key = os.environ.get("INTELX_API_KEY")

    if telegram_token:
        data["telegram_bot_token"] = telegram_token
    if telegram_chat:
        data["telegram_chat_id"] = telegram_chat
    if intelx_key:
        data["intelx_api_key"] = intelx_key

    return KageHoundConfig(**data)
