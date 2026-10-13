"""Compatibility import for the single application Settings class."""

from ckg.config.env import load_env
from ckg.config.settings import Settings

__all__ = ["Settings", "load_env"]
