"""Shared configuration primitives for every CKG application surface."""

from .env import load_env
from .settings import Settings

__all__ = ["Settings", "load_env"]
