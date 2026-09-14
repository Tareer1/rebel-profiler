"""Storage package: SQLite persistence with migrations and case isolation."""

from .database import Database, MIGRATIONS

__all__ = ["Database", "MIGRATIONS"]
