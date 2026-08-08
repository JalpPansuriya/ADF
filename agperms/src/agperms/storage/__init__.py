"""Storage backends.

``MemoryStorage`` is the zero-dependency default. ``SqlStorage`` (requires
``agperms[sql]``) is the durable option -- import it directly from
``agperms.storage.sql`` so that installing agperms without SQLAlchemy still
works.
"""

from __future__ import annotations

from agperms.storage.memory import MemoryStorage
from agperms.storage.protocol import Storage

__all__ = ["MemoryStorage", "Storage"]
