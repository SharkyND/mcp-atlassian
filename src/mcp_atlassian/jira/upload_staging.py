"""In-memory staging store for client-uploaded files pending Jira attachment.

Files are uploaded by the MCP client to the /upload HTTP endpoint, staged here,
then consumed by the jira_upload_attachment MCP tool to push them to Jira.

URI scheme: upload://sessions/<session_id>/<file_id>
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("mcp-jira")

_TTL_MINUTES = int(os.environ.get("UPLOAD_STAGING_TTL_MINUTES", "30"))
_MAX_SIZE_MB = int(os.environ.get("UPLOAD_STAGING_MAX_SIZE_MB", "200"))
_URI_PREFIX = "upload://sessions/"


class UploadStagingStore:
    """In-memory staging store for files uploaded by MCP clients."""

    def __init__(self, ttl_minutes: int = 30, max_size_mb: int = 200) -> None:
        # {session_id: {file_id: entry_dict}}
        self._store: dict[str, dict[str, dict[str, Any]]] = {}
        self._ttl = timedelta(minutes=ttl_minutes)
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._current_size_bytes = 0

    def create_session(self) -> str:
        """Generate a new opaque upload session token."""
        return secrets.token_urlsafe(24)

    def store(
        self, session_id: str, filename: str, content: bytes, mime_type: str
    ) -> str:
        """Stage a file and return its file_id.

        Args:
            session_id: The upload session token (from construct_upload_endpoint).
            filename: Original filename (already sanitised by the upload endpoint).
            content: Raw file bytes.
            mime_type: MIME type of the file.

        Returns:
            file_id component of the resulting upload:// URI.

        Raises:
            ValueError: If the file is too large for the staging store.
        """
        self._evict_expired()

        content_size = len(content)
        if content_size > self._max_size_bytes:
            raise ValueError(
                f"File size ({content_size} bytes) exceeds staging limit "
                f"({self._max_size_bytes} bytes)"
            )

        # Evict LRU entries if needed to make room
        while (
            self._current_size_bytes + content_size > self._max_size_bytes
            and self._store
        ):
            self._evict_oldest()

        file_id = secrets.token_urlsafe(12)
        entry: dict[str, Any] = {
            "filename": filename,
            "content": content,
            "mime_type": mime_type,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + self._ttl,
        }
        self._store.setdefault(session_id, {})[file_id] = entry
        self._current_size_bytes += content_size
        logger.debug(
            "Staged upload '%s' → session=%s file_id=%s (%d bytes)",
            filename,
            session_id,
            file_id,
            content_size,
        )
        return file_id

    def get(self, session_id: str, file_id: str) -> dict[str, Any] | None:
        """Return a staged entry, or None if not found / expired."""
        self._evict_expired()
        entry = self._store.get(session_id, {}).get(file_id)
        if entry and datetime.now() <= entry["expires_at"]:
            return entry
        return None

    def remove(self, session_id: str, file_id: str) -> None:
        """Remove a staged file (call after successful Jira upload)."""
        session = self._store.get(session_id, {})
        if file_id in session:
            self._current_size_bytes -= len(session[file_id]["content"])
            del session[file_id]
            if not session:
                del self._store[session_id]
                logger.debug("Removed empty upload session: %s", session_id)

    # ------------------------------------------------------------------
    # URI helpers
    # ------------------------------------------------------------------

    @staticmethod
    def make_uri(session_id: str, file_id: str) -> str:
        """Build the canonical upload:// URI for a staged file."""
        return f"{_URI_PREFIX}{session_id}/{file_id}"

    @staticmethod
    def parse_uri(uri: str) -> tuple[str, str] | None:
        """Parse upload://sessions/<session_id>/<file_id> → (session_id, file_id).

        Returns None if the URI does not match the expected format.
        """
        if not uri.startswith(_URI_PREFIX):
            return None
        rest = uri[len(_URI_PREFIX):]
        parts = rest.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return None
        return parts[0], parts[1]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_expired(self) -> None:
        now = datetime.now()
        for session_id in list(self._store):
            for file_id in list(self._store[session_id]):
                if now > self._store[session_id][file_id]["expires_at"]:
                    self._current_size_bytes -= len(
                        self._store[session_id][file_id]["content"]
                    )
                    del self._store[session_id][file_id]
            if not self._store.get(session_id):
                self._store.pop(session_id, None)

    def _evict_oldest(self) -> None:
        """Remove the globally oldest staged file to free space."""
        oldest_key: tuple[str, str] | None = None
        oldest_time: datetime | None = None
        for session_id, files in self._store.items():
            for file_id, entry in files.items():
                if oldest_time is None or entry["created_at"] < oldest_time:
                    oldest_time = entry["created_at"]
                    oldest_key = (session_id, file_id)
        if oldest_key:
            self.remove(*oldest_key)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_upload_staging: UploadStagingStore | None = None


def get_upload_staging() -> UploadStagingStore:
    """Return the process-wide singleton UploadStagingStore."""
    global _upload_staging
    if _upload_staging is None:
        _upload_staging = UploadStagingStore(
            ttl_minutes=_TTL_MINUTES,
            max_size_mb=_MAX_SIZE_MB,
        )
    return _upload_staging
