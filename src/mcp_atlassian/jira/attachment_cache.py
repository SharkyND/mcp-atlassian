"""In-memory cache for Jira attachments to expose via MCP resources."""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("mcp-jira")


class AttachmentCache:
    """Thread-safe in-memory cache for storing attachment data temporarily."""

    def __init__(self, ttl_minutes: int = 10, max_size_mb: int = 100):
        """
        Initialize the attachment cache.

        Args:
            ttl_minutes: Time-to-live for cached items in minutes (default: 10)
            max_size_mb: Maximum total cache size in MB (default: 100)
        """
        self._cache: dict[str, dict[str, Any]] = {}
        self._ttl_minutes = ttl_minutes
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._current_size_bytes = 0

    def _generate_key(self, issue_key: str, filename: str) -> str:
        """Generate a unique cache key for an attachment."""
        content = f"{issue_key}:{filename}:{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _evict_expired(self) -> None:
        """Remove expired entries from cache."""
        now = datetime.now()
        expired_keys = [
            key
            for key, value in self._cache.items()
            if now > value["expires_at"]
        ]
        for key in expired_keys:
            self._remove(key)

    def _evict_lru(self) -> None:
        """Remove least recently used entries to free space."""
        if not self._cache:
            return

        # Sort by last accessed time
        sorted_items = sorted(
            self._cache.items(), key=lambda x: x[1]["last_accessed"]
        )

        # Remove oldest 20% of items
        to_remove = max(1, len(sorted_items) // 5)
        for key, _ in sorted_items[:to_remove]:
            self._remove(key)

    def _remove(self, key: str) -> None:
        """Remove an item from cache."""
        if key in self._cache:
            item = self._cache[key]
            self._current_size_bytes -= len(item["content"])
            del self._cache[key]
            logger.debug(f"Removed cached attachment: {key}")

    def store(
        self, issue_key: str, filename: str, content: bytes, mime_type: str
    ) -> str:
        """
        Store attachment content in cache.

        Args:
            issue_key: The Jira issue key
            filename: The attachment filename
            content: The binary content of the attachment
            mime_type: The MIME type of the attachment

        Returns:
            The cache key/ID for retrieving the attachment
        """
        # Clean up expired entries first
        self._evict_expired()

        # Check if we need to make space
        content_size = len(content)
        while (
            self._current_size_bytes + content_size > self._max_size_bytes
            and self._cache
        ):
            self._evict_lru()

        # If still too large after eviction, reject
        if content_size > self._max_size_bytes:
            logger.error(
                f"Attachment {filename} is too large ({content_size} bytes) for cache"
            )
            raise ValueError(
                f"Attachment size ({content_size} bytes) exceeds cache limit"
            )

        # Generate unique key and store
        cache_key = self._generate_key(issue_key, filename)
        expires_at = datetime.now() + timedelta(minutes=self._ttl_minutes)

        self._cache[cache_key] = {
            "issue_key": issue_key,
            "filename": filename,
            "content": content,
            "mime_type": mime_type,
            "created_at": datetime.now(),
            "last_accessed": datetime.now(),
            "expires_at": expires_at,
            "size": content_size,
        }

        self._current_size_bytes += content_size
        logger.info(
            f"Cached attachment {filename} from {issue_key} (key: {cache_key}, "
            f"size: {content_size} bytes, cache usage: {self._current_size_bytes}/{self._max_size_bytes})"
        )

        return cache_key

    def get_by_issue_and_filename(
        self, issue_key: str, filename: str
    ) -> dict[str, Any] | None:
        """
        Retrieve the most recently cached attachment by issue key and filename.

        Args:
            issue_key: The Jira issue key
            filename: The attachment filename

        Returns:
            Dictionary with 'content', 'mime_type', 'filename', 'issue_key' or None if not found
        """
        self._evict_expired()

        matches = [
            (key, item)
            for key, item in self._cache.items()
            if item["issue_key"] == issue_key and item["filename"] == filename
        ]

        if not matches:
            logger.debug(f"Cache miss for issue={issue_key}, filename={filename}")
            return None

        # Use the most recently created entry
        matches.sort(key=lambda x: x[1]["created_at"], reverse=True)
        key, item = matches[0]
        item["last_accessed"] = datetime.now()

        logger.debug(
            f"Cache hit for issue={issue_key}, filename={filename} (key: {key})"
        )
        return {
            "content": item["content"],
            "mime_type": item["mime_type"],
            "filename": item["filename"],
            "issue_key": item["issue_key"],
        }

    def get(self, cache_key: str) -> dict[str, Any] | None:
        """
        Retrieve attachment content from cache.

        Args:
            cache_key: The cache key returned from store()

        Returns:
            Dictionary with 'content', 'mime_type', 'filename', 'issue_key' or None if not found
        """
        self._evict_expired()

        if cache_key not in self._cache:
            logger.debug(f"Cache miss for key: {cache_key}")
            return None

        item = self._cache[cache_key]
        item["last_accessed"] = datetime.now()

        logger.debug(f"Cache hit for key: {cache_key} (file: {item['filename']})")
        return {
            "content": item["content"],
            "mime_type": item["mime_type"],
            "filename": item["filename"],
            "issue_key": item["issue_key"],
        }

    def clear(self) -> None:
        """Clear all cached attachments."""
        count = len(self._cache)
        self._cache.clear()
        self._current_size_bytes = 0
        logger.info(f"Cleared attachment cache ({count} items)")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        self._evict_expired()
        return {
            "item_count": len(self._cache),
            "total_size_bytes": self._current_size_bytes,
            "max_size_bytes": self._max_size_bytes,
            "utilization_percent": round(
                (self._current_size_bytes / self._max_size_bytes) * 100, 2
            )
            if self._max_size_bytes > 0
            else 0,
        }


# Global cache instance
_attachment_cache = AttachmentCache()


def get_attachment_cache() -> AttachmentCache:
    """Get the global attachment cache instance."""
    return _attachment_cache
