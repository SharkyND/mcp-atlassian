"""
Common Bitbucket entity models.

This module provides Pydantic models for common Bitbucket entities like users, workspaces,
repositories, branches, pull requests, and commits.
"""

import logging
from datetime import datetime
from typing import Any, Dict

from pydantic import Field

from mcp_atlassian.utils import parse_date

from ..base import ApiModel, TimestampMixin
from ..constants import (
    UNKNOWN,
)

logger = logging.getLogger(__name__)

class BitbucketUser(ApiModel):
    """Model representing a Bitbucket user."""

    name: str| None = None
    email: str | None = None
    active: bool | None = None
    display_name: str | None = None
    type: str | None = None
    links: Dict[str, Any] | None = None

    @classmethod
    def from_api_response(cls, data: dict[str, Any], **kwargs: Any) -> "BitbucketUser":
        """Create a BitbucketUser from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            name=data.get("name"),
            email=data.get("emailAddress"),
            display_name=data.get("displayName", UNKNOWN),
            active=data.get("active"),
            type=data.get("type"),
            links=data.get('links', {})
        )


class BitbucketWorkspace(ApiModel):
    """Model representing a Bitbucket workspace."""

    key: str | None = None
    name: str | None = None
    description: str | None = None
    public: bool = False
    type: str | None = None
    links: Dict[str, Any] | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketWorkspace":
        """Create a BitbucketWorkspace from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            name=data.get("name", UNKNOWN),
            type=data.get("type"),
            description=data.get("description"),
            public=data.get('public', False),
            links=data.get('links'),
            key=data.get('key')
        )


class BitbucketRepository(ApiModel):
    """Model representing a Bitbucket repository."""
    slug: str | None = None
    name: str | None = None
    description: str | None = None
    state: str | None = None
    forkable: bool | None = True
    project: Dict[str, Any] | None = None
    public: bool | None = False
    archived: bool | None = False
    links: Dict[str, Any] | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketRepository":
        """Create a BitbucketRepository from a Bitbucket API response."""
        if not data:
            return cls()


        return cls(
            slug=data.get('slug'),
            name=data.get("name"),
            description=data.get("description"),
            state=data.get("state"),
            forkable=data.get('forkable', True),
            project=data.get('project', {}),
            public=data.get('public', False),
            archived=data.get('archived', False),
            links=data.get('links', {})
        )


class BitbucketBranch(ApiModel):
    """Model representing a Bitbucket branch."""

    id_ : str = Field(alias='id')
    name: str | None = None
    type: str | None = None
    latest_commit: str | None = None
    latest_changeset: str | None = None
    is_default: bool | None = False
    metadata: Dict[str, Any] | None = None


    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketBranch":
        """Create a BitbucketBranch from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            name=data.get("displayId", UNKNOWN),
            id=data.get('id', UNKNOWN),
            type=data.get("type"),
            latest_commit=data.get('latestCommit'),
            latest_changeset=data.get('latestChangeset'),
            is_default=data.get('isDefault', False),
            metadata=data.get('metadata', {})
        )


class BitbucketCommit(ApiModel):
    """Model representing a Bitbucket commit."""

    id_: str | None = Field(alias='id')
    message: str | None = None
    author: BitbucketUser | None = None
    committer: BitbucketUser | None = None
    parents: list[dict[str, Any]] = Field(default_factory=list)
    author_timestamp: int | None = None
    committer_timestamp: int | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketCommit":
        """Create a BitbucketCommit from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            id=data.get("id"),
            message=data.get("message"),
            author=BitbucketUser.from_api_response(data.get("author", {}))
            if data.get("author")
            else None,
            committer=BitbucketUser.from_api_response(data.get('committer', {})),
            author_timestamp=data.get('authorTimestamp'),
            committer_timestamp=data.get('committerTimestamp'),
            parents=data.get("parents", []),
        )


class BitbucketPullRequest(ApiModel, TimestampMixin):
    """Model representing a Bitbucket pull request."""

    id: int | None = None
    title: str = UNKNOWN
    description: str | None = None
    state: str | None = None  # OPEN, MERGED, DECLINED, SUPERSEDED
    author: BitbucketUser | None = None
    source_branch: str | None = None
    destination_branch: str | None = None
    source_commit: str | None = None
    destination_commit: str | None = None
    merge_commit: str | None = None
    comment_count: int = 0
    task_count: int = 0
    close_source_branch: bool = False
    closed_by: BitbucketUser | None = None
    reason: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketPullRequest":
        """Create a BitbucketPullRequest from a Bitbucket API response."""
        if not data:
            return cls()

        source = data.get("source", {})
        destination = data.get("destination", {})

        return cls(
            id=data.get("id"),
            title=data.get("title", UNKNOWN),
            description=data.get("description"),
            state=data.get("state"),
            author=BitbucketUser.from_api_response(data.get("author", {}))
            if data.get("author")
            else None,
            source_branch=source.get("branch", {}).get("name"),
            destination_branch=destination.get("branch", {}).get("name"),
            source_commit=source.get("commit", {}).get("hash"),
            destination_commit=destination.get("commit", {}).get("hash"),
            merge_commit=data.get("merge_commit", {}).get("hash")
            if data.get("merge_commit")
            else None,
            comment_count=data.get("comment_count", 0),
            task_count=data.get("task_count", 0),
            close_source_branch=data.get("close_source_branch", False),
            closed_by=BitbucketUser.from_api_response(data.get("closed_by", {}))
            if data.get("closed_by")
            else None,
            reason=data.get("reason"),
            created_at=parse_date(data.get("created_on")),
            updated_at=parse_date(data.get("updated_on")),
        )
