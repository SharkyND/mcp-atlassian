"""
Common Bitbucket entity models.

This module provides Pydantic models for common Bitbucket entities like users, workspaces,
repositories, branches, pull requests, and commits.
"""

import logging
from typing import Any

from pydantic import Field

from ..base import ApiModel, TimestampMixin
from ..constants import (
    UNKNOWN,
)

logger = logging.getLogger(__name__)


class BitbucketUser(ApiModel):
    """Model representing a Bitbucket user."""

    name: str | None = None
    email: str | None = None
    active: bool | None = None
    display_name: str | None = None
    type: str | None = None
    links: dict[str, Any] | None = None

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
            links=data.get("links", {}),
        )


class BitbucketWorkspace(ApiModel):
    """Model representing a Bitbucket workspace."""

    key: str | None = None
    name: str | None = None
    description: str | None = None
    public: bool = False
    type: str | None = None
    links: dict[str, Any] | None = None

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
            public=data.get("public", False),
            links=data.get("links"),
            key=data.get("key"),
        )


class BitbucketRepository(ApiModel):
    """Model representing a Bitbucket repository."""

    slug: str | None = None
    name: str | None = None
    description: str | None = None
    state: str | None = None
    forkable: bool | None = True
    project: dict[str, Any] | None = None
    public: bool | None = False
    archived: bool | None = False
    links: dict[str, Any] | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketRepository":
        """Create a BitbucketRepository from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            slug=data.get("slug"),
            name=data.get("name"),
            description=data.get("description"),
            state=data.get("state"),
            forkable=data.get("forkable", True),
            project=data.get("project", {}),
            public=data.get("public", False),
            archived=data.get("archived", False),
            links=data.get("links", {}),
        )


class BitbucketBranch(ApiModel):
    """Model representing a Bitbucket branch."""

    id_: str = Field(alias="id")
    name: str | None = None
    type: str | None = None
    latest_commit: str | None = None
    latest_changeset: str | None = None
    is_default: bool | None = False
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketBranch":
        """Create a BitbucketBranch from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            name=data.get("displayId", UNKNOWN),
            id=data.get("id", UNKNOWN),
            type=data.get("type"),
            latest_commit=data.get("latestCommit"),
            latest_changeset=data.get("latestChangeset"),
            is_default=data.get("isDefault", False),
            metadata=data.get("metadata", {}),
        )


class BitbucketCommit(ApiModel):
    """Model representing a Bitbucket commit."""

    id_: str | None = Field(alias="id")
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
            committer=BitbucketUser.from_api_response(data.get("committer", {})),
            author_timestamp=data.get("authorTimestamp"),
            committer_timestamp=data.get("committerTimestamp"),
            parents=data.get("parents", []),
        )


class BitbucketPullRequest(ApiModel, TimestampMixin):
    """Model representing a Bitbucket pull request."""

    id_: int | None = Field(alias="id")
    version: int | None
    title: str | None
    description: str | None
    state: str | None
    open: bool | None = False
    draft: bool | None = False
    closed: bool | None = False
    created_date: int | None
    updated_date: int | None
    closed_date: int | None
    from_ref: dict[str, Any] | None
    to_ref: dict[str, Any] | None
    locked: bool | None = False
    author: dict[str, Any] | None
    reviewers: list[dict] | None
    participants: list[dict] | None
    links: dict[str, Any] | None

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], **kwargs: Any
    ) -> "BitbucketPullRequest":
        """Create a BitbucketPullRequest from a Bitbucket API response."""
        if not data:
            return cls()

        return cls(
            id=data.get("id"),
            version=data.get("version"),
            title=data.get("title", UNKNOWN),
            description=data.get("description"),
            state=data.get("state"),
            open=data.get("open", False),
            draft=data.get("draft", False),
            closed=data.get("closed", False),
            author=data.get("author"),
            created_date=data.get("createdDate"),
            updated_date=data.get("updatedDate"),
            closed_date=data.get("closedDate"),
            from_ref=data.get("fromRef"),
            to_ref=data.get("toRef"),
            locked=data.get("locked"),
            reviewers=data.get("reviewers", []),
            participants=data.get("participants", []),
            links=data.get("links"),
        )


class CommitChange(ApiModel):
    content_id: str | None
    from_content_id: str | None
    path: dict[str, Any] | None
    executable: bool | None
    percent_unchanged: int | None
    type: str | None
    node_type: str | None
    src_executable: bool | None
    links: dict[str, Any] | None
    properties: dict[str, Any] | None

    @classmethod
    def from_api_response(cls, data: dict[str, Any], **kwargs: Any) -> "CommitChange":
        if not data:
            return cls()
        return cls(
            content_id=data.get("contentId"),
            from_content_id=data.get("fromContentId"),
            path=data.get("path"),
            executable=data.get("executable"),
            percent_unchanged=data.get("percentUnchanged"),
            type=data.get("type"),
            node_type=data.get("nodeType"),
            src_executable=data.get("srcExecutable"),
            links=data.get("links"),
            properties=data.get("properties"),
        )


class CommitChanges(ApiModel):
    from_hash: str | None
    to_hash: str | None
    properties: dict[str, Any] | None
    values: list[CommitChange] | None
    size: int | None
    is_last_page: bool | None
    start: int | None = 0
    limit: int | None = 25
    next_page_start: int | None

    @classmethod
    def from_api_response(cls, data: dict[str, Any], **kwargs: Any) -> "CommitChanges":
        if not data:
            return cls()
        return cls(
            from_hash=data.get("fromHash"),
            to_hash=data.get("toHash"),
            properties=data.get("properties"),
            values=[
                CommitChange.from_api_response(item) for item in data.get("values", [])
            ]
            if data.get("values")
            else None,
            size=data.get("size"),
            is_last_page=data.get("isLastPage"),
            start=data.get("start", 0),
            limit=data.get("limit", 25),
            next_page_start=data.get("nextPageStart"),
        )
