"""Tests for the Bitbucket constants module."""

from mcp_atlassian.bitbucket.constants import (
    DEFAULT_BRANCH_NAMES,
    PR_STATES,
    REPO_TYPES,
)


class TestBitbucketConstants:
    """Test cases for Bitbucket constants."""

    def test_default_branch_names(self):
        """Test that default branch names are correctly defined."""
        expected_branches = ["main", "master", "develop"]
        assert DEFAULT_BRANCH_NAMES == expected_branches
        assert isinstance(DEFAULT_BRANCH_NAMES, list)
        assert len(DEFAULT_BRANCH_NAMES) == 3

    def test_pr_states(self):
        """Test that pull request states are correctly defined."""
        expected_states = {
            "OPEN": "OPEN",
            "MERGED": "MERGED",
            "DECLINED": "DECLINED",
            "SUPERSEDED": "SUPERSEDED",
        }
        assert PR_STATES == expected_states
        assert isinstance(PR_STATES, dict)
        assert len(PR_STATES) == 4

    def test_pr_states_values(self):
        """Test individual PR state values."""
        assert PR_STATES["OPEN"] == "OPEN"
        assert PR_STATES["MERGED"] == "MERGED"
        assert PR_STATES["DECLINED"] == "DECLINED"
        assert PR_STATES["SUPERSEDED"] == "SUPERSEDED"

    def test_repo_types(self):
        """Test that repository types are correctly defined."""
        assert "GIT" in REPO_TYPES
        assert REPO_TYPES["GIT"] == "git"
        assert isinstance(REPO_TYPES, dict)

    def test_constants_immutability(self):
        """Test that constants maintain their expected structure."""
        # These should be stable constants
        assert len(DEFAULT_BRANCH_NAMES) >= 3
        assert len(PR_STATES) >= 4
        assert len(REPO_TYPES) >= 1

    def test_branch_names_are_strings(self):
        """Test that all branch names are strings."""
        for branch in DEFAULT_BRANCH_NAMES:
            assert isinstance(branch, str)
            assert len(branch) > 0

    def test_pr_state_keys_and_values_consistency(self):
        """Test that PR state keys match their values."""
        for key, value in PR_STATES.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert key == value  # In this case, keys and values are the same

    def test_repo_types_format(self):
        """Test repository types format."""
        for key, value in REPO_TYPES.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert key.isupper()  # Keys should be uppercase
            assert value.islower()  # Values should be lowercase
