"""Tests for the I/O utilities module."""

import os
from unittest.mock import patch

from mcp_atlassian.utils.io import is_read_only_mode, resolve_read_only_mode


def test_is_read_only_mode_default():
    """Test that is_read_only_mode returns False by default."""
    # Arrange - Make sure READ_ONLY_MODE is not set
    with patch.dict(os.environ, clear=True):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is False


def test_is_read_only_mode_true():
    """Test that is_read_only_mode returns True when environment variable is set to true."""
    # Arrange - Set READ_ONLY_MODE to true
    with patch.dict(os.environ, {"READ_ONLY_MODE": "true"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is True


def test_is_read_only_mode_yes():
    """Test that is_read_only_mode returns True when environment variable is set to yes."""
    # Arrange - Set READ_ONLY_MODE to yes
    with patch.dict(os.environ, {"READ_ONLY_MODE": "yes"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is True


def test_is_read_only_mode_one():
    """Test that is_read_only_mode returns True when environment variable is set to 1."""
    # Arrange - Set READ_ONLY_MODE to 1
    with patch.dict(os.environ, {"READ_ONLY_MODE": "1"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is True


def test_is_read_only_mode_on():
    """Test that is_read_only_mode returns True when environment variable is set to on."""
    # Arrange - Set READ_ONLY_MODE to on
    with patch.dict(os.environ, {"READ_ONLY_MODE": "on"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is True


def test_is_read_only_mode_uppercase():
    """Test that is_read_only_mode is case-insensitive."""
    # Arrange - Set READ_ONLY_MODE to TRUE (uppercase)
    with patch.dict(os.environ, {"READ_ONLY_MODE": "TRUE"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is True


def test_is_read_only_mode_false():
    """Test that is_read_only_mode returns False when environment variable is set to false."""
    # Arrange - Set READ_ONLY_MODE to false
    with patch.dict(os.environ, {"READ_ONLY_MODE": "false"}):
        # Act
        result = is_read_only_mode()

        # Assert
        assert result is False


def test_is_read_only_mode_uses_cli_when_env_missing():
    """CLI flag should control read-only mode when env variable is unset."""
    with patch.dict(os.environ, {"CLI_READ_ONLY_MODE": "true"}, clear=True):
        assert is_read_only_mode() is True


def test_is_read_only_mode_env_overrides_cli():
    """Environment variable should override CLI flag."""
    with patch.dict(
        os.environ,
        {"CLI_READ_ONLY_MODE": "true", "READ_ONLY_MODE": "false"},
        clear=True,
    ):
        assert is_read_only_mode() is False


def test_resolve_read_only_mode_header_priority():
    """Header value should override env and CLI."""
    result = resolve_read_only_mode(
        cli_read_only=True, env_read_only=True, header_read_only="false"
    )
    assert result is False


def test_resolve_read_only_mode_env_fallback():
    """Env value should be used when header missing."""
    result = resolve_read_only_mode(
        cli_read_only=False, env_read_only=True, header_read_only=None
    )
    assert result is True


def test_resolve_read_only_mode_cli_fallback():
    """CLI value should be used when header/env missing."""
    result = resolve_read_only_mode(
        cli_read_only=True, env_read_only=None, header_read_only=None
    )
    assert result is True


def test_resolve_read_only_mode_header_truthy_variants():
    """Header truthy variants should enable read-only mode."""
    for value in ("TRUE", "yes", "1", "on"):
        assert (
            resolve_read_only_mode(
                cli_read_only=False, env_read_only=False, header_read_only=value
            )
            is True
        )
