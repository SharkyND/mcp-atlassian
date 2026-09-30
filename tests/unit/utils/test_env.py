"""Tests for environment variable utility functions."""

from mcp_atlassian.utils.env import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    get_env_timeout,
    get_max_worker_threads,
    is_env_extended_truthy,
    is_env_ssl_verify,
    is_env_truthy,
)


class TestGetEnvTimeout:
    """Test the get_env_timeout function."""

    def test_returns_default_when_unset(self):
        assert get_env_timeout("UNSET_TIMEOUT_VAR") == DEFAULT_HTTP_TIMEOUT_SECONDS

    def test_reads_valid_integer(self, monkeypatch):
        monkeypatch.setenv("TEST_TIMEOUT", "45")
        assert get_env_timeout("TEST_TIMEOUT") == 45

    def test_respects_explicit_default(self, monkeypatch):
        monkeypatch.delenv("TEST_TIMEOUT", raising=False)
        assert get_env_timeout("TEST_TIMEOUT", default=90) == 90

    def test_blank_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("TEST_TIMEOUT", "   ")
        assert get_env_timeout("TEST_TIMEOUT") == DEFAULT_HTTP_TIMEOUT_SECONDS

    def test_non_numeric_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("TEST_TIMEOUT", "not-a-number")
        assert get_env_timeout("TEST_TIMEOUT") == DEFAULT_HTTP_TIMEOUT_SECONDS

    def test_non_positive_falls_back_to_default(self, monkeypatch):
        """A zero/negative timeout would disable it, reintroducing the hang."""
        for value in ("0", "-1"):
            monkeypatch.setenv("TEST_TIMEOUT", value)
            assert get_env_timeout("TEST_TIMEOUT") == DEFAULT_HTTP_TIMEOUT_SECONDS


class TestIsEnvTruthy:
    """Test the is_env_truthy function."""

    def test_standard_truthy_values(self, monkeypatch):
        """Test standard truthy values: 'true', '1', 'yes'."""
        truthy_values = ["true", "1", "yes"]

        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_truthy("TEST_VAR") is True

        # Test uppercase variants
        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value.upper())
            assert is_env_truthy("TEST_VAR") is True

        # Test mixed case variants
        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value.capitalize())
            assert is_env_truthy("TEST_VAR") is True

    def test_standard_falsy_values(self, monkeypatch):
        """Test that standard falsy values return False."""
        falsy_values = ["false", "0", "no", "", "invalid", "y", "on"]

        for value in falsy_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_truthy("TEST_VAR") is False

    def test_unset_variable_with_default(self, monkeypatch):
        """Test behavior when variable is unset with various defaults."""
        monkeypatch.delenv("TEST_VAR", raising=False)

        # Default empty string
        assert is_env_truthy("TEST_VAR") is False

        # Default truthy value
        assert is_env_truthy("TEST_VAR", "true") is True
        assert is_env_truthy("TEST_VAR", "1") is True
        assert is_env_truthy("TEST_VAR", "yes") is True

        # Default falsy value
        assert is_env_truthy("TEST_VAR", "false") is False
        assert is_env_truthy("TEST_VAR", "0") is False

    def test_empty_string_environment_variable(self, monkeypatch):
        """Test behavior when environment variable is set to empty string."""
        monkeypatch.setenv("TEST_VAR", "")
        assert is_env_truthy("TEST_VAR") is False


class TestIsEnvExtendedTruthy:
    """Test the is_env_extended_truthy function."""

    def test_extended_truthy_values(self, monkeypatch):
        """Test extended truthy values: 'true', '1', 'yes', 'y', 'on'."""
        truthy_values = ["true", "1", "yes", "y", "on"]

        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_extended_truthy("TEST_VAR") is True

        # Test uppercase variants
        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value.upper())
            assert is_env_extended_truthy("TEST_VAR") is True

        # Test mixed case variants
        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value.capitalize())
            assert is_env_extended_truthy("TEST_VAR") is True

    def test_extended_falsy_values(self, monkeypatch):
        """Test that extended falsy values return False."""
        falsy_values = ["false", "0", "no", "", "invalid", "off"]

        for value in falsy_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_extended_truthy("TEST_VAR") is False

    def test_extended_vs_standard_difference(self, monkeypatch):
        """Test that extended truthy accepts 'y' and 'on' while standard doesn't."""
        extended_only_values = ["y", "on"]

        for value in extended_only_values:
            monkeypatch.setenv("TEST_VAR", value)
            # Extended should be True
            assert is_env_extended_truthy("TEST_VAR") is True
            # Standard should be False
            assert is_env_truthy("TEST_VAR") is False

    def test_unset_variable_with_default(self, monkeypatch):
        """Test behavior when variable is unset with various defaults."""
        monkeypatch.delenv("TEST_VAR", raising=False)

        # Default empty string
        assert is_env_extended_truthy("TEST_VAR") is False

        # Default truthy values
        assert is_env_extended_truthy("TEST_VAR", "true") is True
        assert is_env_extended_truthy("TEST_VAR", "y") is True
        assert is_env_extended_truthy("TEST_VAR", "on") is True

        # Default falsy value
        assert is_env_extended_truthy("TEST_VAR", "false") is False


class TestIsEnvSslVerify:
    """Test the is_env_ssl_verify function."""

    def test_ssl_verify_default_true(self, monkeypatch):
        """Test that SSL verification defaults to True when unset."""
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert is_env_ssl_verify("TEST_VAR") is True

    def test_ssl_verify_explicit_false_values(self, monkeypatch):
        """Test that SSL verification is False only for explicit false values."""
        false_values = ["false", "0", "no"]

        for value in false_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_ssl_verify("TEST_VAR") is False

        # Test uppercase variants
        for value in false_values:
            monkeypatch.setenv("TEST_VAR", value.upper())
            assert is_env_ssl_verify("TEST_VAR") is False

        # Test mixed case variants
        for value in false_values:
            monkeypatch.setenv("TEST_VAR", value.capitalize())
            assert is_env_ssl_verify("TEST_VAR") is False

    def test_ssl_verify_truthy_and_other_values(self, monkeypatch):
        """Test that SSL verification is True for truthy and other values."""
        truthy_values = ["true", "1", "yes", "y", "on", "enable", "enabled", "anything"]

        for value in truthy_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_ssl_verify("TEST_VAR") is True

    def test_ssl_verify_custom_default(self, monkeypatch):
        """Test SSL verification with custom defaults."""
        monkeypatch.delenv("TEST_VAR", raising=False)

        # Custom default true
        assert is_env_ssl_verify("TEST_VAR", "true") is True

        # Custom default false
        assert is_env_ssl_verify("TEST_VAR", "false") is False

        # Custom default other value
        assert is_env_ssl_verify("TEST_VAR", "anything") is True

    def test_ssl_verify_empty_string(self, monkeypatch):
        """Test SSL verification when set to empty string."""
        monkeypatch.setenv("TEST_VAR", "")
        # Empty string is not in the false values, so should be True
        assert is_env_ssl_verify("TEST_VAR") is True


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_whitespace_handling(self, monkeypatch):
        """Test that whitespace in values is not stripped."""
        # Values with leading/trailing whitespace should not match
        monkeypatch.setenv("TEST_VAR", " true ")
        assert is_env_truthy("TEST_VAR") is False
        assert is_env_extended_truthy("TEST_VAR") is False

        monkeypatch.setenv("TEST_VAR", " false ")
        assert is_env_ssl_verify("TEST_VAR") is True  # Not in false values

    def test_special_characters(self, monkeypatch):
        """Test behavior with special characters."""
        special_values = ["true!", "@yes", "1.0", "y,", "on;"]

        for value in special_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_truthy("TEST_VAR") is False
            assert is_env_extended_truthy("TEST_VAR") is False
            assert is_env_ssl_verify("TEST_VAR") is True  # Not in false values

    def test_unicode_values(self, monkeypatch):
        """Test behavior with unicode values."""
        unicode_values = ["truë", "yés", "1️⃣"]

        for value in unicode_values:
            monkeypatch.setenv("TEST_VAR", value)
            assert is_env_truthy("TEST_VAR") is False
            assert is_env_extended_truthy("TEST_VAR") is False
            assert is_env_ssl_verify("TEST_VAR") is True  # Not in false values

    def test_numeric_string_edge_cases(self, monkeypatch):
        """Test numeric string edge cases."""
        numeric_values = ["01", "1.0", "10", "-1", "2"]

        for value in numeric_values:
            monkeypatch.setenv("TEST_VAR", value)
            if value == "01":
                # "01" is not exactly "1", so should be False
                assert is_env_truthy("TEST_VAR") is False
                assert is_env_extended_truthy("TEST_VAR") is False
            else:
                assert is_env_truthy("TEST_VAR") is False
                assert is_env_extended_truthy("TEST_VAR") is False
            assert is_env_ssl_verify("TEST_VAR") is True  # Not in false values


class TestGetMaxWorkerThreads:
    """Test worker-pool sizing.

    Python's default executor derives its size from os.cpu_count(), which in a
    container reports the node's CPUs rather than the cgroup quota, so
    identical pods get different capacity depending on scheduling. The pool
    size must therefore come from configuration, not inference.
    """

    def test_default_is_deterministic_and_not_cpu_derived(self, monkeypatch):
        import os as _os

        from mcp_atlassian.utils.env import DEFAULT_MAX_WORKER_THREADS

        monkeypatch.delenv("MCP_MAX_WORKER_THREADS", raising=False)
        monkeypatch.setattr(_os, "cpu_count", lambda: 2)
        assert get_max_worker_threads() == DEFAULT_MAX_WORKER_THREADS
        monkeypatch.setattr(_os, "cpu_count", lambda: 64)
        assert get_max_worker_threads() == DEFAULT_MAX_WORKER_THREADS

    def test_reads_override(self, monkeypatch):
        monkeypatch.setenv("MCP_MAX_WORKER_THREADS", "8")
        assert get_max_worker_threads() == 8

    def test_invalid_values_fall_back(self, monkeypatch):
        from mcp_atlassian.utils.env import DEFAULT_MAX_WORKER_THREADS

        for bad in ("0", "-4", "many", "  "):
            monkeypatch.setenv("MCP_MAX_WORKER_THREADS", bad)
            assert get_max_worker_threads() == DEFAULT_MAX_WORKER_THREADS
