"""Tests for the environment utilities module."""

import logging

import pytest

from mcp_atlassian.utils.environment import get_available_services
from tests.utils.assertions import assert_log_contains
from tests.utils.mocks import MockEnvironment


@pytest.fixture(autouse=True)
def setup_logger():
    """Ensure logger is set to INFO level for capturing log messages."""
    logger = logging.getLogger("mcp-atlassian.utils.environment")
    original_level = logger.level
    logger.setLevel(logging.INFO)
    yield
    logger.setLevel(original_level)


@pytest.fixture
def env_scenarios():
    """Environment configuration scenarios for testing."""
    return {
        "oauth_cloud": {
            "CONFLUENCE_URL": "https://company.atlassian.net",
            "JIRA_URL": "https://company.atlassian.net",
            "BITBUCKET_URL": "https://bitbucket.org/company",
            "XRAY_URL": "https://company.atlassian.net",
            "ATLASSIAN_OAUTH_CLIENT_ID": "client_id",
            "ATLASSIAN_OAUTH_CLIENT_SECRET": "client_secret",
            "ATLASSIAN_OAUTH_REDIRECT_URI": "http://localhost:8080/callback",
            "ATLASSIAN_OAUTH_SCOPE": "read:jira-user",
            "ATLASSIAN_OAUTH_CLOUD_ID": "cloud_id",
        },
        "basic_auth_cloud": {
            "CONFLUENCE_URL": "https://company.atlassian.net",
            "CONFLUENCE_USERNAME": "user@company.com",
            "CONFLUENCE_API_TOKEN": "api_token",
            "JIRA_URL": "https://company.atlassian.net",
            "JIRA_USERNAME": "user@company.com",
            "JIRA_API_TOKEN": "api_token",
            "BITBUCKET_URL": "https://bitbucket.org/company",
            "BITBUCKET_USERNAME": "user@company.com",
            "BITBUCKET_APP_PASSWORD": "app_password",
            "XRAY_URL": "https://company.atlassian.net",
            "XRAY_USERNAME": "user@company.com",
            "XRAY_API_TOKEN": "api_token",
        },
        "pat_server": {
            "CONFLUENCE_URL": "https://confluence.company.com",
            "CONFLUENCE_PERSONAL_TOKEN": "pat_token",
            "JIRA_URL": "https://jira.company.com",
            "JIRA_PERSONAL_TOKEN": "pat_token",
            "BITBUCKET_URL": "https://bitbucket.company.com",
            "BITBUCKET_PERSONAL_TOKEN": "pat_token",
            "XRAY_URL": "https://xray.company.com",
            "XRAY_PERSONAL_TOKEN": "pat_token",
        },
        "basic_auth_server": {
            "CONFLUENCE_URL": "https://confluence.company.com",
            "CONFLUENCE_USERNAME": "admin",
            "CONFLUENCE_API_TOKEN": "password",
            "JIRA_URL": "https://jira.company.com",
            "JIRA_USERNAME": "admin",
            "JIRA_API_TOKEN": "password",
            "BITBUCKET_URL": "https://bitbucket.company.com",
            "BITBUCKET_USERNAME": "admin",
            "BITBUCKET_APP_PASSWORD": "password",
            "XRAY_URL": "https://xray.company.com",
            "XRAY_USERNAME": "admin",
            "XRAY_API_TOKEN": "password",
        },
    }


def _assert_service_availability(
    result,
    confluence_expected,
    jira_expected,
    bitbucket_expected=False,
    xray_expected=False,
):
    """Helper to assert service availability."""
    assert result == {
        "confluence": confluence_expected,
        "jira": jira_expected,
        "bitbucket": bitbucket_expected,
        "xray": xray_expected,
    }


def _assert_authentication_logs(caplog, auth_type, services):
    """Helper to assert authentication log messages."""
    log_patterns = {
        "oauth": "OAuth 2.0 (3LO) authentication (Cloud-only features)",
        "cloud_basic": "Cloud Basic Authentication (API Token)",
        "server": "Server/Data Center authentication (PAT or Basic Auth)",
        "not_configured": "is not configured or required environment variables are missing",
    }

    for service in services:
        service_name = service.title()
        if auth_type == "not_configured":
            assert_log_contains(
                caplog, "INFO", f"{service_name} {log_patterns[auth_type]}"
            )
        else:
            assert_log_contains(
                caplog, "INFO", f"Using {service_name} {log_patterns[auth_type]}"
            )


class TestGetAvailableServices:
    """Test cases for get_available_services function."""

    def test_no_services_configured(self, caplog):
        """Test that no services are available when no environment variables are set."""
        with MockEnvironment.clean_env():
            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=False,
                jira_expected=False,
                bitbucket_expected=False,
                xray_expected=False,
            )
            _assert_authentication_logs(
                caplog, "not_configured", ["confluence", "jira", "bitbucket", "xray"]
            )

    @pytest.mark.parametrize(
        "scenario,expected_confluence,expected_jira,expected_bitbucket,expected_xray",
        [
            ("oauth_cloud", True, True, True, True),
            ("basic_auth_cloud", True, True, True, True),
            ("pat_server", True, True, True, True),
            ("basic_auth_server", True, True, True, True),
        ],
    )
    def test_valid_authentication_scenarios(
        self,
        env_scenarios,
        scenario,
        expected_confluence,
        expected_jira,
        expected_bitbucket,
        expected_xray,
        caplog,
    ):
        """Test various valid authentication scenarios."""
        with MockEnvironment.clean_env():
            for key, value in env_scenarios[scenario].items():
                import os

                os.environ[key] = value

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=expected_confluence,
                jira_expected=expected_jira,
                bitbucket_expected=expected_bitbucket,
                xray_expected=expected_xray,
            )

            # Verify appropriate log messages based on scenario
            if scenario == "oauth_cloud":
                _assert_authentication_logs(
                    caplog, "oauth", ["confluence", "jira", "bitbucket", "xray"]
                )
            elif scenario == "basic_auth_cloud":
                _assert_authentication_logs(
                    caplog, "cloud_basic", ["confluence", "jira", "xray"]
                )
                # Bitbucket Cloud uses App Password, which has different log message
                assert_log_contains(
                    caplog,
                    "INFO",
                    "Using Bitbucket Cloud Basic Authentication (App Password)",
                )
            elif scenario in ["pat_server", "basic_auth_server"]:
                _assert_authentication_logs(
                    caplog, "server", ["confluence", "jira", "bitbucket", "xray"]
                )

    @pytest.mark.parametrize(
        "missing_oauth_var",
        [
            "ATLASSIAN_OAUTH_CLIENT_ID",
            "ATLASSIAN_OAUTH_CLIENT_SECRET",
            "ATLASSIAN_OAUTH_REDIRECT_URI",
            "ATLASSIAN_OAUTH_SCOPE",
            "ATLASSIAN_OAUTH_CLOUD_ID",
        ],
    )
    def test_oauth_missing_required_vars(
        self, env_scenarios, missing_oauth_var, caplog
    ):
        """Test that OAuth fails when any required variable is missing."""
        with MockEnvironment.clean_env():
            oauth_config = env_scenarios["oauth_cloud"].copy()
            # Remove one required OAuth variable
            del oauth_config[missing_oauth_var]

            for key, value in oauth_config.items():
                import os

                os.environ[key] = value

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=False,
                jira_expected=False,
                bitbucket_expected=False,
                xray_expected=False,
            )

    @pytest.mark.parametrize(
        "missing_basic_vars,service",
        [
            (
                [
                    "CONFLUENCE_USERNAME",
                    "JIRA_USERNAME",
                    "BITBUCKET_USERNAME",
                    "XRAY_USERNAME",
                ],
                "username",
            ),
            (
                [
                    "CONFLUENCE_API_TOKEN",
                    "JIRA_API_TOKEN",
                    "BITBUCKET_APP_PASSWORD",
                    "XRAY_API_TOKEN",
                ],
                "token",
            ),
        ],
    )
    def test_basic_auth_missing_credentials(
        self, env_scenarios, missing_basic_vars, service
    ):
        """Test that basic auth fails when credentials are missing."""
        with MockEnvironment.clean_env():
            basic_config = env_scenarios["basic_auth_cloud"].copy()

            # Remove required variables
            for var in missing_basic_vars:
                if var in basic_config:
                    del basic_config[var]

            for key, value in basic_config.items():
                import os

                os.environ[key] = value

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=False,
                jira_expected=False,
                bitbucket_expected=False,
                xray_expected=False,
            )

    def test_oauth_precedence_over_basic_auth(self, env_scenarios, caplog):
        """Test that OAuth takes precedence over Basic Auth."""
        with MockEnvironment.clean_env():
            # Set both OAuth and Basic Auth variables
            combined_config = {
                **env_scenarios["oauth_cloud"],
                **env_scenarios["basic_auth_cloud"],
            }

            for key, value in combined_config.items():
                import os

                os.environ[key] = value

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=True,
                jira_expected=True,
                bitbucket_expected=True,
                xray_expected=True,
            )

            # Should use OAuth, not Basic Auth
            _assert_authentication_logs(
                caplog, "oauth", ["confluence", "jira", "bitbucket", "xray"]
            )
            assert "Basic Authentication" not in caplog.text

    def test_mixed_service_configuration(self, caplog):
        """Test mixed configurations where only one service is configured."""
        with MockEnvironment.clean_env():
            import os

            os.environ["CONFLUENCE_URL"] = "https://company.atlassian.net"
            os.environ["CONFLUENCE_USERNAME"] = "user@company.com"
            os.environ["CONFLUENCE_API_TOKEN"] = "api_token"

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=True,
                jira_expected=False,
                bitbucket_expected=False,
                xray_expected=False,
            )

            _assert_authentication_logs(caplog, "cloud_basic", ["confluence"])
            _assert_authentication_logs(
                caplog, "not_configured", ["jira", "bitbucket", "xray"]
            )

    def test_return_value_structure(self):
        """Test that the return value has the correct structure."""
        with MockEnvironment.clean_env():
            result = get_available_services()

            assert isinstance(result, dict)
            assert set(result.keys()) == {"confluence", "jira", "bitbucket", "xray"}
            assert all(isinstance(v, bool) for v in result.values())

    @pytest.mark.parametrize(
        "invalid_vars",
        [
            {"CONFLUENCE_URL": "", "JIRA_URL": ""},  # Empty strings
            {"confluence_url": "https://test.com"},  # Wrong case
        ],
    )
    def test_invalid_environment_variables(self, invalid_vars, caplog):
        """Test behavior with invalid environment variables."""
        with MockEnvironment.clean_env():
            for key, value in invalid_vars.items():
                import os

                os.environ[key] = value

            result = get_available_services()
            _assert_service_availability(
                result,
                confluence_expected=False,
                jira_expected=False,
                bitbucket_expected=False,
                xray_expected=False,
            )
            _assert_authentication_logs(
                caplog, "not_configured", ["confluence", "jira", "bitbucket", "xray"]
            )
