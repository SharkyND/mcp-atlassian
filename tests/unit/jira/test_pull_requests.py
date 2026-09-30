from unittest.mock import MagicMock

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira.pull_requests import PullRequestsMixin


class TestPullRequestsMixin:
    @pytest.mark.parametrize(
        ("is_cloud", "application_type"),
        [(True, "bitbucket"), (False, "stash")],
    )
    def test_get_issue_related_pull_requests_filters_declined(
        self,
        mock_config,
        mock_atlassian_jira,
        is_cloud,
        application_type,
    ):
        mixin = PullRequestsMixin(config=mock_config)
        mixin.jira = mock_atlassian_jira
        mixin.config.url = (
            "https://test.atlassian.net" if is_cloud else "https://jira.example.com"
        )
        mock_atlassian_jira.get_issue.return_value = {"id": "14460459"}
        mock_atlassian_jira.get.return_value = {
            "detail": [
                {
                    "pullRequests": [
                        {"id": str(index), "status": status}
                        for index, status in enumerate(["OPEN"] * 6 + ["DECLINED"] * 2)
                    ]
                }
            ]
        }

        result = mixin.get_issue_related_pull_requests("JEKP-20750")

        pull_requests = result["detail"][0]["pullRequests"]
        assert len(pull_requests) == 6
        assert all(pr["status"] != "DECLINED" for pr in pull_requests)
        mock_atlassian_jira.get.assert_called_once_with(
            "rest/dev-status/1.0/issue/detail",
            params={
                "issueId": "14460459",
                "applicationType": application_type,
                "dataType": "pullrequest",
            },
        )

    @staticmethod
    def _mixin_raising(mock_config, mock_atlassian_jira, status_code, body=None):
        """Build a mixin whose dev-status call fails with the given HTTP status."""
        mixin = PullRequestsMixin(config=mock_config)
        mixin.jira = mock_atlassian_jira
        mock_atlassian_jira.get_issue.return_value = {"id": "14460459"}
        response = MagicMock()
        response.status_code = status_code
        if body is None:
            response.json.side_effect = ValueError("no json")
            response.text = ""
        else:
            response.json.return_value = body
        mock_atlassian_jira.get.side_effect = HTTPError(response=response)
        return mixin

    def test_403_reports_missing_development_tools_permission(
        self, mock_config, mock_atlassian_jira
    ):
        """A 403 is a permission problem, not an expired/invalid token."""
        mixin = self._mixin_raising(mock_config, mock_atlassian_jira, 403)

        with pytest.raises(MCPAtlassianAuthenticationError) as exc_info:
            mixin.get_issue_related_pull_requests("JEKP-20750")

        message = str(exc_info.value)
        assert "Permission denied" in message
        assert "View Development Tools" in message
        assert "Token may be expired" not in message

    def test_401_reports_invalid_credentials(self, mock_config, mock_atlassian_jira):
        """A 401 with no permission detail is still a credentials problem."""
        mixin = self._mixin_raising(mock_config, mock_atlassian_jira, 401)

        with pytest.raises(MCPAtlassianAuthenticationError) as exc_info:
            mixin.get_issue_related_pull_requests("JEKP-20750")

        message = str(exc_info.value)
        assert "Authentication failed" in message
        assert "Token may be expired" in message
        assert "Permission denied" not in message

    def test_401_with_permission_body_reports_permission_denied(
        self, mock_config, mock_atlassian_jira
    ):
        """Some Jira DC deployments report permission errors as 401."""
        mixin = self._mixin_raising(
            mock_config,
            mock_atlassian_jira,
            401,
            body={"errorMessages": ["You do not have permission to view this"]},
        )

        with pytest.raises(MCPAtlassianAuthenticationError) as exc_info:
            mixin.get_issue_related_pull_requests("JEKP-20750")

        assert "Permission denied" in str(exc_info.value)

    def test_missing_issue_raises_value_error(self, mock_config, mock_atlassian_jira):
        """The specific ValueError must not be masked by the generic handler."""
        mixin = PullRequestsMixin(config=mock_config)
        mixin.jira = mock_atlassian_jira
        mock_atlassian_jira.get_issue.return_value = {}

        with pytest.raises(ValueError, match="was not found"):
            mixin.get_issue_related_pull_requests("JEKP-20750")

    def test_unexpected_response_type_raises_type_error(
        self, mock_config, mock_atlassian_jira
    ):
        """The specific TypeError must not be masked by the generic handler."""
        mixin = PullRequestsMixin(config=mock_config)
        mixin.jira = mock_atlassian_jira
        mock_atlassian_jira.get_issue.return_value = {"id": "14460459"}
        mock_atlassian_jira.get.return_value = None

        with pytest.raises(TypeError, match="Unexpected return value"):
            mixin.get_issue_related_pull_requests("JEKP-20750")
