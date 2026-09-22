import pytest

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
