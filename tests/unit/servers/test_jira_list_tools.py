"""Tests for jira_check_list and jira_list_all."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from requests import Response
from requests.exceptions import HTTPError

from mcp_atlassian.servers.jira import (
    _list_parse_terms,
    _list_word_match,
    check_list,
    list_all,
)


def _issue(key: str, summary: str = "", status: str = "Open", **fields) -> dict:
    return {
        "key": key,
        "fields": {"summary": summary, "status": {"name": status}, **fields},
    }


def _server_fetcher(issues: list[dict]) -> MagicMock:
    """Server/Data Center fetcher whose JQL search returns the given issues."""
    fetcher = MagicMock()
    fetcher.config.is_cloud = False
    custom = {"Sprint": "customfield_10020", "nosuchfield": None}
    fetcher.get_field_id.side_effect = lambda name: custom.get(name, name)
    fetcher.jira.jql.return_value = {"issues": issues}
    return fetcher


async def _call(tool, fetcher, **kwargs) -> dict:
    with patch(
        "mcp_atlassian.servers.jira.get_jira_fetcher",
        AsyncMock(return_value=fetcher),
    ):
        return json.loads(await tool.fn(MagicMock(), **kwargs))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ABC-1, ABC-2;ABC-3\nABC-4", ["ABC-1", "ABC-2", "ABC-3", "ABC-4"]),
        ('["a, b", "c"]', ["a, b", "c"]),
        (["x", "X", " y "], ["x", "y"]),
        ("[not json", ["[not json"]),
        ("", []),
    ],
)
def test_parse_terms(raw, expected):
    assert _list_parse_terms(raw) == expected


def test_word_match_is_whole_word():
    assert _list_word_match("ABC-12", "see ABC-12 for details")
    assert not _list_word_match("ABC-12", "see ABC-123 for details")


@pytest.mark.anyio
async def test_check_list_keys_found_and_missing():
    fetcher = _server_fetcher([_issue("ABC-1", "First"), _issue("ABC-3", "Third")])

    result = await _call(check_list, fetcher, values="ABC-1, abc-2, ABC-3, nokey")

    assert result["values_checked"] == 4
    assert result["found_count"] == 2
    assert result["missing"] == ["abc-2"]
    assert result["not_an_issue_key"] == ["nokey"]
    assert result["found"]["ABC-1"] == {
        "key": "ABC-1",
        "summary": "First",
        "status": "Open",
    }
    jql = fetcher.jira.jql.call_args.args[0]
    assert jql == "key in (ABC-1, ABC-2, ABC-3)"


@pytest.mark.anyio
async def test_check_list_drops_keys_rejected_by_jira():
    fetcher = _server_fetcher([])
    response = Response()
    response.status_code = 400
    response._content = b"An issue with key 'ABC-2' does not exist for field 'key'."
    fetcher.jira.jql.side_effect = [
        HTTPError("400 Client Error", response=response),
        {"issues": [_issue("ABC-1", "First")]},
    ]

    result = await _call(check_list, fetcher, values="ABC-1,ABC-2", only_missing=True)

    assert result["missing"] == ["ABC-2"]
    assert "found" not in result
    assert fetcher.jira.jql.call_args.args[0] == "key in (ABC-1)"


@pytest.mark.anyio
async def test_check_list_text_matches_whole_words_within_scope():
    fetcher = _server_fetcher(
        [_issue("ABC-1", "Login fails"), _issue("ABC-2", "Logins are slow")]
    )

    result = await _call(
        check_list,
        fetcher,
        values="login, export",
        match_field="summary",
        jql="project = ABC",
    )

    assert result["missing"] == ["export"]
    assert [issue["key"] for issue in result["found"]["login"]] == ["ABC-1"]
    assert (
        fetcher.jira.jql.call_args.args[0]
        == '(summary ~ "\\"login\\"" OR summary ~ "\\"export\\"") AND (project = ABC)'
    )


@pytest.mark.anyio
async def test_check_list_rejects_unknown_field():
    fetcher = _server_fetcher([])

    with pytest.raises(ValueError, match="Unknown field: nosuchfield"):
        await _call(check_list, fetcher, values="ABC-1", fields="summary,nosuchfield")


@pytest.mark.anyio
async def test_list_all_reports_more_and_maps_field_names():
    fetcher = _server_fetcher(
        [
            _issue(f"ABC-{n}", f"Issue {n}", customfield_10020=[{"name": "Sprint 7"}])
            for n in range(3)
        ]
    )

    result = await _call(
        list_all, fetcher, jql="project = ABC", fields="summary,Sprint", max_results=2
    )

    assert result["count"] == 2
    assert result["more"] is True
    assert result["issues"][0] == {
        "key": "ABC-0",
        "summary": "Issue 0",
        "Sprint": ["Sprint 7"],
    }


@pytest.mark.anyio
async def test_list_all_unescapes_html_in_jql():
    fetcher = _server_fetcher([])

    await _call(list_all, fetcher, jql="project = ABC AND created &gt;= -7d")

    assert fetcher.jira.jql.call_args.args[0] == "project = ABC AND created >= -7d"


@pytest.mark.anyio
async def test_list_all_count_by():
    fetcher = _server_fetcher(
        [
            _issue("ABC-1", status="Open"),
            _issue("ABC-2", status="Done"),
            _issue("ABC-3", status="Open"),
        ]
    )

    result = await _call(list_all, fetcher, jql="project = ABC", count_by="status")

    assert result == {
        "total": 3,
        "complete": True,
        "count_by": "status",
        "counts": {"Open": 2, "Done": 1},
    }


@pytest.mark.anyio
async def test_list_all_count_by_without_values_is_an_error():
    fetcher = _server_fetcher([_issue("ABC-1", labels=[])])

    with pytest.raises(ValueError, match="has a value in field labels"):
        await _call(list_all, fetcher, jql="project = ABC", count_by="labels")


@pytest.mark.anyio
async def test_list_all_pages_with_next_page_token_on_cloud():
    fetcher = MagicMock()
    fetcher.config.is_cloud = True
    fetcher.get_field_id.side_effect = lambda name: name
    fetcher.jira.resource_url.return_value = "rest/api/3/search/jql"
    pages = iter(
        [
            {"issues": [_issue("ABC-1")], "nextPageToken": "next"},
            {"issues": [_issue("ABC-2")]},
        ]
    )
    sent_tokens = []

    def get(url, params):
        sent_tokens.append(params.get("nextPageToken"))
        return next(pages)

    fetcher.jira.get.side_effect = get

    result = await _call(list_all, fetcher, jql="project = ABC", fields="summary")

    assert [issue["key"] for issue in result["issues"]] == ["ABC-1", "ABC-2"]
    assert sent_tokens == [None, "next"]
