"""Tests for the Confluence v2 adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from requests import Session
from requests.exceptions import HTTPError

from mcp_atlassian.confluence.v2_adapter import ConfluenceV2Adapter


def make_response(json_data: dict | None = None, status_code: int = 200) -> MagicMock:
    """Helper to build a mock response."""
    response = MagicMock()
    response.json.return_value = json_data or {}
    response.status_code = status_code
    response.text = "response-body"
    response.raise_for_status.return_value = None
    return response


def make_http_error(response: MagicMock | None = None) -> HTTPError:
    """Helper to build an HTTPError with optional response."""
    error = HTTPError("boom")
    error.response = response
    return error


def build_adapter(session: Session | None = None) -> ConfluenceV2Adapter:
    """Convenience factory for the adapter."""
    return ConfluenceV2Adapter(
        session or MagicMock(spec=Session), "https://example.atlassian.net/wiki"
    )


class TestGetSpaceId:
    def test_get_space_id_success(self):
        session = MagicMock(spec=Session)
        session.get.return_value = make_response({"results": [{"id": "42"}]})
        adapter = build_adapter(session)

        result = adapter._get_space_id("SPACE")

        assert result == "42"
        session.get.assert_called_once_with(
            "https://example.atlassian.net/wiki/api/v2/spaces",
            params={"keys": "SPACE"},
        )

    def test_get_space_id_missing_space_raises(self):
        session = MagicMock(spec=Session)
        session.get.return_value = make_response({"results": []})
        adapter = build_adapter(session)

        with pytest.raises(ValueError) as exc:
            adapter._get_space_id("MISSING")

        assert "not found" in str(exc.value)

    def test_get_space_id_http_error(self):
        session = MagicMock(spec=Session)
        response = make_response()
        http_error = make_http_error(response)
        response.raise_for_status.side_effect = http_error
        session.get.return_value = response
        adapter = build_adapter(session)

        with pytest.raises(ValueError) as exc:
            adapter._get_space_id("SPACE")

        assert "Failed to get space ID" in str(exc.value)


class TestCreatePage:
    def test_create_page_success(self):
        session = MagicMock(spec=Session)
        response = make_response(
            {
                "id": "123",
                "title": "Example",
                "spaceId": "1",
                "status": "current",
                "version": {"number": 1},
                "_links": {},
            }
        )
        session.post.return_value = response
        adapter = build_adapter(session)

        with (
            patch.object(adapter, "_get_space_id", return_value="1") as mock_space,
            patch.object(
                adapter, "_convert_v2_to_v1_format", return_value={"id": "123"}
            ) as mock_convert,
        ):
            result = adapter.create_page("SPACE", "Example", "<p>Hello</p>")

        assert result == {"id": "123"}
        mock_space.assert_called_once_with("SPACE")
        session.post.assert_called_once()
        mock_convert.assert_called_once()

    def test_create_page_http_error(self):
        session = MagicMock(spec=Session)
        http_error = make_http_error(make_response())
        session.post.return_value = make_response()
        session.post.return_value.raise_for_status.side_effect = http_error
        adapter = build_adapter(session)

        with patch.object(adapter, "_get_space_id", return_value="1"):
            with pytest.raises(ValueError):
                adapter.create_page("SPACE", "Title", "Body")


class TestGetPageVersion:
    def test_get_page_version_success(self):
        session = MagicMock(spec=Session)
        session.get.return_value = make_response({"version": {"number": 5}})
        adapter = build_adapter(session)

        assert adapter._get_page_version("123") == 5

    def test_get_page_version_missing_version(self):
        session = MagicMock(spec=Session)
        session.get.return_value = make_response({})
        adapter = build_adapter(session)

        with pytest.raises(ValueError):
            adapter._get_page_version("123")


class TestUpdatePage:
    def test_update_page_success(self):
        session = MagicMock(spec=Session)
        update_response = make_response(
            {
                "id": "123",
                "spaceId": "space-id",
                "title": "Updated",
                "status": "current",
                "version": {"number": 2},
            }
        )
        session.put.return_value = update_response
        adapter = build_adapter(session)

        with (
            patch.object(adapter, "_get_page_version", return_value=1),
            patch.object(adapter, "_get_space_key_from_id", return_value="SPACE"),
            patch.object(
                adapter, "_convert_v2_to_v1_format", return_value={"converted": True}
            ) as mock_convert,
        ):
            result = adapter.update_page("123", "Updated", "<p>Body</p>")

        assert result == {"converted": True}
        mock_convert.assert_called_once_with(update_response.json.return_value, "SPACE")

    def test_update_page_http_error(self):
        session = MagicMock(spec=Session)
        response = make_response()
        response.raise_for_status.side_effect = make_http_error(response)
        session.put.return_value = response
        adapter = build_adapter(session)

        with patch.object(adapter, "_get_page_version", return_value=1):
            with pytest.raises(ValueError):
                adapter.update_page("123", "Title", "Body")


class TestSpaceKeyLookup:
    def test_get_space_key_from_id_success(self):
        session = MagicMock(spec=Session)
        session.get.return_value = make_response({"key": "DOC"})
        adapter = build_adapter(session)

        assert adapter._get_space_key_from_id("999") == "DOC"

    def test_get_space_key_from_id_http_error_returns_id(self):
        session = MagicMock(spec=Session)
        response = make_response()
        response.raise_for_status.side_effect = make_http_error(response)
        session.get.return_value = response
        adapter = build_adapter(session)

        assert adapter._get_space_key_from_id("999") == "999"

    def test_get_space_key_from_id_general_exception(self):
        session = MagicMock(spec=Session)
        session.get.side_effect = RuntimeError("oops")
        adapter = build_adapter(session)
        assert adapter._get_space_key_from_id("999") == "999"


class TestGetPage:
    def test_get_page_success(self):
        session = MagicMock(spec=Session)
        page_data = {
            "id": "123",
            "status": "current",
            "title": "Example",
            "spaceId": "space-id",
            "body": {"storage": {"value": "<p>Hi</p>"}},
            "version": {"number": 3},
            "_links": {"self": "url"},
        }
        session.get.return_value = make_response(page_data)
        adapter = build_adapter(session)

        with patch.object(adapter, "_get_space_key_from_id", return_value="SPACE"):
            result = adapter.get_page("123")

        assert result["space"]["key"] == "SPACE"
        assert result["body"]["storage"]["value"] == "<p>Hi</p>"
        assert result["version"]["number"] == 3

    def test_get_page_http_error(self):
        session = MagicMock(spec=Session)
        response = make_response()
        response.raise_for_status.side_effect = make_http_error(response)
        session.get.return_value = response
        adapter = build_adapter(session)

        with pytest.raises(ValueError):
            adapter.get_page("123")


class TestDeletePage:
    def test_delete_page_success(self):
        session = MagicMock(spec=Session)
        session.delete.return_value = make_response(status_code=204)
        adapter = build_adapter(session)

        assert adapter.delete_page("123") is True
        session.delete.assert_called_once_with(
            "https://example.atlassian.net/wiki/api/v2/pages/123"
        )

    def test_delete_page_http_error(self):
        session = MagicMock(spec=Session)
        response = make_response()
        response.raise_for_status.side_effect = make_http_error(response)
        session.delete.return_value = response
        adapter = build_adapter(session)

        with pytest.raises(ValueError):
            adapter.delete_page("123")


def test_convert_v2_to_v1_format():
    adapter = build_adapter()
    v2_data = {
        "id": "1",
        "status": "current",
        "title": "Title",
        "spaceId": "space-id",
        "version": {"number": 4},
        "_links": {},
        "body": {"storage": {"value": "<p>Body</p>"}},
    }

    converted = adapter._convert_v2_to_v1_format(v2_data, "SPACE")

    assert converted["space"]["key"] == "SPACE"
    assert converted["version"]["number"] == 4
    assert converted["body"]["storage"]["value"] == "<p>Body</p>"
