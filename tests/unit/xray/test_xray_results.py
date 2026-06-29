"""Tests for the Xray test results mixin."""

import base64
from unittest.mock import MagicMock, patch

import pytest

from mcp_atlassian.xray.config import XrayConfig
from mcp_atlassian.xray.results import MixTestResults
from tests.fixtures.xray_mocks import (
    MOCK_XRAY_EVIDENCE_LIST,
    MOCK_XRAY_EVIDENCE_LIST_EMPTY,
    MOCK_XRAY_TEST_EXECUTION_DETAILED_RESPONSE,
    MOCK_XRAY_TEST_RUN_RESPONSE,
    MOCK_XRAY_TEST_STEPS_RESPONSE,
)


class TestMixTestResults:
    """Tests for the MixTestResults mixin."""

    @pytest.fixture
    def xray_config(self):
        """Create a basic Xray config for testing."""
        return XrayConfig(
            url="https://xray.example.com",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
        )

    @pytest.fixture
    def results_mixin(self, xray_config):
        """Create a MixTestResults instance for testing."""
        with patch(
            "mcp_atlassian.xray.results.XrayClient.__init__", return_value=None
        ):
            mixin = MixTestResults()
            mixin.config = xray_config
            mixin.xray = MagicMock()
            return mixin

    # ------------------------------------------------------------------ #
    # get_test_execution_results                                           #
    # ------------------------------------------------------------------ #

    def test_get_test_execution_results_returns_structured_response(
        self, results_mixin
    ):
        """get_test_execution_results returns structured dict with results list."""
        results_mixin.xray.get_tests_with_test_execution.return_value = (
            MOCK_XRAY_TEST_EXECUTION_DETAILED_RESPONSE
        )

        output = results_mixin.get_test_execution_results("EXEC-001")

        assert output["execution_key"] == "EXEC-001"
        assert output["page"] == 1
        assert output["limit"] == 50
        assert output["total"] == 3
        assert len(output["results"]) == 3

    def test_get_test_execution_results_maps_fields(self, results_mixin):
        """Each result entry contains the expected mapped fields."""
        results_mixin.xray.get_tests_with_test_execution.return_value = (
            MOCK_XRAY_TEST_EXECUTION_DETAILED_RESPONSE
        )

        output = results_mixin.get_test_execution_results("EXEC-001")

        first = output["results"][0]
        assert first["test_key"] == "TEST-001"
        assert first["run_id"] == 12345
        assert first["status"] == "PASS"
        assert first["assignee"] == "test-user"
        assert first["defects"] == []
        assert first["started_on"] == "2024-01-15T10:00:00-05:00"
        assert first["comment"] == "Test executed successfully"

        second = output["results"][1]
        assert second["test_key"] == "TEST-002"
        assert second["status"] == "FAIL"
        assert second["defects"] == ["BUG-001"]

        third = output["results"][2]
        assert third["status"] == "TODO"
        assert third["assignee"] is None
        assert third["started_on"] is None

    def test_get_test_execution_results_passes_pagination(self, results_mixin):
        """Pagination parameters are forwarded to the underlying API call."""
        results_mixin.xray.get_tests_with_test_execution.return_value = []

        results_mixin.get_test_execution_results("EXEC-002", page=2, limit=25)

        results_mixin.xray.get_tests_with_test_execution.assert_called_once_with(
            "EXEC-002",
            detailed=True,
            page=2,
            limit=25,
        )

    def test_get_test_execution_results_empty_execution(self, results_mixin):
        """An empty execution returns total=0 and an empty results list."""
        results_mixin.xray.get_tests_with_test_execution.return_value = []

        output = results_mixin.get_test_execution_results("EXEC-EMPTY")

        assert output["total"] == 0
        assert output["results"] == []

    def test_get_test_execution_results_handles_non_list_response(
        self, results_mixin
    ):
        """Non-list API responses are treated as empty safely."""
        results_mixin.xray.get_tests_with_test_execution.return_value = None

        output = results_mixin.get_test_execution_results("EXEC-001")

        assert output["total"] == 0
        assert output["results"] == []

    # ------------------------------------------------------------------ #
    # get_test_run_full_results                                            #
    # ------------------------------------------------------------------ #

    def test_get_test_run_full_results_returns_all_fields(self, results_mixin):
        """get_test_run_full_results aggregates all sub-calls into one dict."""
        results_mixin.xray.get_test_run.return_value = MOCK_XRAY_TEST_RUN_RESPONSE
        results_mixin.xray.get_test_run_status.return_value = "PASS"
        results_mixin.xray.get_test_run_assignee.return_value = "test-user"
        results_mixin.xray.get_test_run_comment.return_value = (
            "Test executed successfully"
        )
        results_mixin.xray.get_test_run_defects.return_value = []
        results_mixin.xray.get_test_run_steps.return_value = (
            MOCK_XRAY_TEST_STEPS_RESPONSE
        )

        output = results_mixin.get_test_run_full_results(12345)

        assert output["run_id"] == 12345
        assert output["status"] == "PASS"
        assert output["assignee"] == "test-user"
        assert output["comment"] == "Test executed successfully"
        assert output["defects"] == []
        assert output["steps"] == MOCK_XRAY_TEST_STEPS_RESPONSE
        assert output["details"] == MOCK_XRAY_TEST_RUN_RESPONSE

    def test_get_test_run_full_results_calls_all_sub_apis(self, results_mixin):
        """All six Xray sub-API calls are made exactly once."""
        results_mixin.xray.get_test_run.return_value = {}
        results_mixin.xray.get_test_run_status.return_value = "FAIL"
        results_mixin.xray.get_test_run_assignee.return_value = "user"
        results_mixin.xray.get_test_run_comment.return_value = ""
        results_mixin.xray.get_test_run_defects.return_value = ["BUG-001"]
        results_mixin.xray.get_test_run_steps.return_value = []

        results_mixin.get_test_run_full_results(99)

        results_mixin.xray.get_test_run.assert_called_once_with(99)
        results_mixin.xray.get_test_run_status.assert_called_once_with(99)
        results_mixin.xray.get_test_run_assignee.assert_called_once_with(99)
        results_mixin.xray.get_test_run_comment.assert_called_once_with(99)
        results_mixin.xray.get_test_run_defects.assert_called_once_with(99)
        results_mixin.xray.get_test_run_steps.assert_called_once_with(99)

    def test_get_test_run_full_results_normalises_non_list_defects(
        self, results_mixin
    ):
        """Non-list defects response is normalised to an empty list."""
        results_mixin.xray.get_test_run.return_value = {}
        results_mixin.xray.get_test_run_status.return_value = "TODO"
        results_mixin.xray.get_test_run_assignee.return_value = None
        results_mixin.xray.get_test_run_comment.return_value = None
        results_mixin.xray.get_test_run_defects.return_value = None  # bad response
        results_mixin.xray.get_test_run_steps.return_value = []

        output = results_mixin.get_test_run_full_results(1)

        assert output["defects"] == []

    def test_get_test_run_full_results_normalises_non_list_steps(
        self, results_mixin
    ):
        """Non-list steps response is normalised to an empty list."""
        results_mixin.xray.get_test_run.return_value = {}
        results_mixin.xray.get_test_run_status.return_value = "TODO"
        results_mixin.xray.get_test_run_assignee.return_value = None
        results_mixin.xray.get_test_run_comment.return_value = None
        results_mixin.xray.get_test_run_defects.return_value = []
        results_mixin.xray.get_test_run_steps.return_value = None  # bad response

        output = results_mixin.get_test_run_full_results(1)

        assert output["steps"] == []

    # ------------------------------------------------------------------ #
    # get_test_run_evidences                                               #
    # ------------------------------------------------------------------ #

    def test_get_test_run_evidences_returns_list(self, results_mixin):
        """get_test_run_evidences returns the list from the API call."""
        results_mixin.xray.resource_url.return_value = "rest/raven/1.0/api/testrun/12345/attachment"
        results_mixin.xray.get.return_value = MOCK_XRAY_EVIDENCE_LIST

        output = results_mixin.get_test_run_evidences(12345)

        assert output == MOCK_XRAY_EVIDENCE_LIST
        results_mixin.xray.resource_url.assert_called_once_with(
            "testrun/12345/attachment"
        )

    def test_get_test_run_evidences_empty_response(self, results_mixin):
        """Non-list API response is normalised to an empty list."""
        results_mixin.xray.resource_url.return_value = "rest/raven/1.0/api/testrun/1/attachment"
        results_mixin.xray.get.return_value = None

        output = results_mixin.get_test_run_evidences(1)

        assert output == []

    def test_get_test_run_evidences_no_attachments(self, results_mixin):
        """Empty list from API is returned as-is."""
        results_mixin.xray.resource_url.return_value = "rest/raven/1.0/api/testrun/1/attachment"
        results_mixin.xray.get.return_value = MOCK_XRAY_EVIDENCE_LIST_EMPTY

        output = results_mixin.get_test_run_evidences(1)

        assert output == []

    # ------------------------------------------------------------------ #
    # get_test_execution_evidences                                         #
    # ------------------------------------------------------------------ #

    def test_get_test_execution_evidences_aggregates_runs(self, results_mixin):
        """Evidences embedded in the detailed response are collected per run."""
        detailed = [
            {
                "id": 12345,
                "key": "TEST-001",
                "evidences": [{"id": 301, "fileName": "img.png"}],
            },
            {
                "id": 12346,
                "key": "TEST-002",
                "evidences": [],
            },
        ]
        results_mixin.xray.get_tests_with_test_execution.return_value = detailed

        output = results_mixin.get_test_execution_evidences("EXEC-001")

        assert output["execution_key"] == "EXEC-001"
        assert output["total_runs"] == 2
        assert output["total_evidences"] == 1
        assert output["evidences"][0]["run_id"] == 12345
        assert output["evidences"][0]["attachments"] == [{"id": 301, "fileName": "img.png"}]
        assert output["evidences"][1]["attachments"] == []

    def test_get_test_execution_evidences_falls_back_to_api(self, results_mixin):
        """When embedded evidences field is absent, get_test_run_evidences is called."""
        detailed = [{"id": 99, "key": "TEST-003"}]  # no 'evidences' key
        results_mixin.xray.get_tests_with_test_execution.return_value = detailed
        results_mixin.xray.resource_url.return_value = "url"
        results_mixin.xray.get.return_value = MOCK_XRAY_EVIDENCE_LIST

        output = results_mixin.get_test_execution_evidences("EXEC-002")

        assert output["total_evidences"] == len(MOCK_XRAY_EVIDENCE_LIST)
        results_mixin.xray.get.assert_called_once()

    def test_get_test_execution_evidences_empty_execution(self, results_mixin):
        """Empty execution returns zero runs and zero evidences."""
        results_mixin.xray.get_tests_with_test_execution.return_value = []

        output = results_mixin.get_test_execution_evidences("EXEC-EMPTY")

        assert output["total_runs"] == 0
        assert output["total_evidences"] == 0
        assert output["evidences"] == []

    def test_get_test_execution_evidences_forwards_pagination(self, results_mixin):
        """Pagination parameters are forwarded to get_tests_with_test_execution."""
        results_mixin.xray.get_tests_with_test_execution.return_value = []

        results_mixin.get_test_execution_evidences("EXEC-001", page=3, limit=20)

        results_mixin.xray.get_tests_with_test_execution.assert_called_once_with(
            "EXEC-001", detailed=True, page=3, limit=20
        )

    # ------------------------------------------------------------------ #
    # download_test_run_evidence                                           #
    # ------------------------------------------------------------------ #

    def test_download_test_run_evidence_returns_base64_when_no_path(
        self, results_mixin
    ):
        """When target_path is None, content is returned Base64-encoded."""
        file_content = b"hello\n"
        mock_response = MagicMock()
        mock_response.content = file_content
        mock_response.headers = {
            "Content-Type": "text/plain",
            "Content-Disposition": 'attachment; filename="log.txt"',
        }
        mock_response.raise_for_status = MagicMock()
        results_mixin.xray._session.get.return_value = mock_response
        results_mixin.xray.resource_url.return_value = "rest/raven/1.0/api/testrun/1/attachment/10"
        results_mixin.xray.url = "http://example.com"

        output = results_mixin.download_test_run_evidence(1, 10)

        assert output["run_id"] == 1
        assert output["attachment_id"] == 10
        assert output["file_name"] == "log.txt"
        assert output["content_type"] == "text/plain"
        assert output["size_bytes"] == len(file_content)
        assert output["saved_to"] is None
        assert output["content_base64"] == base64.b64encode(file_content).decode()

    def test_download_test_run_evidence_saves_to_disk(
        self, results_mixin, tmp_path
    ):
        """When target_path is provided, the file is saved and saved_to is set."""
        file_content = b"binary data"
        mock_response = MagicMock()
        mock_response.content = file_content
        mock_response.headers = {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "",
        }
        mock_response.raise_for_status = MagicMock()
        results_mixin.xray._session.get.return_value = mock_response
        results_mixin.xray.resource_url.return_value = "rest/raven/1.0/api/testrun/2/attachment/20"
        results_mixin.xray.url = "http://example.com"

        dest = str(tmp_path / "evidence.bin")
        output = results_mixin.download_test_run_evidence(2, 20, target_path=dest)

        assert output["saved_to"] == dest
        assert output["content_base64"] is None
        assert open(dest, "rb").read() == file_content

    def test_download_test_run_evidence_fallback_filename(self, results_mixin):
        """When Content-Disposition is absent, file_name falls back to attachment_{id}."""
        mock_response = MagicMock()
        mock_response.content = b"data"
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.raise_for_status = MagicMock()
        results_mixin.xray._session.get.return_value = mock_response
        results_mixin.xray.resource_url.return_value = "url"
        results_mixin.xray.url = "http://example.com"

        output = results_mixin.download_test_run_evidence(5, 99)

        assert output["file_name"] == "attachment_99"
