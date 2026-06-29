"""Test results mixin for Xray API interactions."""

import base64
import logging
import os
from typing import Any

from .client import XrayClient

logger = logging.getLogger(__name__)


class MixTestResults(XrayClient):
    """Mixin for Xray test result retrieval operations."""

    def get_test_execution_results(
        self,
        execution_key: str,
        page: int = 1,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve enriched test results for a test execution.

        Fetches all tests in the execution with their detailed run information
        (status, assignee, defects, run ID) in a single structured response.

        Args:
            execution_key: The test execution issue key (e.g., 'EXEC-001').
            page: Page number for pagination (1-based).
            limit: Maximum number of results per page.

        Returns:
            dict containing:
                - execution_key: The execution key provided.
                - page: Current page number.
                - limit: Page size.
                - total: Number of results returned.
                - results: List of test result dicts with keys
                  ``test_key``, ``run_id``, ``status``, ``assignee``,
                  ``defects``, ``started_on``, ``comment``.
        """
        raw = self.xray.get_tests_with_test_execution(
            execution_key,
            detailed=True,
            page=page,
            limit=limit,
        )

        tests: list[Any] = raw if isinstance(raw, list) else []
        results: list[dict[str, Any]] = []
        for test in tests:
            results.append(
                {
                    "test_key": test.get("key") or test.get("testKey"),
                    "run_id": test.get("id"),
                    "status": test.get("status"),
                    "assignee": test.get("assignee"),
                    "defects": test.get("defects", []),
                    "started_on": test.get("startedOn") or test.get("startedOnIso"),
                    "comment": test.get("comment"),
                }
            )

        return {
            "execution_key": execution_key,
            "page": page,
            "limit": limit,
            "total": len(results),
            "results": results,
        }

    def get_test_run_full_results(self, test_run_id: int) -> dict[str, Any]:
        """Retrieve comprehensive results for a single test run.

        Aggregates status, assignee, comment, defects, and step-level
        results into one structured response.

        Args:
            test_run_id: The numeric ID of the test run.

        Returns:
            dict containing:
                - run_id: The test run ID.
                - status: Overall run status string.
                - assignee: Username of the assignee.
                - comment: Comment on the test run.
                - defects: List of defect keys linked to the run.
                - steps: List of step result objects.
                - details: Full raw test run object from the API.
        """
        details = self.xray.get_test_run(test_run_id)
        status = self.xray.get_test_run_status(test_run_id)
        assignee = self.xray.get_test_run_assignee(test_run_id)
        comment = self.xray.get_test_run_comment(test_run_id)
        defects = self.xray.get_test_run_defects(test_run_id)
        steps = self.xray.get_test_run_steps(test_run_id)

        return {
            "run_id": test_run_id,
            "status": status,
            "assignee": assignee,
            "comment": comment,
            "defects": defects if isinstance(defects, list) else [],
            "steps": steps if isinstance(steps, list) else [],
            "details": details,
        }

    # ------------------------------------------------------------------ #
    # Evidence / attachment helpers                                        #
    # ------------------------------------------------------------------ #

    def get_test_run_evidences(self, test_run_id: int) -> list[dict[str, Any]]:
        """Retrieve all evidence (attachment) metadata for a test run.

        Calls the Xray REST endpoint ``testrun/{id}/attachment`` to list
        every file attached as evidence to the run.

        Args:
            test_run_id: The numeric ID of the test run.

        Returns:
            List of evidence dicts. Each entry contains at minimum:
            ``id``, ``fileName``, ``fileSize``, ``fileURL``,
            ``contentType``, and ``created``.
        """
        url = self.xray.resource_url(f"testrun/{test_run_id}/attachment")
        result = self.xray.get(url)
        return result if isinstance(result, list) else []

    def get_test_execution_evidences(
        self,
        execution_key: str,
        page: int = 1,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve all evidence attachments across every test run in an execution.

        Fetches the test runs for the execution, then collects evidence
        metadata from each run in a single aggregated response.

        Args:
            execution_key: The test execution issue key (e.g., 'EXEC-001').
            page: Page number passed to the test-execution listing.
            limit: Maximum number of test runs to inspect per page.

        Returns:
            dict containing:
                - execution_key: The execution key provided.
                - total_runs: Number of test runs inspected.
                - total_evidences: Total evidence files found across all runs.
                - evidences: List of dicts, each with ``run_id``, ``test_key``,
                  and ``attachments`` (list of evidence metadata objects).
        """
        raw = self.xray.get_tests_with_test_execution(
            execution_key,
            detailed=True,
            page=page,
            limit=limit,
        )
        tests: list[Any] = raw if isinstance(raw, list) else []

        evidence_rows: list[dict[str, Any]] = []
        total_evidences = 0

        for test in tests:
            run_id = test.get("id")
            test_key = test.get("key") or test.get("testKey")

            # Prefer the evidences already embedded in the detailed response;
            # fall back to a dedicated API call so we always get fresh data.
            embedded: list[Any] = test.get("evidences") or []
            if embedded:
                attachments = embedded
            elif run_id is not None:
                attachments = self.get_test_run_evidences(run_id)
            else:
                attachments = []

            total_evidences += len(attachments)
            evidence_rows.append(
                {
                    "run_id": run_id,
                    "test_key": test_key,
                    "attachments": attachments,
                }
            )

        return {
            "execution_key": execution_key,
            "total_runs": len(evidence_rows),
            "total_evidences": total_evidences,
            "evidences": evidence_rows,
        }

    def download_test_run_evidence(
        self,
        test_run_id: int,
        attachment_id: int,
        target_path: str | None = None,
    ) -> dict[str, Any]:
        """Download a specific evidence file from a test run.

        Fetches the raw file bytes using the Xray session and either saves
        the file to *target_path* or returns the content as a Base64 string.

        Args:
            test_run_id: The numeric ID of the test run.
            attachment_id: The numeric ID of the evidence attachment.
            target_path: Optional filesystem path to save the file. When
                ``None`` (default) the content is returned Base64-encoded.

        Returns:
            dict containing:
                - attachment_id: The evidence attachment ID.
                - run_id: The test run ID.
                - file_name: File name from the Content-Disposition header
                  (or ``attachment_{id}`` if unavailable).
                - content_type: MIME type from the response headers.
                - size_bytes: Size of the downloaded content.
                - saved_to: Absolute path if saved to disk, else ``None``.
                - content_base64: Base64-encoded file content when *target_path*
                  is ``None``, else ``None``.
        """
        url = self.xray.resource_url(
            f"testrun/{test_run_id}/attachment/{attachment_id}"
        )
        response = self.xray._session.get(
            f"{self.xray.url}/{url}", stream=True
        )
        response.raise_for_status()

        content = response.content
        content_type = response.headers.get("Content-Type", "application/octet-stream")

        # Extract file name from Content-Disposition or fall back gracefully
        disposition = response.headers.get("Content-Disposition", "")
        file_name = f"attachment_{attachment_id}"
        for part in disposition.split(";"):
            part = part.strip()
            if part.startswith("filename="):
                file_name = part.split("=", 1)[1].strip().strip('"')
                break

        saved_to: str | None = None
        content_base64: str | None = None

        if target_path:
            abs_path = os.path.abspath(target_path)
            os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
            with open(abs_path, "wb") as fh:
                fh.write(content)
            saved_to = abs_path
            logger.info(
                "Evidence %s from test run %s saved to %s (%d bytes)",
                attachment_id,
                test_run_id,
                abs_path,
                len(content),
            )
        else:
            content_base64 = base64.b64encode(content).decode("ascii")

        return {
            "attachment_id": attachment_id,
            "run_id": test_run_id,
            "file_name": file_name,
            "content_type": content_type,
            "size_bytes": len(content),
            "saved_to": saved_to,
            "content_base64": content_base64,
        }
