"""Xray FastMCP server instance and tool definitions."""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_atlassian.servers.dependencies import get_xray_fetcher
from mcp_atlassian.utils.decorators import check_write_access

logger = logging.getLogger(__name__)

xray_mcp = FastMCP(
    name="Xray MCP Service",
)


# Test Management Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_tests(
    ctx: Context,
    test_keys: Annotated[
        str,
        Field(
            description="Comma-separated list of test keys to retrieve (e.g., 'TEST-001,TEST-002')"
        ),
    ],
) -> str:
    """
    Retrieve information about the provided tests.

    Args:
        ctx: The FastMCP context.
        test_keys: Comma-separated list of test keys.

    Returns:
        JSON string representing the test information.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        test_list = [key.strip() for key in test_keys.split(",")]
        result = xray.xray.get_tests(test_list)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving tests {test_keys}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_statuses(ctx: Context) -> str:
    """
    Retrieve a list of all Test Statuses available in Xray sorted by rank.

    Args:
        ctx: The FastMCP context.

    Returns:
        JSON string representing the test statuses.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_statuses()
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test statuses: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_runs(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to retrieve test runs for (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Retrieve test runs of a test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test runs for.

    Returns:
        JSON string representing the test runs.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_runs(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test runs for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_runs_with_environment(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to retrieve test runs for (e.g., 'TEST-001')"),
    ],
    environments: Annotated[
        str,
        Field(
            description="Comma-separated list of environments to filter by (e.g., 'Android,iOS')"
        ),
    ],
) -> str:
    """
    Retrieve test runs of a test filtered by test environments.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test runs for.
        environments: Comma-separated list of environments.

    Returns:
        JSON string representing the filtered test runs.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_runs_with_environment(test_key, environments)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(
            f"Error retrieving test runs for {test_key} with environments {environments}: {e}"
        )
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_preconditions(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(
            description="The test key to retrieve preconditions for (e.g., 'TEST-001')"
        ),
    ],
) -> str:
    """
    Retrieve pre-conditions of a test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve preconditions for.

    Returns:
        JSON string representing the test preconditions.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_preconditions(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving preconditions for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_sets(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to retrieve test sets for (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Retrieve test sets associated with a test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test sets for.

    Returns:
        JSON string representing the test sets.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_sets(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test sets for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_executions(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(
            description="The test key to retrieve test executions for (e.g., 'TEST-001')"
        ),
    ],
) -> str:
    """
    Retrieve test executions of a test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test executions for.

    Returns:
        JSON string representing the test executions.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_executions(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test executions for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_plans(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to retrieve test plans for (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Retrieve test plans associated with a test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test plans for.

    Returns:
        JSON string representing the test plans.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_plans(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test plans for {test_key}: {e}")
        raise


# Test Steps Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_step_statuses(ctx: Context) -> str:
    """
    Retrieve the test step statuses available in Xray sorted by rank.

    Args:
        ctx: The FastMCP context.

    Returns:
        JSON string representing the test step statuses.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_step_statuses()
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test step statuses: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_step(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key (e.g., 'TEST-001')"),
    ],
    step_key: Annotated[
        str,
        Field(description="The test step key (e.g., 'STEP-001')"),
    ],
) -> str:
    """
    Retrieve the specified test step of a given test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key.
        step_key: The test step key.

    Returns:
        JSON string representing the test step information.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_step(test_key, step_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test step {step_key} for test {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_steps(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to retrieve test steps for (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Retrieve the test steps of a given test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to retrieve test steps for.

    Returns:
        JSON string representing the test steps.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_steps(test_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test steps for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def create_test_step(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key to create a test step for (e.g., 'TEST-001')"),
    ],
    step: Annotated[
        str,
        Field(description="The test step description"),
    ],
    data: Annotated[
        str,
        Field(description="The test data for this step"),
    ],
    result: Annotated[
        str,
        Field(description="The expected result for this step"),
    ],
) -> str:
    """
    Create a new test step for a given test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key to create a test step for.
        step: The test step description.
        data: The test data for this step.
        result: The expected result for this step.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result_data = xray.xray.create_test_step(test_key, step, data, result)
        return json.dumps(result_data, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error creating test step for {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_step(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key (e.g., 'TEST-001')"),
    ],
    step_id: Annotated[
        int,
        Field(description="The test step ID to update"),
    ],
    step: Annotated[
        str,
        Field(description="The updated test step description"),
    ],
    data: Annotated[
        str,
        Field(description="The updated test data"),
    ],
    result: Annotated[
        str,
        Field(description="The updated expected result"),
    ],
) -> str:
    """
    Update the specified test step for a given test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key.
        step_id: The test step ID to update.
        step: The updated test step description.
        data: The updated test data.
        result: The updated expected result.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result_data = xray.xray.update_test_step(test_key, step_id, step, data, result)
        return json.dumps(result_data, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating test step {step_id} for test {test_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_step(
    ctx: Context,
    test_key: Annotated[
        str,
        Field(description="The test key (e.g., 'TEST-001')"),
    ],
    step_id: Annotated[
        int,
        Field(description="The test step ID to delete"),
    ],
) -> str:
    """
    Remove the specified test step from a given test.

    Args:
        ctx: The FastMCP context.
        test_key: The test key.
        step_id: The test step ID to delete.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_step(test_key, step_id)
        return json.dumps(
            {
                "success": True,
                "message": f"Test step {step_id} deleted from {test_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(f"Error deleting test step {step_id} from test {test_key}: {e}")
        raise


# Pre-conditions Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_tests_with_precondition(
    ctx: Context,
    precondition_key: Annotated[
        str,
        Field(description="The precondition key (e.g., 'PREC-001')"),
    ],
) -> str:
    """
    Retrieve the tests associated with the given pre-condition.

    Args:
        ctx: The FastMCP context.
        precondition_key: The precondition key.

    Returns:
        JSON string representing the tests associated with the precondition.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_tests_with_precondition(precondition_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(
            f"Error retrieving tests with precondition {precondition_key}: {e}"
        )
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_precondition(
    ctx: Context,
    precondition_key: Annotated[
        str,
        Field(description="The precondition key (e.g., 'PREC-001')"),
    ],
    add_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to add (e.g., 'TEST-001,TEST-002')",
            default=None,
        ),
    ] = None,
    remove_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to remove (e.g., 'TEST-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Associate tests with the given pre-condition.

    Args:
        ctx: The FastMCP context.
        precondition_key: The precondition key.
        add_tests: Optional comma-separated list of test keys to add.
        remove_tests: Optional comma-separated list of test keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = [key.strip() for key in add_tests.split(",")] if add_tests else []
        remove_list = (
            [key.strip() for key in remove_tests.split(",")] if remove_tests else []
        )

        result = xray.xray.update_precondition(
            precondition_key, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating precondition {precondition_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_from_precondition(
    ctx: Context,
    precondition_key: Annotated[
        str,
        Field(description="The precondition key (e.g., 'PREC-001')"),
    ],
    test_key: Annotated[
        str,
        Field(description="The test key to remove (e.g., 'TEST-003')"),
    ],
) -> str:
    """
    Remove association of the specified test from the given pre-condition.

    Args:
        ctx: The FastMCP context.
        precondition_key: The precondition key.
        test_key: The test key to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_from_precondition(precondition_key, test_key)
        return json.dumps(
            {
                "success": True,
                "message": f"Test {test_key} removed from precondition {precondition_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(
            f"Error removing test {test_key} from precondition {precondition_key}: {e}"
        )
        raise


# Test Sets Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_tests_with_test_set(
    ctx: Context,
    test_set_key: Annotated[
        str,
        Field(description="The test set key (e.g., 'SET-001')"),
    ],
    page: Annotated[
        int,
        Field(description="Page number for pagination (default: 1)", default=1),
    ] = 1,
    limit: Annotated[
        int,
        Field(
            description="Maximum number of results per page (default: 10)", default=10
        ),
    ] = 10,
) -> str:
    """
    Retrieve the tests associated with the given test set.

    Args:
        ctx: The FastMCP context.
        test_set_key: The test set key.
        page: Page number for pagination.
        limit: Maximum number of results per page.

    Returns:
        JSON string representing the tests associated with the test set.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_tests_with_test_set(test_set_key, page=page, limit=limit)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving tests with test set {test_set_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_set(
    ctx: Context,
    test_set_key: Annotated[
        str,
        Field(description="The test set key (e.g., 'SET-001')"),
    ],
    add_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to add (e.g., 'TEST-001,TEST-002')",
            default=None,
        ),
    ] = None,
    remove_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to remove (e.g., 'TEST-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Associate tests with the given test set.

    Args:
        ctx: The FastMCP context.
        test_set_key: The test set key.
        add_tests: Optional comma-separated list of test keys to add.
        remove_tests: Optional comma-separated list of test keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = [key.strip() for key in add_tests.split(",")] if add_tests else []
        remove_list = (
            [key.strip() for key in remove_tests.split(",")] if remove_tests else []
        )

        result = xray.xray.update_test_set(
            test_set_key, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating test set {test_set_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_from_test_set(
    ctx: Context,
    test_set_key: Annotated[
        str,
        Field(description="The test set key (e.g., 'SET-001')"),
    ],
    test_key: Annotated[
        str,
        Field(description="The test key to remove (e.g., 'TEST-003')"),
    ],
) -> str:
    """
    Remove association of the specified test from the given test set.

    Args:
        ctx: The FastMCP context.
        test_set_key: The test set key.
        test_key: The test key to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_from_test_set(test_set_key, test_key)
        return json.dumps(
            {
                "success": True,
                "message": f"Test {test_key} removed from test set {test_set_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(
            f"Error removing test {test_key} from test set {test_set_key}: {e}"
        )
        raise


# Test Plans Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_tests_with_test_plan(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
) -> str:
    """
    Retrieve the tests associated with the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.

    Returns:
        JSON string representing the tests associated with the test plan.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_tests_with_test_plan(test_plan_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving tests with test plan {test_plan_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_plan(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
    add_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to add (e.g., 'TEST-001,TEST-002')",
            default=None,
        ),
    ] = None,
    remove_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to remove (e.g., 'TEST-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Associate tests with the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.
        add_tests: Optional comma-separated list of test keys to add.
        remove_tests: Optional comma-separated list of test keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = [key.strip() for key in add_tests.split(",")] if add_tests else []
        remove_list = (
            [key.strip() for key in remove_tests.split(",")] if remove_tests else []
        )

        result = xray.xray.update_test_plan(
            test_plan_key, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating test plan {test_plan_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_from_test_plan(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
    test_key: Annotated[
        str,
        Field(description="The test key to remove (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Remove association of the specified test from the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.
        test_key: The test key to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_from_test_plan(test_plan_key, test_key)
        return json.dumps(
            {
                "success": True,
                "message": f"Test {test_key} removed from test plan {test_plan_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(
            f"Error removing test {test_key} from test plan {test_plan_key}: {e}"
        )
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_executions_with_test_plan(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
) -> str:
    """
    Retrieve the test executions associated with the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.

    Returns:
        JSON string representing the test executions associated with the test plan.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_executions_with_test_plan(test_plan_key)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(
            f"Error retrieving test executions with test plan {test_plan_key}: {e}"
        )
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_plan_test_executions(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
    add_executions: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test execution keys to add (e.g., 'EXEC-001,EXEC-002')",
            default=None,
        ),
    ] = None,
    remove_executions: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test execution keys to remove (e.g., 'EXEC-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Associate test executions with the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.
        add_executions: Optional comma-separated list of test execution keys to add.
        remove_executions: Optional comma-separated list of test execution keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = (
            [key.strip() for key in add_executions.split(",")] if add_executions else []
        )
        remove_list = (
            [key.strip() for key in remove_executions.split(",")]
            if remove_executions
            else []
        )

        result = xray.xray.update_test_plan_test_executions(
            test_plan_key, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating test plan test executions {test_plan_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_execution_from_test_plan(
    ctx: Context,
    test_plan_key: Annotated[
        str,
        Field(description="The test plan key (e.g., 'PLAN-001')"),
    ],
    execution_key: Annotated[
        str,
        Field(description="The test execution key to remove (e.g., 'EXEC-001')"),
    ],
) -> str:
    """
    Remove association of the specified test execution from the given test plan.

    Args:
        ctx: The FastMCP context.
        test_plan_key: The test plan key.
        execution_key: The test execution key to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_execution_from_test_plan(
            test_plan_key, execution_key
        )
        return json.dumps(
            {
                "success": True,
                "message": f"Test execution {execution_key} removed from test plan {test_plan_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(
            f"Error removing test execution {execution_key} from test plan {test_plan_key}: {e}"
        )
        raise


# Test Executions Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_tests_with_test_execution(
    ctx: Context,
    execution_key: Annotated[
        str,
        Field(description="The test execution key (e.g., 'EXEC-001')"),
    ],
    detailed: Annotated[
        bool,
        Field(
            description="Whether to include detailed information (default: True)",
            default=True,
        ),
    ] = True,
    page: Annotated[
        int,
        Field(description="Page number for pagination (default: 1)", default=1),
    ] = 1,
    limit: Annotated[
        int,
        Field(
            description="Maximum number of results per page (default: 10)", default=10
        ),
    ] = 10,
) -> str:
    """
    Retrieve the tests associated with the given test execution.

    Args:
        ctx: The FastMCP context.
        execution_key: The test execution key.
        detailed: Whether to include detailed information.
        page: Page number for pagination.
        limit: Maximum number of results per page.

    Returns:
        JSON string representing the tests associated with the test execution.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_tests_with_test_execution(
            execution_key, detailed=detailed, page=page, limit=limit
        )
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving tests with test execution {execution_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_execution(
    ctx: Context,
    execution_key: Annotated[
        str,
        Field(description="The test execution key (e.g., 'EXEC-001')"),
    ],
    add_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to add (e.g., 'TEST-001,TEST-002')",
            default=None,
        ),
    ] = None,
    remove_tests: Annotated[
        str | None,
        Field(
            description="Comma-separated list of test keys to remove (e.g., 'TEST-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Associate tests with the given test execution.

    Args:
        ctx: The FastMCP context.
        execution_key: The test execution key.
        add_tests: Optional comma-separated list of test keys to add.
        remove_tests: Optional comma-separated list of test keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = [key.strip() for key in add_tests.split(",")] if add_tests else []
        remove_list = (
            [key.strip() for key in remove_tests.split(",")] if remove_tests else []
        )

        result = xray.xray.update_test_execution(
            execution_key, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating test execution {execution_key}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def delete_test_from_test_execution(
    ctx: Context,
    execution_key: Annotated[
        str,
        Field(description="The test execution key (e.g., 'EXEC-001')"),
    ],
    test_key: Annotated[
        str,
        Field(description="The test key to remove (e.g., 'TEST-001')"),
    ],
) -> str:
    """
    Remove association of the specified test from the given test execution.

    Args:
        ctx: The FastMCP context.
        execution_key: The test execution key.
        test_key: The test key to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.delete_test_from_test_execution(execution_key, test_key)
        return json.dumps(
            {
                "success": True,
                "message": f"Test {test_key} removed from test execution {execution_key}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(
            f"Error removing test {test_key} from test execution {execution_key}: {e}"
        )
        raise


# Test Runs Tools


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve detailed information about the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run information.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_assignee(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve the assignee for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run assignee.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_assignee(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving assignee for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_run_assignee(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
    assignee: Annotated[
        str,
        Field(description="The username of the new assignee (e.g., 'bob')"),
    ],
) -> str:
    """
    Update the assignee for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.
        assignee: The username of the new assignee.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.update_test_run_assignee(test_run_id, assignee)
        return json.dumps(
            {
                "success": True,
                "message": f"Test run {test_run_id} assignee updated to {assignee}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(f"Error updating assignee for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_iteration(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
    iteration_id: Annotated[
        int,
        Field(description="The iteration ID"),
    ],
) -> str:
    """
    Retrieve a specific iteration of the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.
        iteration_id: The iteration ID.

    Returns:
        JSON string representing the test run iteration.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_iteration(test_run_id, iteration_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(
            f"Error retrieving iteration {iteration_id} for test run {test_run_id}: {e}"
        )
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_status(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve the status for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run status.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_status(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving status for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_run_status(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
    status: Annotated[
        str,
        Field(description="The new status (e.g., 'PASS', 'FAIL', 'TODO', 'EXECUTING')"),
    ],
) -> str:
    """
    Update the status for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.
        status: The new status.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.update_test_run_status(test_run_id, status)
        return json.dumps(
            {
                "success": True,
                "message": f"Test run {test_run_id} status updated to {status}",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(f"Error updating status for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_defects(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve the defects for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run defects.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_defects(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving defects for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_run_defects(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
    add_defects: Annotated[
        str | None,
        Field(
            description="Comma-separated list of defect keys to add (e.g., 'BUG-001,BUG-002')",
            default=None,
        ),
    ] = None,
    remove_defects: Annotated[
        str | None,
        Field(
            description="Comma-separated list of defect keys to remove (e.g., 'BUG-003')",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Update the defects associated with the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.
        add_defects: Optional comma-separated list of defect keys to add.
        remove_defects: Optional comma-separated list of defect keys to remove.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        add_list = (
            [key.strip() for key in add_defects.split(",")] if add_defects else []
        )
        remove_list = (
            [key.strip() for key in remove_defects.split(",")] if remove_defects else []
        )

        result = xray.xray.update_test_run_defects(
            test_run_id, add=add_list, remove=remove_list
        )
        return json.dumps({"success": True, "data": result}, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error updating defects for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_comment(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve the comment for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run comment.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_comment(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving comment for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "write"})
@check_write_access
async def update_test_run_comment(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
    comment: Annotated[
        str,
        Field(description="The new comment for the test run"),
    ],
) -> str:
    """
    Update the comment for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.
        comment: The new comment.

    Returns:
        JSON string indicating success or failure.

    Raises:
        ValueError: If in read-only mode or Xray client unavailable.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.update_test_run_comment(test_run_id, comment)
        return json.dumps(
            {"success": True, "message": f"Test run {test_run_id} comment updated"},
            indent=2,
            default=str,
        )
    except Exception as e:
        logger.error(f"Error updating comment for test run {test_run_id}: {e}")
        raise


@xray_mcp.tool(tags={"xray", "read"})
async def get_test_run_steps(
    ctx: Context,
    test_run_id: Annotated[
        int,
        Field(description="The test run ID"),
    ],
) -> str:
    """
    Retrieve the steps for the given test run.

    Args:
        ctx: The FastMCP context.
        test_run_id: The test run ID.

    Returns:
        JSON string representing the test run steps.

    Raises:
        ValueError: If the Xray client is not configured or available.
    """
    xray = await get_xray_fetcher(ctx)
    try:
        result = xray.xray.get_test_run_steps(test_run_id)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error retrieving steps for test run {test_run_id}: {e}")
        raise
