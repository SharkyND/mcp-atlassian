"""Mock data for Xray API responses used in unit tests."""

# Mock Test Data - Updated to match real API structure
MOCK_XRAY_TEST_RESPONSE = {
    "key": "TEST-001",
    "id": 10001,
    "self": "http://example.com/rest/api/2/issue/10001",
    "reporter": "test-user",
    "precondition": [],
    "type": "Manual",
    "status": "TODO",
    "archived": False,
    "definition": {
        "steps": [
            {
                "id": 1001,
                "index": 1,
                "step": {
                    "raw": "Open the application",
                    "rendered": "<p>Open the application</p>",
                },
                "data": {
                    "raw": "Navigate to application URL",
                    "rendered": "<p>Navigate to application URL</p>",
                },
                "result": {
                    "raw": "Application should load successfully",
                    "rendered": "<p>Application should load successfully</p>",
                },
                "attachments": [],
            },
            {
                "id": 1002,
                "index": 2,
                "step": {
                    "raw": "Login with valid credentials",
                    "rendered": "<p>Login with valid credentials</p>",
                },
                "data": {
                    "raw": "Username: test@example.com, Password: testpass",
                    "rendered": "<p>Username: test@example.com, Password: testpass</p>",
                },
                "result": {
                    "raw": "User should be logged in successfully",
                    "rendered": "<p>User should be logged in successfully</p>",
                },
                "attachments": [],
            },
        ]
    },
}

MOCK_XRAY_TESTS_RESPONSE = [
    {
        "key": "TEST-001",
        "id": 10001,
        "self": "http://example.com/rest/api/2/issue/10001",
        "reporter": "test-user",
        "precondition": [],
        "type": "Manual",
        "status": "TODO",
        "archived": False,
    },
    {
        "key": "TEST-002",
        "id": 10002,
        "self": "http://example.com/rest/api/2/issue/10002",
        "reporter": "test-user-2",
        "precondition": [],
        "type": "Automated",
        "status": "PASS",
        "archived": False,
    },
]

# Mock Test Run Data - Updated with real API structure
MOCK_XRAY_TEST_RUN_RESPONSE = {
    "id": 12345,
    "status": "PASS",
    "color": "#95C160",
    "testKey": "TEST-001",
    "testExecKey": "EXEC-001",
    "assignee": "test-user",
    "startedOn": "2024-01-15T10:00:00-05:00",
    "startedOnIso": "2024-01-15T10:00:00-05:00",
    "defects": [],
    "evidences": [],
    "comment": "Test executed successfully",
    "testEnvironments": [],
    "fixVersions": [],
    "archived": False,
    "testVersion": "v1",
    "steps": [
        {
            "id": 1001,
            "index": 1,
            "step": {
                "raw": "Open the application",
                "rendered": "<p>Open the application</p>",
            },
            "data": {
                "raw": "Navigate to application URL",
                "rendered": "<p>Navigate to application URL</p>",
            },
            "result": {
                "raw": "Application should load successfully",
                "rendered": "<p>Application should load successfully</p>",
            },
            "attachments": [],
            "status": "PASS",
            "comment": {"rendered": "Step completed successfully"},
            "defects": [],
            "evidences": [],
            "actualResult": {"rendered": "Application loaded successfully"},
        }
    ],
}

MOCK_XRAY_TEST_RUNS_RESPONSE = [
    {
        "id": 12345,
        "status": "PASS",
        "color": "#95C160",
        "testKey": "TEST-001",
        "testExecKey": "EXEC-001",
        "assignee": "test-user",
        "startedOn": "2024-01-15T10:00:00-05:00",
        "startedOnIso": "2024-01-15T10:00:00-05:00",
        "defects": [],
        "evidences": [],
        "comment": "Test executed successfully",
        "testEnvironments": [],
        "fixVersions": [],
        "archived": False,
        "testVersion": "v1",
        "steps": [],
    },
    {
        "id": 12346,
        "status": "FAIL",
        "color": "#D45D52",
        "testKey": "TEST-002",
        "testExecKey": "EXEC-001",
        "assignee": "test-user-2",
        "startedOn": "2024-01-16T10:00:00-05:00",
        "startedOnIso": "2024-01-16T10:00:00-05:00",
        "defects": ["BUG-001"],
        "evidences": [],
        "comment": "Test failed with error",
        "testEnvironments": [],
        "fixVersions": [],
        "archived": False,
        "testVersion": "v1",
        "steps": [],
    },
]

# Mock Test Status Data - Updated with real API response
MOCK_XRAY_TEST_STATUSES_RESPONSE = [
    {
        "id": 0,
        "rank": 0,
        "name": "PASS",
        "description": "The test run/iteration has passed",
        "color": "#95C160",
        "requirementStatusName": "OK",
        "final": True,
    },
    {
        "id": 1,
        "rank": 1,
        "name": "TODO",
        "description": "The test run/iteration has not started",
        "color": "#A2A6AE",
        "requirementStatusName": "NOTRUN",
        "final": False,
    },
    {
        "id": 2,
        "rank": 2,
        "name": "EXECUTING",
        "description": "The test run/iteration is currently being executed",
        "color": "#F1E069",
        "requirementStatusName": "NOTRUN",
        "final": False,
    },
    {
        "id": 3,
        "rank": 3,
        "name": "FAIL",
        "description": "The test run/iteration has failed",
        "color": "#D45D52",
        "requirementStatusName": "NOK",
        "final": True,
    },
    {
        "id": 4,
        "rank": 4,
        "name": "ABORTED",
        "description": "The test run/iteration was aborted",
        "color": "#111111",
        "requirementStatusName": "NOTRUN",
        "final": True,
    },
    {
        "id": 1000,
        "rank": 5,
        "name": "NA",
        "description": "Not applicable",
        "color": "#37D637",
        "requirementStatusName": "OK",
        "final": True,
    },
]

# Mock Test Step Status Data - Updated with real API response
MOCK_XRAY_TEST_STEP_STATUSES_RESPONSE = [
    {
        "id": 0,
        "rank": 0,
        "name": "PASS",
        "description": "The test step has passed",
        "testStatusId": 0,
        "color": "#95C160",
    },
    {
        "id": 1,
        "rank": 1,
        "name": "TODO",
        "description": "The test step has not started",
        "testStatusId": 1,
        "color": "#A2A6AE",
    },
    {
        "id": 2,
        "rank": 2,
        "name": "EXECUTING",
        "description": "The test step is currently being executed",
        "testStatusId": 2,
        "color": "#F1E069",
    },
    {
        "id": 3,
        "rank": 3,
        "name": "FAIL",
        "description": "The test step has failed",
        "testStatusId": 3,
        "color": "#D45D52",
    },
    {
        "id": 1000,
        "rank": 4,
        "name": "NA",
        "description": "Not Applicable",
        "testStatusId": 0,
        "color": "#37D637",
    },
]

# Mock Test Steps Data - Updated to match real API structure
MOCK_XRAY_TEST_STEPS_RESPONSE = [
    {
        "id": 1001,
        "index": 1,
        "step": {
            "raw": "Open the application",
            "rendered": "<p>Open the application</p>",
        },
        "data": {
            "raw": "Navigate to application URL",
            "rendered": "<p>Navigate to application URL</p>",
        },
        "result": {
            "raw": "Application should load successfully",
            "rendered": "<p>Application should load successfully</p>",
        },
        "attachments": [],
    },
    {
        "id": 1002,
        "index": 2,
        "step": {
            "raw": "Login with valid credentials",
            "rendered": "<p>Login with valid credentials</p>",
        },
        "data": {
            "raw": "Username: test@example.com, Password: testpass",
            "rendered": "<p>Username: test@example.com, Password: testpass</p>",
        },
        "result": {
            "raw": "User should be logged in successfully",
            "rendered": "<p>User should be logged in successfully</p>",
        },
        "attachments": [],
    },
]

# Mock Test Step Data - Updated to match real API structure
MOCK_XRAY_TEST_STEP_RESPONSE = {
    "id": 1001,
    "index": 1,
    "step": {"raw": "Open the application", "rendered": "<p>Open the application</p>"},
    "data": {
        "raw": "Navigate to application URL",
        "rendered": "<p>Navigate to application URL</p>",
    },
    "result": {
        "raw": "Application should load successfully",
        "rendered": "<p>Application should load successfully</p>",
    },
    "attachments": [],
}

# Mock Precondition Data
MOCK_XRAY_PRECONDITIONS_RESPONSE = [
    {
        "key": "PREC-001",
        "id": 20001,
        "summary": "Database Setup Precondition",
        "description": "Ensure test database is properly configured",
    },
    {
        "key": "PREC-002",
        "id": 20002,
        "summary": "User Account Precondition",
        "description": "Ensure test user accounts exist",
    },
]

MOCK_XRAY_TESTS_WITH_PRECONDITION_RESPONSE = [
    {
        "key": "TEST-001",
        "summary": "Test Case 1 with Precondition",
        "status": {"name": "TODO", "id": 1},
    },
    {
        "key": "TEST-002",
        "summary": "Test Case 2 with Precondition",
        "status": {"name": "PASS", "id": 0},
    },
]

# Mock Test Set Data
MOCK_XRAY_TEST_SETS_RESPONSE = [
    {
        "key": "SET-001",
        "id": 30001,
        "summary": "Smoke Test Set",
        "description": "Critical smoke tests for the application",
    },
    {
        "key": "SET-002",
        "id": 30002,
        "summary": "Regression Test Set",
        "description": "Full regression test suite",
    },
]

MOCK_XRAY_TESTS_WITH_TEST_SET_RESPONSE = {
    "total": 2,
    "start": 0,
    "limit": 10,
    "tests": [
        {
            "key": "TEST-001",
            "summary": "Test in Set 1",
            "status": {"name": "TODO", "id": 1},
        },
        {
            "key": "TEST-002",
            "summary": "Test in Set 2",
            "status": {"name": "PASS", "id": 0},
        },
    ],
}

# Mock Test Plan Data - Updated with real API structure
MOCK_XRAY_TEST_PLANS_RESPONSE = [
    {
        "id": 40001,
        "key": "PLAN-001",
        "summary": "Sprint 1 Test Plan",
        "self": "http://example.com/rest/api/2/issue/40001",
        "archived": False,
    }
]

MOCK_XRAY_TESTS_WITH_TEST_PLAN_RESPONSE = [
    {"id": 10001, "key": "TEST-001", "latestStatus": "TODO", "archived": False},
    {"id": 10003, "key": "TEST-003", "latestStatus": "EXECUTING", "archived": False},
]

# Mock Test Execution Data - Updated with real API structure
MOCK_XRAY_TEST_EXECUTIONS_RESPONSE = [
    {
        "id": 50001,
        "key": "EXEC-001",
        "summary": "Sprint 1 Test Execution",
        "self": "http://example.com/rest/api/2/issue/50001",
        "testEnvironments": [],
        "archived": False,
    }
]

MOCK_XRAY_TESTS_WITH_TEST_EXECUTION_RESPONSE = [
    {
        "id": 12345,
        "status": "PASS",
        "assignee": "test-user",
        "startedOn": "2024-01-15T10:00:00-05:00",
        "defects": [],
        "evidences": [],
        "comment": "Test executed successfully",
        "archived": False,
        "key": "TEST-001",
        "rank": 1,
    },
    {
        "id": 12346,
        "status": "FAIL",
        "assignee": "test-user-2",
        "startedOn": "2024-01-16T10:00:00-05:00",
        "defects": ["BUG-001"],
        "evidences": [],
        "comment": "Test failed with error",
        "archived": False,
        "key": "TEST-002",
        "rank": 2,
    },
]

MOCK_XRAY_TEST_EXECUTIONS_WITH_TEST_PLAN_RESPONSE = [
    {
        "id": 50001,
        "key": "EXEC-001",
        "summary": "Execution for Plan 1",
        "self": "http://example.com/rest/api/2/issue/50001",
        "testEnvironments": [],
        "archived": False,
    },
    {
        "id": 50002,
        "key": "EXEC-002",
        "summary": "Execution for Plan 2",
        "self": "http://example.com/rest/api/2/issue/50002",
        "testEnvironments": [],
        "archived": False,
    },
]

# Mock data for test results tools (get_test_runs_in_context)
MOCK_XRAY_TEST_RUNS_IN_CONTEXT_RESPONSE = [
    {
        "id": 12345,
        "status": "PASS",
        "color": "#95C160",
        "testKey": "TEST-001",
        "testExecKey": "EXEC-001",
        "assignee": "test-user",
        "startedOn": "2024-01-15T10:00:00-05:00",
        "startedOnIso": "2024-01-15T10:00:00-05:00",
        "defects": [],
        "comment": "Test executed successfully",
        "steps": [
            {
                "id": 1001,
                "index": 1,
                "status": "PASS",
                "comment": {"rendered": "Step passed"},
                "actualResult": {"rendered": "Application loaded"},
            }
        ],
    },
    {
        "id": 12346,
        "status": "FAIL",
        "color": "#D45D52",
        "testKey": "TEST-002",
        "testExecKey": "EXEC-001",
        "assignee": "test-user-2",
        "startedOn": "2024-01-16T10:00:00-05:00",
        "startedOnIso": "2024-01-16T10:00:00-05:00",
        "defects": ["BUG-001"],
        "comment": "Test failed",
        "steps": [
            {
                "id": 1002,
                "index": 1,
                "status": "FAIL",
                "comment": {"rendered": "Step failed"},
                "actualResult": {"rendered": "Error occurred"},
            }
        ],
    },
]

# Mock detailed test execution result items (from get_tests_with_test_execution detailed=True)
MOCK_XRAY_TEST_EXECUTION_DETAILED_RESPONSE = [
    {
        "id": 12345,
        "key": "TEST-001",
        "status": "PASS",
        "assignee": "test-user",
        "defects": [],
        "startedOn": "2024-01-15T10:00:00-05:00",
        "comment": "Test executed successfully",
    },
    {
        "id": 12346,
        "key": "TEST-002",
        "status": "FAIL",
        "assignee": "test-user-2",
        "defects": ["BUG-001"],
        "startedOn": "2024-01-16T10:00:00-05:00",
        "comment": "Test failed with error",
    },
    {
        "id": 12347,
        "key": "TEST-003",
        "status": "TODO",
        "assignee": None,
        "defects": [],
        "startedOn": None,
        "comment": None,
    },
]

# Mock full test run results (combined status + steps + defects + comment + assignee)
MOCK_XRAY_TEST_RUN_FULL_RESULTS = {
    "run_id": 12345,
    "status": "PASS",
    "assignee": "test-user",
    "comment": "Test executed successfully",
    "defects": [],
    "steps": [
        {
            "id": 1001,
            "index": 1,
            "status": "PASS",
            "comment": {"rendered": "Step passed"},
            "actualResult": {"rendered": "Application loaded successfully"},
        }
    ],
    "details": MOCK_XRAY_TEST_RUN_RESPONSE,
}

# Mock evidence / attachment data returned by testrun/{id}/attachment
MOCK_XRAY_EVIDENCE_LIST = [
    {
        "id": 301,
        "fileName": "screenshot_pass.png",
        "fileSize": 45678,
        "fileURL": "http://example.com/rest/raven/1.0/api/testrun/12345/attachment/301",
        "contentType": "image/png",
        "created": "2024-01-15T10:05:00-05:00",
    },
    {
        "id": 302,
        "fileName": "log_output.txt",
        "fileSize": 1234,
        "fileURL": "http://example.com/rest/raven/1.0/api/testrun/12345/attachment/302",
        "contentType": "text/plain",
        "created": "2024-01-15T10:06:00-05:00",
    },
]

MOCK_XRAY_EVIDENCE_LIST_EMPTY: list = []

# Mock aggregated evidences for a test execution
MOCK_XRAY_TEST_EXECUTION_EVIDENCES = {
    "execution_key": "EXEC-001",
    "total_runs": 2,
    "total_evidences": 3,
    "evidences": [
        {
            "run_id": 12345,
            "test_key": "TEST-001",
            "attachments": [
                {
                    "id": 301,
                    "fileName": "screenshot_pass.png",
                    "fileSize": 45678,
                    "fileURL": "http://example.com/rest/raven/1.0/api/testrun/12345/attachment/301",
                    "contentType": "image/png",
                    "created": "2024-01-15T10:05:00-05:00",
                },
                {
                    "id": 302,
                    "fileName": "log_output.txt",
                    "fileSize": 1234,
                    "fileURL": "http://example.com/rest/raven/1.0/api/testrun/12345/attachment/302",
                    "contentType": "text/plain",
                    "created": "2024-01-15T10:06:00-05:00",
                },
            ],
        },
        {
            "run_id": 12346,
            "test_key": "TEST-002",
            "attachments": [
                {
                    "id": 303,
                    "fileName": "failure_screenshot.png",
                    "fileSize": 89012,
                    "fileURL": "http://example.com/rest/raven/1.0/api/testrun/12346/attachment/303",
                    "contentType": "image/png",
                    "created": "2024-01-16T10:07:00-05:00",
                },
            ],
        },
    ],
}

# Mock download result (Base64-encoded content)
MOCK_XRAY_EVIDENCE_DOWNLOAD_RESULT = {
    "attachment_id": 301,
    "run_id": 12345,
    "file_name": "screenshot_pass.png",
    "content_type": "image/png",
    "size_bytes": 6,
    "saved_to": None,
    "content_base64": "aGVsbG8=",  # base64("hello\n")
}

# Success Response Templates
MOCK_XRAY_SUCCESS_RESPONSE = {
    "success": True,
    "message": "Operation completed successfully",
}

MOCK_XRAY_CREATE_TEST_STEP_RESPONSE = {
    "success": True,
    "data": {"id": 1003, "attachmentIds": []},
}

MOCK_XRAY_UPDATE_SUCCESS_RESPONSE = {
    "success": True,
    "data": {"id": 1001, "attachmentIds": []},
}

# Error Response Templates
MOCK_XRAY_ERROR_RESPONSE = {"error": "Test not found", "code": 404}

MOCK_XRAY_VALIDATION_ERROR_RESPONSE = {
    "error": "Invalid input parameters",
    "code": 400,
    "details": ["Required field missing"],
}
