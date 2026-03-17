# Jira Attachment Tools — Download & Upload Guide

Two MCP tools let you move files between your local machine and Jira issues:

| Goal | Tool(s) |
|---|---|
| View / save Jira attachments locally | `download_attachments` |
| Upload a local file to a Jira issue | `construct_upload_endpoint` → *(curl)* → `jira_upload_attachment` |

---

## Downloading Attachments

### How it works

When you call `download_attachments`, the MCP server fetches all attachments from the Jira issue and registers them as **MCP Resources** — clickable items that appear in the VS Code MCP resource browser. No base64 blobs, no manual copy-paste.

```
download_attachments("PROJ-123")
        │
        ▼
MCP server caches file content in memory (10-minute TTL)
        │
        ▼
Registers static resource URIs:
  jira://attachments/PROJ-123/design.pdf
  jira://attachments/PROJ-123/screenshot.png
  ...
        │
        ▼
Resources appear in VS Code → you click to open / save locally
```

### Step-by-step

**Step 1 — Call the tool**

Ask the agent (or call directly):
```
download_attachments issue_key="PROJ-123"
```

The response lists every attachment with its resource URI:
```json
{
  "downloaded": [
    {
      "filename": "design.pdf",
      "size": 204800,
      "static_resource_uri": "jira://attachments/PROJ-123/design.pdf",
      "mime_type": "application/pdf"
    },
    {
      "filename": "screenshot.png",
      "size": 51200,
      "static_resource_uri": "jira://attachments/PROJ-123/screenshot.png",
      "mime_type": "image/png"
    }
  ]
}
```

**Step 2 — Open files from the resource browser**

In VS Code, open the MCP panel and navigate to **Resources**. Each attachment appears as a clickable link:

- **Images** (PNG, JPEG, GIF) render inline immediately.
- **Text / PDF / other files** open in your editor or trigger a save dialog.

You can also reference the URI directly: `jira://attachments/PROJ-123/design.pdf`

> **Note:** Cached resources expire after **10 minutes**. Simply re-run `download_attachments` to refresh them.

### Checking what's cached

```
list_cached_attachments
```

Shows all files currently in cache with their URIs, sizes, MIME types, and expiry times.

---

## Uploading Attachments

Uploading is a **3-step flow** that keeps file bytes out of the AI context entirely — only a small URI reference is passed between steps.

```
Step 1: construct_upload_endpoint
        → returns upload_url + session_id + ready-to-run curl command

Step 2: Run the curl command in a terminal
        → your file is staged on the MCP server
        → returns an  upload://  URI

Step 3: jira_upload_attachment(issue_key, [upload_uri])
        → MCP server reads staged bytes and posts to Jira
        → staged file is cleaned up automatically
```

### Step-by-step

**Step 1 — Get the upload URL**

```
construct_upload_endpoint
```

The tool automatically:
- Creates a secure staging session with a unique ID
- Detects your OS and generates the correct curl command
- Resolves the server base URL from config (no manual setup needed)

Example response:
```json
{
  "upload_url": "http://localhost:8932/upload",
  "session_id": "abc123def456",
  "curl_example": "curl.exe -s -X POST \"http://localhost:8932/upload\" -H \"Mcp-Session-Id: abc123def456\" -F 'file=@\"C:\\path with spaces\\your_file.pdf\"'",
  "instructions": "1. Replace the path placeholder ... 5. Call jira_upload_attachment ..."
}
```

**Step 2 — Upload your file via curl**

Copy the `curl_example` value, replace the placeholder path with your actual file path, and run it in a terminal:

*Windows PowerShell:*
```powershell
curl.exe -s -X POST "http://localhost:8932/upload" `
  -H "Mcp-Session-Id: abc123def456" `
  -F 'file=@"C:\Users\You\Documents\spec.pdf"'
```

*Linux / macOS:*
```bash
curl -s -X POST "http://localhost:8932/upload" \
  -H "Mcp-Session-Id: abc123def456" \
  -F "file=@'/home/you/documents/spec.pdf'"
```

A successful upload returns:
```json
{
  "success": true,
  "uploaded": [
    {
      "filename": "spec.pdf",
      "uri": "upload://sessions/abc123def456/xyz789",
      "size": 204800
    }
  ]
}
```

> **Paths with spaces** are handled automatically by the generated curl command.  
> The `-s` flag suppresses the progress bar so the output is clean JSON.

**Step 3 — Attach to the Jira issue**

Pass the `uri` value(s) from the previous step:

```
jira_upload_attachment
  issue_key = "PROJ-123"
  upload_uris = ["upload://sessions/abc123def456/xyz789"]
```

Response:
```json
{
  "success": true,
  "issue_key": "PROJ-123",
  "total": 1,
  "uploaded": [
    { "filename": "spec.pdf", "size": 204800, "id": "10042" }
  ],
  "failed": []
}
```

The staged file is deleted from the server after a successful upload. Unused staged files expire automatically after 30 minutes.

### Uploading multiple files

Run `curl` once per file (each gets its own URI), then pass all URIs together:

```
jira_upload_attachment
  issue_key = "PROJ-123"
  upload_uris = [
    "upload://sessions/abc123def456/file1id",
    "upload://sessions/abc123def456/file2id"
  ]
```

---

## Quick Reference

| Tool | What it does |
|---|---|
| `download_attachments` | Downloads all attachments from a Jira issue and registers them as MCP resources |
| `list_cached_attachments` | Lists currently cached attachments and their resource URIs |
| `construct_upload_endpoint` | Generates the upload URL, session ID, and OS-specific curl command |
| `jira_upload_attachment` | Uploads staged files (by URI) to a Jira issue and cleans up |

## Troubleshooting

**"Attachment not found" when clicking a resource URI**  
The 10-minute cache has expired. Re-run `download_attachments` to refresh.

**curl returns a progress bar instead of JSON**  
Make sure you're using the `-s` flag (already included in the generated `curl_example`).

**"Staged file not found or expired" in jira_upload_attachment**  
The staging session expired (30-minute TTL). Re-run from Step 1.

**Path with spaces not working in curl**  
Use the exact quoting shown in `curl_example`:
- Windows: `-F 'file=@"C:\My Docs\file.pdf"'` (outer single, inner double)
- Linux/macOS: `-F "file=@'/my docs/file.pdf'"` (outer double, inner single)

- [save_jira_attachments.py](../scripts/save_jira_attachments.py) - Helper script
- [MCP Protocol Documentation](https://spec.modelcontextprotocol.io/)
