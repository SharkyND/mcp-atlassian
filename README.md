# MCP Atlassian

![PyPI Version](https://img.shields.io/pypi/v/mcp-atlassian)
![PyPI - Downloads](https://img.shields.io/pypi/dm/mcp-atlassian)
![PePy - Total Downloads](https://static.pepy.tech/personalized-badge/mcp-atlassian?period=total&units=international_system&left_color=grey&right_color=blue&left_text=Total%20Downloads)
[![Run Tests](https://github.com/sooperset/mcp-atlassian/actions/workflows/tests.yml/badge.svg)](https://github.com/sooperset/mcp-atlassian/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/sooperset/mcp-atlassian)
[![Docs](https://img.shields.io/badge/docs-mintlify-blue)](https://mcp-atlassian.soomiles.com)

Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Supports both Cloud and Server/Data Center deployments.

https://github.com/user-attachments/assets/35303504-14c6-4ae4-913b-7c25ea511c3e

<details>
<summary>Confluence Demo</summary>

https://github.com/user-attachments/assets/7fe9c488-ad0c-4876-9b54-120b666bb785

</details>

## Quick Start

### 1. Get Your API Token

Go to https://id.atlassian.com/manage-profile/security/api-tokens and create a token.

> For Server/Data Center, use a Personal Access Token instead. See [Authentication](https://mcp-atlassian.soomiles.com/docs/authentication).

### 2. Configure Your IDE

Add to your Claude Desktop or Cursor MCP configuration:

```json
{
  "mcpServers": {
    "mcp-atlassian": {
      "command": "uvx",
      "args": ["mcp-atlassian"],
      "env": {
        "JIRA_URL": "https://your-company.atlassian.net",
        "JIRA_USERNAME": "your.email@company.com",
        "JIRA_API_TOKEN": "your_api_token",
        "CONFLUENCE_URL": "https://your-company.atlassian.net/wiki",
        "CONFLUENCE_USERNAME": "your.email@company.com",
        "CONFLUENCE_API_TOKEN": "your_api_token"
      }
    }
  }
}
```

> **Server/Data Center users**: Use `JIRA_PERSONAL_TOKEN` instead of `JIRA_USERNAME` + `JIRA_API_TOKEN`. See [Authentication](https://mcp-atlassian.soomiles.com/docs/authentication) for details.

#### Autohand Code

Use the same `uvx` server with your Atlassian credentials:

```bash
autohand mcp add mcp-atlassian env \
  JIRA_URL=https://your-company.atlassian.net \
  JIRA_USERNAME=your.email@company.com \
  JIRA_API_TOKEN=your_api_token \
  CONFLUENCE_URL=https://your-company.atlassian.net/wiki \
  CONFLUENCE_USERNAME=your.email@company.com \
  CONFLUENCE_API_TOKEN=your_api_token \
  uvx mcp-atlassian
```

Add `--scope project` after `add` to keep the configuration in the current
project. See [Autohand Code](https://github.com/autohandai/code-cli/) for current
installation and CLI details.

### 3. Start Using

Ask your AI assistant to:
- **"Find issues assigned to me in PROJ project"**
- **"Search Confluence for onboarding docs"**
- **"Create a bug ticket for the login issue"**
- **"Update the status of PROJ-123 to Done"**

## Documentation

Full documentation is available at **[mcp-atlassian.soomiles.com](https://mcp-atlassian.soomiles.com)**.

Documentation is also available in [llms.txt format](https://llmstxt.org/), which LLMs can consume easily:
- [`llms.txt`](https://mcp-atlassian.soomiles.com/llms.txt) — documentation sitemap
- [`llms-full.txt`](https://mcp-atlassian.soomiles.com/llms-full.txt) — complete documentation

| Topic | Description |
|-------|-------------|
| [Installation](https://mcp-atlassian.soomiles.com/docs/installation) | uvx, Docker, pip, from source |
| [Authentication](https://mcp-atlassian.soomiles.com/docs/authentication) | API tokens, PAT, OAuth 2.0 |
| [Configuration](https://mcp-atlassian.soomiles.com/docs/configuration) | IDE setup, environment variables |
| [HTTP Transport](https://mcp-atlassian.soomiles.com/docs/http-transport) | SSE, streamable-http, multi-user |
| [Tools Reference](https://mcp-atlassian.soomiles.com/docs/tools-reference) | All Jira & Confluence tools |
| [Troubleshooting](https://mcp-atlassian.soomiles.com/docs/troubleshooting) | Common issues & debugging |

## Compatibility

| Product | Deployment | Support |
|---------|------------|---------|
| Confluence | Cloud | Fully supported |
| Confluence | Server/Data Center | Supported (v6.0+) |
| Jira | Cloud | Fully supported |
| Jira | Server/Data Center | Supported (v8.14+) |

## Key Tools

| Jira | Confluence |
|------|------------|
| `jira_search` - Search with JQL | `confluence_search` - Search with CQL |
| `jira_get_issue` - Get issue details | `confluence_get_page` - Get page content |
| `jira_create_issue` - Create issues | `confluence_create_page` - Create pages |
| `jira_update_issue` - Update issues | `confluence_update_page` - Update pages |
| `jira_transition_issue` - Change status | `confluence_add_comment` - Add comments |

**93 tools total** — See [Tools Reference](https://mcp-atlassian.soomiles.com/docs/tools-reference) for the complete list.

## Security

Never share API tokens. Keep `.env` files secure. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

MIT - See [LICENSE](LICENSE). Not an official Atlassian product.


## Fork security baseline (28 October 2026)

This fork tracks the complete upstream **v0.23.1** security baseline, commit
`5be93a041385e2ba076478787946d93ae02c663f`, while retaining its Bitbucket
Cloud/Server/DC tools and optional Prometheus endpoint. The downstream package
version is `0.23.1+puratos.1` (OCI tag `0.23.1-puratos.1`). Consume this fork by
an immutable Git revision or reviewed image digest. This is a source upgrade,
not a version-only workaround for a scanner. Jira default-field ordering also
includes upstream fix `0a5d2427144d72f5aade07d4fabd385421cec401`, so registered
input schemas remain stable across process hash seeds.

Python **3.12 or newer** is required. The frozen lockfile includes FastMCP 3.4.11,
MCP SDK 1.30.0 and patched dependencies; the legacy Python 3.10 dependency branch
is removed. The image builds from that lockfile on the fork's Alpine Python base, keeps
compilers in the builder stage only, and runs as UID 10001.
AnyAscii (ISC) replaces the GPL-licensed Unidecode dependency for Unicode name
matching. The framework's existing application-library licence policy is retained.

HTTP MCP requests require per-request authentication. Do not enable
`ALLOW_GLOBAL_CRED_FALLBACK` in a shared or multi-user deployment. Discovery and
ping must also supply authentication; `/healthz` remains a public process probe.
Each request gets a fresh service fetcher; no user's credentials are copied into
shared process environment. Bitbucket uses the same hardened auth resolver as
Jira/Confluence, validates header URLs, pins DNS, checks redirects, rejects
pagination URLs outside its configured API origin and never logs token suffixes.
`MCP_ATLASSIAN_VALIDATION_CACHE_TTL=0` disables credential-validation caching when
immediate revocation checks are required. `TOOLSETS=bitbucket` selects the fork's
Bitbucket tools; the read-only and exact enabled-tool filters apply to both
listing and invocation. `REQUIRE_USERNAME` remains optional tracking metadata,
never a replacement for authentication. `/metrics` retains optional HTTP and
user-activity counters without reading/replaying request bodies.

Local checks:

```bash
uv sync --frozen --all-extras --dev
uv run pre-commit run --all-files
uv run pytest
# Build without publishing; optional local corporate-CA secret is supported.
docker build -t mcp-atlassian:security .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --add-host synthetic-jira.test:127.0.0.1 \
  --mount type=bind,source="$PWD/scripts/test_http_security.py",target=/fixture.py,readonly \
  --entrypoint python mcp-atlassian:security /fixture.py
```

The real HTTP smoke runs entirely inside a network-isolated container with
in-memory synthetic PATs and a loopback Jira API. It verifies startup,
unauthenticated request denial, metadata-address rejection, two-user concurrent
isolation, filtered discovery, direct invocation denial for hidden writes,
identity isolation when reusing an MCP session ID, and invalid-token denial.
Real Atlassian/E2E tests require their explicit flags and are not this proof.

The Security workflow retains secret scanning and adds pinned Trivy 0.74.0
source/image checks for fixable HIGH/CRITICAL findings, plus this HTTP smoke.
Application-library licences and OS obligations remain part of the framework's
release review. The canonical framework Helm charts remain in
`agentic-platform-config`; bundled standalone charts retain hardened defaults.
