# Public tool definitions (definitions only, no data)

Downloaded on 2026-11-07. Used only to show how the Copilot behaves on tools it has never seen (no gold set, so no accuracy claim).

| File | Source | What it is |
|---|---|---|
| `github_mcp_tools.json` | https://github.com/github/github-mcp-server/tree/main/pkg/github/__toolsnaps__ (one `.snap` file per tool, main branch, 2026-11-07) | the tool definitions (name, description, inputSchema) of GitHub's official MCP server, merged into one MCP-format list. **143 snapshot files, 133 unique names:** 10 names appear twice in the upstream repo (variants of the same tool with different descriptions, e.g. get_job_logs, list_branches, list_issues); we kept the FIRST definition of each. The Copilot's loader rejects duplicate names on purpose (a policy is written per tool name) |
| `petstore.openapi.json` | https://petstore3.swagger.io/api/v3/openapi.json (2026-11-07) | the public Swagger Petstore OpenAPI 3 document |

Licenses are those of the upstream projects (MIT for github-mcp-server; Apache-2.0 for the Swagger Petstore).
