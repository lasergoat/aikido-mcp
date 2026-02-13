# Aikido MCP Server

An MCP (Model Context Protocol) server that integrates with [Aikido Security](https://aikido.dev) to fetch vulnerability information for your repositories. This allows Claude to access your security findings and help you understand and fix vulnerabilities.

## Features

- List all monitored repositories
- Search repositories by name
- Fetch security issues with filtering by severity and type
- Get detailed vulnerability information including remediation guidance
- View grouped issues across your codebase

## Prerequisites

- Node.js 18+
- An Aikido Security account with API access
- API credentials (Client ID and Client Secret)

## Getting API Credentials

You'll need to create API credentials in your Aikido dashboard:

**[Create API Credentials in Aikido Settings](https://app.aikido.dev/settings/integrations/api)**

Or follow these steps:

1. Log into your [Aikido dashboard](https://app.aikido.dev)
2. Navigate to **Settings** > **Integrations** > **Public REST API** ([direct link](https://app.aikido.dev/settings/integrations/api))
3. Click **Add Client**
4. Give it a name, select **Private App** type
5. Enable the required permissions:
   - `basics:read` - Required for authentication
   - `issues:read` - Required for fetching vulnerabilities
6. Click **Save** and copy your **Client ID** and **Client Secret**

> **Note:** The Client Secret is only shown once. Save it immediately.

## Installation

### Using Claude Code CLI

```bash
claude mcp add aikido npx @lasergoat/aikido-mcp \
  -e AIKIDO_CLIENT_ID=your_client_id \
  -e AIKIDO_API_KEY=your_client_secret
```

### Manual Configuration

Add to your Claude MCP settings (`~/.claude.json` or Claude Desktop config):

```json
{
  "mcpServers": {
    "aikido": {
      "command": "npx",
      "args": ["@lasergoat/aikido-mcp"],
      "env": {
        "AIKIDO_CLIENT_ID": "your_client_id",
        "AIKIDO_API_KEY": "your_client_secret"
      }
    }
  }
}
```

### From Source

```bash
git clone https://github.com/lasergoat/aikido-mcp.git
cd aikido-mcp
npm install
npm run build

# Add to Claude
claude mcp add aikido node /path/to/aikido-mcp/dist/index.js \
  -e AIKIDO_CLIENT_ID=your_client_id \
  -e AIKIDO_API_KEY=your_client_secret
```

## Available Tools

### `list_repositories`
List all code repositories monitored by Aikido.

### `search_repository_by_name`
Search for a repository by name to find its ID.

**Parameters:**
- `name` (required): Repository name or partial name to search for

### `get_issues`
Get security issues for a repository. Returns condensed summaries.

**Parameters:**
- `repo_id`: Repository ID (use `list_repositories` to find this)
- `severity`: Filter by severity levels (`critical`, `high`, `medium`, `low`)
- `issue_type`: Filter by type (`open_source`, `leaked_secret`, `sast`, `iac`, `container`, `cloud`, `dast`)
- `page`: Page number (0-indexed)
- `per_page`: Results per page (max 100)

### `get_issue_details`
Get full details for a specific issue including remediation steps.

**Parameters:**
- `issue_id` (required): The issue ID

### `get_open_issue_groups`
Get grouped view of open issues. Issues are grouped by vulnerability type.

**Parameters:**
- `repo_id`: Repository ID to filter
- `severity`: Filter by severity levels
- `page`: Page number (0-indexed)
- `per_page`: Results per page (max 50)

### `get_issue_group_details`
Get detailed information about an issue group.

**Parameters:**
- `group_id` (required): The issue group ID

## Example Usage

Once configured, you can ask Claude things like:

- "What security vulnerabilities are in my project?"
- "Show me the critical issues in the api-service repo"
- "Get details on issue 12345 and help me fix it"
- "What SQL injection vulnerabilities exist in my codebase?"

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AIKIDO_CLIENT_ID` | Your Aikido API Client ID |
| `AIKIDO_API_KEY` | Your Aikido API Client Secret |

## Regional Endpoints

The server defaults to the EU endpoint (`app.aikido.dev`). If you need to use a different region, you can modify the `AIKIDO_BASE_URL` in the source:

- **EU:** `https://app.aikido.dev/api`
- **US:** `https://app.us.aikido.dev/api`
- **Middle East:** `https://app.me.aikido.dev/api`

## License

ISC

## Links

- [Aikido Security](https://aikido.dev)
- [Aikido API Documentation](https://apidocs.aikido.dev)
- [Model Context Protocol](https://modelcontextprotocol.io)
