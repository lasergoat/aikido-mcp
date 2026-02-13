#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { config } from "dotenv";

// Load environment variables
config({ path: ".env.local" });

const AIKIDO_CLIENT_ID = process.env.AIKIDO_CLIENT_ID;
const AIKIDO_API_KEY = process.env.AIKIDO_API_KEY;
const AIKIDO_BASE_URL = "https://app.aikido.dev/api";

// Token cache
let accessToken: string | null = null;
let tokenExpiry: number = 0;

async function getAccessToken(): Promise<string> {
  // Return cached token if still valid (with 60s buffer)
  if (accessToken && Date.now() < tokenExpiry - 60000) {
    return accessToken;
  }

  if (!AIKIDO_CLIENT_ID || !AIKIDO_API_KEY) {
    throw new Error(
      "Missing AIKIDO_CLIENT_ID or AIKIDO_API_KEY environment variables"
    );
  }

  const credentials = Buffer.from(
    `${AIKIDO_CLIENT_ID}:${AIKIDO_API_KEY}`
  ).toString("base64");

  const response = await fetch(`${AIKIDO_BASE_URL}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      grant_type: "client_credentials",
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get access token: ${response.status} - ${error}`);
  }

  const data = await response.json();
  accessToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000;

  return accessToken!;
}

async function aikidoRequest(
  endpoint: string,
  options: RequestInit = {}
): Promise<any> {
  const token = await getAccessToken();

  const response = await fetch(`${AIKIDO_BASE_URL}/public/v1${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Aikido API error: ${response.status} - ${error}`);
  }

  return response.json();
}

// Tool definitions
const tools = [
  {
    name: "list_repositories",
    description:
      "List all code repositories monitored by Aikido. Use this to find the repository ID for a project.",
    inputSchema: {
      type: "object" as const,
      properties: {
        page: {
          type: "number",
          description: "Page number (0-indexed)",
          default: 0,
        },
        per_page: {
          type: "number",
          description: "Results per page (max 100)",
          default: 100,
        },
      },
    },
  },
  {
    name: "get_issues",
    description:
      "Get all security issues/vulnerabilities for a specific repository or all repositories. Returns detailed issue information including severity, affected packages, and remediation guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {
        repo_id: {
          type: "number",
          description:
            "Repository ID to filter issues (use list_repositories to find this)",
        },
        severity: {
          type: "array",
          items: { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: "Filter by severity levels",
        },
        issue_type: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "open_source",
              "leaked_secret",
              "sast",
              "iac",
              "container",
              "cloud",
              "dast",
            ],
          },
          description: "Filter by issue type",
        },
        page: {
          type: "number",
          description: "Page number (0-indexed)",
          default: 0,
        },
        per_page: {
          type: "number",
          description: "Results per page (max 100)",
          default: 50,
        },
      },
    },
  },
  {
    name: "get_issue_details",
    description:
      "Get detailed information about a specific issue including full description, affected files, remediation steps, and related CVEs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        issue_id: {
          type: "number",
          description: "The issue ID to get details for",
        },
      },
      required: ["issue_id"],
    },
  },
  {
    name: "get_open_issue_groups",
    description:
      "Get grouped view of open issues. Issues are grouped by type/vulnerability. Useful for seeing unique vulnerabilities across the codebase.",
    inputSchema: {
      type: "object" as const,
      properties: {
        repo_id: {
          type: "number",
          description: "Repository ID to filter issue groups",
        },
        severity: {
          type: "array",
          items: { type: "string", enum: ["critical", "high", "medium", "low"] },
          description: "Filter by severity levels",
        },
        page: {
          type: "number",
          description: "Page number (0-indexed)",
          default: 0,
        },
        per_page: {
          type: "number",
          description: "Results per page (max 50)",
          default: 20,
        },
      },
    },
  },
  {
    name: "get_issue_group_details",
    description:
      "Get detailed information about an issue group, including all affected locations and remediation guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {
        group_id: {
          type: "number",
          description: "The issue group ID to get details for",
        },
      },
      required: ["group_id"],
    },
  },
  {
    name: "search_repository_by_name",
    description:
      "Search for a repository by name. Returns matching repositories with their IDs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: {
          type: "string",
          description: "Repository name or partial name to search for",
        },
      },
      required: ["name"],
    },
  },
];

// Tool handlers
async function listRepositories(args: {
  page?: number;
  per_page?: number;
}): Promise<any> {
  const params = new URLSearchParams();
  params.set("page", String(args.page ?? 0));
  params.set("per_page", String(args.per_page ?? 100));

  return aikidoRequest(`/repositories/code?${params.toString()}`);
}

// Condensed issue for list views
function summarizeIssue(issue: any): any {
  return {
    id: issue.id,
    group_id: issue.group_id,
    type: issue.type,
    severity: issue.severity,
    title: issue.rule || issue.cve_id || "Unknown",
    package: issue.affected_package,
    file: issue.affected_file,
    line: issue.start_line,
    repo: issue.code_repo_name,
    language: issue.programming_language,
  };
}

async function getIssues(args: {
  repo_id?: number;
  severity?: string[];
  issue_type?: string[];
  page?: number;
  per_page?: number;
}): Promise<any> {
  const params = new URLSearchParams();
  params.set("page", String(args.page ?? 0));
  params.set("per_page", String(args.per_page ?? 50));

  if (args.repo_id) {
    params.set("filter_code_repo_id", String(args.repo_id));
  }
  if (args.severity && args.severity.length > 0) {
    args.severity.forEach((s) => params.append("filter_severities", s));
  }
  if (args.issue_type && args.issue_type.length > 0) {
    args.issue_type.forEach((t) => params.append("filter_issue_type", t));
  }

  const response = await aikidoRequest(`/issues/export?${params.toString()}`);

  // Return condensed summaries
  if (Array.isArray(response)) {
    return {
      total: response.length,
      issues: response.map(summarizeIssue),
      hint: "Use get_issue_details with an issue id for full information including remediation steps",
    };
  }
  return response;
}

async function getIssueDetails(args: { issue_id: number }): Promise<any> {
  return aikidoRequest(`/issues/${args.issue_id}`);
}

// Condensed issue group for list views
function summarizeIssueGroup(group: any): any {
  return {
    id: group.id,
    type: group.type,
    severity: group.severity,
    title: group.title,
    description: group.description,
    location_count: group.locations?.length ?? 0,
    locations: group.locations?.map((l: any) => l.name).slice(0, 5),
    fix_time_minutes: group.time_to_fix_minutes,
    how_to_fix: group.how_to_fix?.slice(0, 200) + (group.how_to_fix?.length > 200 ? "..." : ""),
    cves: group.related_cve_ids?.slice(0, 5),
  };
}

async function getOpenIssueGroups(args: {
  repo_id?: number;
  severity?: string[];
  page?: number;
  per_page?: number;
}): Promise<any> {
  const params = new URLSearchParams();
  params.set("page", String(args.page ?? 0));
  params.set("per_page", String(args.per_page ?? 20));

  if (args.repo_id) {
    params.set("filter_code_repo_id", String(args.repo_id));
  }
  if (args.severity && args.severity.length > 0) {
    args.severity.forEach((s) => params.append("filter_severities", s));
  }

  const response = await aikidoRequest(`/open-issue-groups?${params.toString()}`);

  // Return condensed summaries
  if (Array.isArray(response)) {
    return {
      total: response.length,
      groups: response.map(summarizeIssueGroup),
      hint: "Use get_issue_group_details with a group id for full information",
    };
  }
  return response;
}

async function getIssueGroupDetails(args: { group_id: number }): Promise<any> {
  return aikidoRequest(`/issues/groups/${args.group_id}`);
}

async function searchRepositoryByName(args: { name: string }): Promise<any> {
  // Fetch all repos and filter by name
  const allRepos: any[] = [];
  let page = 0;
  let hasMore = true;

  while (hasMore) {
    const response = await listRepositories({ page, per_page: 100 });
    if (response.repositories && response.repositories.length > 0) {
      allRepos.push(...response.repositories);
      page++;
      hasMore = response.repositories.length === 100;
    } else {
      hasMore = false;
    }
  }

  const searchTerm = args.name.toLowerCase();
  const matches = allRepos.filter(
    (repo: any) =>
      repo.name?.toLowerCase().includes(searchTerm) ||
      repo.external_repo_id?.toLowerCase().includes(searchTerm)
  );

  return {
    total: matches.length,
    repositories: matches,
  };
}

// Create server
const server = new Server(
  {
    name: "aikido-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: any;

    switch (name) {
      case "list_repositories":
        result = await listRepositories(args as any);
        break;
      case "get_issues":
        result = await getIssues(args as any);
        break;
      case "get_issue_details":
        result = await getIssueDetails(args as any);
        break;
      case "get_open_issue_groups":
        result = await getOpenIssueGroups(args as any);
        break;
      case "get_issue_group_details":
        result = await getIssueGroupDetails(args as any);
        break;
      case "search_repository_by_name":
        result = await searchRepositoryByName(args as any);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Aikido MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
