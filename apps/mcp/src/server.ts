/**
 * Builds the Shor MCP server instance and registers its (three) tools. A fresh
 * server is built per request in the stateless HTTP transport, so this stays a
 * pure factory with no shared mutable state.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from './tools.js';

const INSTRUCTIONS = [
  'Shor black-box web-security scanning, exposed for authorized engagements only.',
  'A scan can be started ONLY with a single-use authorizationToken that a human approver mints for the',
  'specific engagement and the specific signed Rules of Engagement (RoE). You cannot mint that token;',
  'obtain it from the approval step and pass it verbatim to start_blackbox_run. The RoE you pass is the',
  'scope the engine enforces (default-deny). Share the read-only get_share_url link for results.',
].join(' ');

export function buildServer(): McpServer {
  const server = new McpServer(
    { name: 'shor', version: '0.0.0' },
    { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
  );
  registerTools(server);
  return server;
}
