/**
 * Shor MCP connector entrypoint — boots the HTTP transport.
 *
 * The connector holds only the engine trigger token (to reach `/external/*`) and
 * the client-facing bearer; it has no database and no mint secret, so it can
 * consume launch tokens but never create them.
 */

import { startMcpHttpServer } from './http.js';

startMcpHttpServer();
