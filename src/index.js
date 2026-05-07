#!/usr/bin/env node

/**
 * Entry point for the Email-Based Google Workspace MCP Server
 * 
 * This file starts the Express server with all routes and middleware configured.
 */

const { startServer } = require('./app');

console.log('[AUTH MODE] Client-level account binding (one account per client)');

startServer();
