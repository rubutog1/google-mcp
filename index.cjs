#!/usr/bin/env node
/* CommonJS entrypoint copy of index.js for environments where package.json has "type":"module" */
// This file is identical to index.js but uses .cjs extension so Node treats it as CommonJS

const fs = require('fs');
const path = require('path');

// Load the main file text and execute it as CommonJS to preserve the original file unchanged.
// This avoids modifying package.json or index.js while allowing the server to run.
const mainPath = path.join(__dirname, 'index.js');
if (!fs.existsSync(mainPath)) {
  console.error('index.js not found at', mainPath);
  process.exit(1);
}

// Use Node's module loader to compile and run the script as CommonJS
const Module = require('module');
const m = new Module(mainPath, module.parent);
m.filename = mainPath;
m.paths = Module._nodeModulePaths(path.dirname(mainPath));
const content = fs.readFileSync(mainPath, 'utf8');
try {
  m._compile(content, mainPath);
} catch (e) {
  console.error('Failed to execute index.js as CommonJS:', e && (e.stack || e));
  process.exit(1);
}
