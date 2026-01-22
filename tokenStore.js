const fs = require('fs');
const path = require('path');

const TOKENS_DIR = path.join(__dirname, 'tokens');
const STABLE_DIR = path.join(TOKENS_DIR, 'stable');
const BINDINGS_DIR = path.join(TOKENS_DIR, 'bindings');
if (!fs.existsSync(TOKENS_DIR)) fs.mkdirSync(TOKENS_DIR, { recursive: true });
if (!fs.existsSync(STABLE_DIR)) fs.mkdirSync(STABLE_DIR, { recursive: true });
if (!fs.existsSync(BINDINGS_DIR)) fs.mkdirSync(BINDINGS_DIR, { recursive: true });

function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }

function sessionPath(sessionId) { return path.join(TOKENS_DIR, `${sessionId}.json`); }
function stablePathFor(acctKey) { return path.join(STABLE_DIR, `${acctKey.toLowerCase()}.json`); }
function bindingPath(sessionId) { return path.join(BINDINGS_DIR, `${sessionId}.json`); }

function listStableAccounts() {
  try {
    const files = fs.readdirSync(STABLE_DIR).filter(f => f.endsWith('.json'));
    // Sort by mtime descending so the most recently authorized account appears first
    const withStats = files.map(f => {
      try {
        const s = fs.statSync(path.join(STABLE_DIR, f));
        return { file: f, mtime: s.mtimeMs || 0 };
      } catch (e) {
        return { file: f, mtime: 0 };
      }
    });
    withStats.sort((a, b) => b.mtime - a.mtime);
    return withStats.map(x => x.file.replace(/\.json$/, '').toLowerCase());
  } catch {
    return [];
  }
}

function readStableFor(account) { if (!account) return null; return readJson(stablePathFor(account)); }

function getBoundAccountForSession(sessionId) { const b = readJson(bindingPath(sessionId)); return b && b.account ? b.account.toLowerCase() : null; }

function loadTokens(sessionId, { permissiveFallback = true, account = null } = {}) {
  const perSession = sessionId ? readJson(sessionPath(sessionId)) : null;
  if (perSession) { const bound = getBoundAccountForSession(sessionId); return { tokens: perSession, source: 'session', account: bound || null }; }

  if (account) { const st = readJson(stablePathFor(account)); if (st) return { tokens: st, source: 'stable', account: account.toLowerCase() }; return null; }

  const accounts = listStableAccounts();
  if (accounts.length === 1 && permissiveFallback) { const st = readJson(stablePathFor(accounts[0])); if (st) return { tokens: st, source: 'stable', account: accounts[0] }; }

  return null;
}

function sanitizeId(id) {
  if (!id) return id;
  // remove whitespace and control characters to avoid invalid filenames
  return String(id).replace(/\s+/g, '').replace(/[^0-9a-zA-Z\-@._]/g, '');
}

function saveTokensForSession(sessionId, tokens, acctKey = null) {
  if (!sessionId) throw new Error('sessionId required to save tokens');
  const sid = sanitizeId(sessionId);
  fs.writeFileSync(sessionPath(sid), JSON.stringify(tokens, null, 2), 'utf8');
  if (acctKey) {
    try { fs.writeFileSync(stablePathFor(acctKey), JSON.stringify(tokens, null, 2), 'utf8'); } catch (e) { /* ignore */ }
    try { fs.writeFileSync(bindingPath(sid), JSON.stringify({ account: acctKey.toLowerCase() }, null, 2), 'utf8'); } catch (e) { /* ignore */ }
  }
}
// Remove per-session token + binding; keep stable account tokens
function deleteSession(sessionId) {
  if (!sessionId) return;
  const sid = sanitizeId(sessionId);
  try { fs.unlinkSync(sessionPath(sid)); } catch (e) { /* ignore */ }
  try { fs.unlinkSync(bindingPath(sid)); } catch (e) { /* ignore */ }
}

module.exports = { loadTokens, saveTokensForSession, listStableAccounts, readStableFor, getBoundAccountForSession, deleteSession };

