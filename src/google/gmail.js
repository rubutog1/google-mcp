const { callWithAutoRefresh } = require('./credentials');

/**
 * Extract email body from Gmail payload
 */
function extractEmailBody(payload) {
  if (!payload) return null;
  if (payload.body && payload.body.data) {
    const d = payload.body.data;
    try {
      return Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    } catch (e) {
      return null;
    }
  }
  if (Array.isArray(payload.parts)) {
    for (const p of payload.parts) {
      const r = extractEmailBody(p);
      if (r) return r;
    }
  }
  return null;
}

/**
 * Fetch Gmail messages with metadata
 */
async function fetchGmailMessages(gmail, oauth2, email, messageIds) {
  const results = [];
  for (const m of messageIds) {
    try {
      const md = await callWithAutoRefresh(
        () => gmail.users.messages.get({
          userId: 'me',
          id: m.id,
          format: 'metadata',
          metadataHeaders: ['From', 'To', 'Subject', 'Date']
        }),
        oauth2,
        email
      );
      const headers = (md.data.payload && md.data.payload.headers) || [];
      const hmap = {};
      for (const h of headers) hmap[h.name] = h.value;
      results.push({
        id: md.data.id,
        threadId: md.data.threadId,
        snippet: md.data.snippet || '',
        from: hmap.From || '',
        to: hmap.To || '',
        subject: hmap.Subject || '',
        date: hmap.Date || '',
        labels: md.data.labelIds || []
      });
    } catch (e) {
      console.warn('Failed to fetch message metadata for', m.id, e && e.message);
    }
  }
  return results;
}

module.exports = {
  extractEmailBody,
  fetchGmailMessages
};
