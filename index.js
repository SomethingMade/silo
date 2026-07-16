const { onRequest } = require('firebase-functions/v2/https');
const { onObjectFinalized, onObjectDeleted } = require('firebase-functions/v2/storage');
const { logger } = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

admin.initializeApp();
const db = admin.firestore();
const bucket = admin.storage().bucket();

const PREFIX = 'companies'; // storage layout: companies/{companyId}/{path...}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// Turns a client-supplied path like "avatars/../../x" into a safe, rooted path.
// Rejects empty segments, "..", and leading slashes.
function safeObjectPath(companyId, rawPath) {
  const cleaned = String(rawPath || '')
    .split('/')
    .map(seg => seg.trim())
    .filter(seg => seg.length > 0 && seg !== '.' && seg !== '..');
  if (cleaned.length === 0) return null;
  return `${PREFIX}/${companyId}/${cleaned.join('/')}`;
}

function companyIdFromObjectPath(objectName) {
  // companies/{companyId}/...
  const parts = String(objectName).split('/');
  if (parts.length < 2 || parts[0] !== PREFIX) return null;
  return parts[1];
}

// ---------------------------------------------------------------------------
// Auth middleware — validates the sk_live_ API key against the company doc,
// checks status, and stamps lastSeenAt (matches the contract already noted
// in the admin console source).
// ---------------------------------------------------------------------------

async function requireApiKey(req, res, next) {
  const header = req.get('authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return res.status(401).json({ error: 'missing_api_key', message: 'Send Authorization: Bearer <api_key>' });
  }
  const rawKey = match[1].trim();
  const keyHash = sha256Hex(rawKey);

  const snap = await db.collection('companies').where('apiKeyHash', '==', keyHash).limit(1).get();
  if (snap.empty) {
    return res.status(401).json({ error: 'invalid_api_key' });
  }
  const doc = snap.docs[0];
  const company = { id: doc.id, ...doc.data() };

  if (company.status === 'suspended') {
    return res.status(403).json({ error: 'account_suspended' });
  }
  if (company.status === 'pending') {
    return res.status(403).json({ error: 'account_pending', message: 'This workspace has not been activated yet.' });
  }

  req.company = company;

  // Fire-and-forget — don't block the request on this write.
  doc.ref.update({ lastSeenAt: admin.firestore.FieldValue.serverTimestamp() }).catch(err => {
    logger.warn('lastSeenAt update failed', err);
  });

  next();
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(cors({ origin: true }));
// Accept any content-type as a raw buffer for uploads; JSON for everything else.
app.use((req, res, next) => {
  if (req.method === 'PUT' || req.method === 'POST') {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      req.rawBody = Buffer.concat(chunks);
      next();
    });
  } else {
    next();
  }
});

app.use(requireApiKey);

// ---- GET /v1/usage --------------------------------------------------------
app.get('/v1/usage', (req, res) => {
  const c = req.company;
  res.json({
    plan: c.plan,
    status: c.status,
    quotaBytes: c.quotaBytes,
    usedBytes: c.usedBytes || 0,
    remainingBytes: c.quotaBytes ? Math.max(0, c.quotaBytes - (c.usedBytes || 0)) : null,
  });
});

// ---- PUT /v1/files/:path* --------------------------------------------------
// Body: raw file bytes. Header: Content-Type is stored as the file's content type.
app.put('/v1/files/*', async (req, res) => {
  const c = req.company;
  const objectPath = safeObjectPath(c.id, req.params[0]);
  if (!objectPath) return res.status(400).json({ error: 'invalid_path' });

  const size = req.rawBody ? req.rawBody.length : 0;
  if (size === 0) return res.status(400).json({ error: 'empty_body' });

  const usedBytes = c.usedBytes || 0;
  if (c.quotaBytes && usedBytes + size > c.quotaBytes) {
    return res.status(402).json({
      error: 'quota_exceeded',
      quotaBytes: c.quotaBytes,
      usedBytes,
      attemptedBytes: size,
    });
  }

  const file = bucket.file(objectPath);
  try {
    await file.save(req.rawBody, {
      contentType: req.get('content-type') || 'application/octet-stream',
      resumable: false,
      metadata: { metadata: { companyId: c.id } },
    });
  } catch (err) {
    logger.error('upload failed', err);
    return res.status(500).json({ error: 'upload_failed' });
  }

  // usedBytes itself is reconciled by the Storage trigger below, not here —
  // that's the source of truth. We just report what we know synchronously.
  res.status(201).json({
    path: req.params[0],
    size,
    contentType: req.get('content-type') || 'application/octet-stream',
  });
});

// ---- GET /v1/files ----------------------------------------------------------
// Lists files under an optional ?prefix=
app.get('/v1/files', async (req, res) => {
  const c = req.company;
  const prefix = `${PREFIX}/${c.id}/` + (req.query.prefix ? String(req.query.prefix).replace(/^\/+/, '') : '');
  try {
    const [files] = await bucket.getFiles({ prefix });
    const items = files.map(f => ({
      path: f.name.slice(`${PREFIX}/${c.id}/`.length),
      size: Number(f.metadata.size || 0),
      contentType: f.metadata.contentType,
      updated: f.metadata.updated,
    }));
    res.json({ files: items });
  } catch (err) {
    logger.error('list failed', err);
    res.status(500).json({ error: 'list_failed' });
  }
});

// ---- GET /v1/files/:path* ----------------------------------------------------
// Returns a short-lived signed download URL rather than streaming through
// the function (cheaper, faster, works for large files).
app.get('/v1/files/*', async (req, res) => {
  const c = req.company;
  const objectPath = safeObjectPath(c.id, req.params[0]);
  if (!objectPath) return res.status(400).json({ error: 'invalid_path' });

  const file = bucket.file(objectPath);
  try {
    const [exists] = await file.exists();
    if (!exists) return res.status(404).json({ error: 'not_found' });

    const [url] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes
    });
    res.json({ url, expiresInSeconds: 900 });
  } catch (err) {
    logger.error('signed url failed', err);
    res.status(500).json({ error: 'signed_url_failed' });
  }
});

// ---- DELETE /v1/files/:path* -------------------------------------------------
app.delete('/v1/files/*', async (req, res) => {
  const c = req.company;
  const objectPath = safeObjectPath(c.id, req.params[0]);
  if (!objectPath) return res.status(400).json({ error: 'invalid_path' });

  try {
    await bucket.file(objectPath).delete();
    res.status(204).send();
  } catch (err) {
    if (err.code === 404) return res.status(404).json({ error: 'not_found' });
    logger.error('delete failed', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

exports.siloApi = onRequest({ region: 'us-east1', cors: true }, app);

// ---------------------------------------------------------------------------
// Storage triggers — the real source of truth for usedBytes. These fire
// regardless of how an object was written/removed, so the quota counter in
// Firestore can never drift from what's actually in the bucket.
// ---------------------------------------------------------------------------

exports.onFileFinalized = onObjectFinalized({ region: 'us-east1' }, async (event) => {
  const obj = event.data;
  const companyId = companyIdFromObjectPath(obj.name);
  if (!companyId) return;
  const size = Number(obj.size || 0);
  await db.collection('companies').doc(companyId).update({
    usedBytes: admin.firestore.FieldValue.increment(size),
  }).catch(err => logger.error('usedBytes increment failed', err));
});

exports.onFileDeletedTrigger = onObjectDeleted({ region: 'us-east1' }, async (event) => {
  const obj = event.data;
  const companyId = companyIdFromObjectPath(obj.name);
  if (!companyId) return;
  const size = Number(obj.size || 0);
  await db.collection('companies').doc(companyId).update({
    usedBytes: admin.firestore.FieldValue.increment(-size),
  }).catch(err => logger.error('usedBytes decrement failed', err));
});
