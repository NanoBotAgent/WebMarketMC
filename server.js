/**
 * Aurelium Web Dashboard — Central Server
 * 
 * A single Express instance that handles market dashboards
 * for multiple Minecraft servers. Each MC server syncs its
 * data here via outbound HTTP — no ports needed on the MC side.
 * 
 * Persistence: Astra DB (DataStaxa) via REST v2 API
 * Caching: In-memory write-through cache for performance
 * Encryption: AES-256-GCM field-level encryption for sensitive data
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ── Astra DB Configuration ──────────────────────────────────────
const ASTRA_TOKEN = process.env.ASTRA_TOKEN || '';
const ASTRA_DB_ID = process.env.ASTRA_DB_ID;
const ASTRA_REGION = process.env.ASTRA_REGION;
const ASTRA_KEYSPACE = process.env.ASTRA_KEYSPACE;

// Fail fast if Astra is configured but target env vars are missing
if (ASTRA_TOKEN && (!ASTRA_DB_ID || !ASTRA_REGION || !ASTRA_KEYSPACE)) {
    console.error('[Astra] ASTRA_DB_ID, ASTRA_REGION, and ASTRA_KEYSPACE are required when ASTRA_TOKEN is set');
    process.exit(1);
}

const ASTRA_BASE = ASTRA_DB_ID && ASTRA_REGION
    ? `https://${ASTRA_DB_ID}-${ASTRA_REGION}.apps.astra.datastax.com`
    : '';
const ASTRA_REST = ASTRA_BASE && ASTRA_KEYSPACE
    ? `${ASTRA_BASE}/api/rest/v2/keyspaces/${ASTRA_KEYSPACE}`
    : '';

// ── Field-Level Encryption ──────────────────────────────────────
// AES-256-GCM encryption for sensitive fields stored in Astra DB.
// If ENCRYPTION_KEY is not set and Astra is enabled, fail fast.
// If neither is set, run in plaintext mode (local/dev only).
// Encrypted values are prefixed with "enc:" for auto-detection on read.

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const ENCRYPTION_PREFIX = 'enc:';
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;    // 96-bit IV for GCM
const AUTH_TAG_LENGTH = 16; // 128-bit auth tag
const KEY_LENGTH = 32;   // 256-bit key

let encryptionEnabled = false;

/**
 * Derive a 32-byte key from the ENCRYPTION_KEY env var.
 * Accepts either a 64-char hex string or any string (SHA-256 hashed).
 */
function deriveKey(rawKey) {
    if (!rawKey) return null;
    // If it's a valid 64-char hex string, use it directly
    if (/^[0-9a-f]{64}$/i.test(rawKey)) {
        return Buffer.from(rawKey, 'hex');
    }
    // Otherwise hash it to get a 32-byte key
    return crypto.createHash('sha256').update(rawKey).digest();
}

const derivedKey = deriveKey(ENCRYPTION_KEY);
if (derivedKey) {
    encryptionEnabled = true;
    console.log('[Encryption] AES-256-GCM field-level encryption enabled');
} else if (ASTRA_TOKEN) {
    // Astra persistence requires encryption for sensitive fields
    console.error('[Encryption] ENCRYPTION_KEY is required when Astra persistence is enabled');
    process.exit(1);
} else {
    console.log('[Encryption] No ENCRYPTION_KEY set — running in plaintext mode (local/dev only)');
}

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Returns "enc:<iv>:<ciphertext>:<authTag>" (all base64url).
 * Returns the original value if encryption is disabled.
 */
function encrypt(plaintext) {
    if (!encryptionEnabled || plaintext === null || plaintext === undefined) {
        return plaintext;
    }
    const str = String(plaintext);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, derivedKey, iv, { authTagLength: AUTH_TAG_LENGTH });
    let encrypted = cipher.update(str, 'utf8', 'base64url');
    encrypted += cipher.final('base64url');
    const authTag = cipher.getAuthTag().toString('base64url');
    const ivB64 = iv.toString('base64url');
    return `${ENCRYPTION_PREFIX}${ivB64}:${encrypted}:${authTag}`;
}

/**
 * Decrypt a value that was encrypted by encrypt().
 * Auto-detects encrypted values by the "enc:" prefix.
 * Returns the original value if it's not encrypted or decryption is disabled.
 */
function decrypt(ciphertext) {
    if (!ciphertext || typeof ciphertext !== 'string' || !ciphertext.startsWith(ENCRYPTION_PREFIX)) {
        return ciphertext;
    }
    if (!encryptionEnabled) {
        console.warn('[Encryption] Found encrypted value but no key available — returning raw');
        return ciphertext;
    }
    try {
        const parts = ciphertext.slice(ENCRYPTION_PREFIX.length).split(':');
        if (parts.length !== 3) {
            console.error('[Encryption] Malformed encrypted value');
            return ciphertext;
        }
        const [ivB64, encData, authTagB64] = parts;
        const iv = Buffer.from(ivB64, 'base64url');
        const authTag = Buffer.from(authTagB64, 'base64url');
        const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey, iv, { authTagLength: AUTH_TAG_LENGTH });
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encData, 'base64url', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error('[Encryption] Decryption failed:', e.message);
        return ciphertext;
    }
}

/**
 * Encrypt a JSON object by serializing and encrypting the whole string.
 * Used for balances_json which contains structured data.
 * Always returns a string (JSON in plaintext mode, encrypted in encrypted mode).
 */
function encryptJson(obj) {
    const json = JSON.stringify(obj ?? {});
    return encryptionEnabled ? encrypt(json) : json;
}

/**
 * Decrypt an encrypted JSON string back to an object.
 * Falls back to JSON.parse for unencrypted values.
 */
function decryptJson(ciphertext) {
    if (!ciphertext) return {};
    const decrypted = decrypt(ciphertext);
    if (typeof decrypted !== 'string' || decrypted.startsWith(ENCRYPTION_PREFIX)) {
        // Decryption failed or not encrypted — try parsing as-is
        try { return JSON.parse(ciphertext); } catch { return {}; }
    }
    try { return JSON.parse(decrypted); } catch { return {}; }
}

/**
 * Deterministic hash for session token (used as stable primary key).
 * Uses HMAC-SHA256 with a fixed key derived from ENCRYPTION_KEY or a constant.
 */
function tokenHash(token) {
    const key = derivedKey || crypto.createHash('sha256').update('webmarketmc-session-key').digest();
    return crypto.createHmac('sha256', key).update(token).digest('hex');
}

// ── In-Memory Write-Through Cache ──────────────────────────────
// These cache Astra DB data for fast reads; writes go to DB first
// Cache stores DECRYPTED values — encryption only applies to DB storage
/** @type {Map<string, object>} serverId → server data */
const serverCache = new Map();
/** @type {Map<string, object>} tokenHash → session data */
const sessionCache = new Map();
/** @type {Map<string, object>} purchaseId → purchase data */
const purchaseCache = new Map();

// Track if initial cache load is done
let cacheReady = false;

// ── Astra DB Helper ─────────────────────────────────────────────
const ASTRA_TIMEOUT_MS = 10000;

async function astraFetch(table, method, pathSuffix, body) {
    if (!ASTRA_REST) return { ok: false, error: 'Astra not configured' };
    const url = `${ASTRA_REST}/${table}${pathSuffix ? '/' + pathSuffix : ''}`;
    const headers = {
        'Authorization': `Bearer ${ASTRA_TOKEN}`,
        'X-Cassandra-Token': ASTRA_TOKEN,
        'Content-Type': 'application/json',
    };
    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);

    // Add timeout via AbortController
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), ASTRA_TIMEOUT_MS);
    opts.signal = controller.signal;

    try {
        const resp = await fetch(url, opts);
        clearTimeout(timeoutId);
        if (resp.status === 204 || resp.status === 201) return { ok: true, status: resp.status, data: null };
        const text = await resp.text();
        let data = null;
        try { data = JSON.parse(text); } catch {}
        if (!resp.ok) {
            const errMsg = data?.description || data?.message || text.slice(0, 200);
            console.error(`[Astra] ${method} ${url} → ${resp.status}: ${errMsg}`);
            return { ok: false, status: resp.status, data, error: errMsg };
        }
        return { ok: true, status: resp.status, data };
    } catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            console.error(`[Astra] ${method} ${url} → timeout after ${ASTRA_TIMEOUT_MS}ms`);
            return { ok: false, error: 'timeout' };
        }
        console.error(`[Astra] ${method} ${url} → error:`, e.message);
        return { ok: false, error: e.message };
    }
}

// Get a single row by primary key
async function astraGet(table, pk) {
    const result = await astraFetch(table, 'GET', pk);
    // Preserve fetch errors (timeout, 500, network) so callers can
    // distinguish outages from missing rows
    if (!result.ok) return result;
    // Astra REST API returns 200 with { data: null } for non-existent PKs
    // instead of 404. Validate that data actually contains the row.
    if (result.data && result.data.data && result.data.data[Object.keys(result.data.data)[0]]) {
        return result;
    }
    return { ok: false, error: 'not found', data: null };
}

// Insert a row
async function astraInsert(table, row) {
    return astraFetch(table, 'POST', '', row);
}

// Update a row (partial by PK)
async function astraUpdate(table, pk, fields) {
    return astraFetch(table, 'PUT', pk, fields);
}

// Delete a row by PK
async function astraDelete(table, pk) {
    return astraFetch(table, 'DELETE', pk);
}

// Query rows with a filter (value is escaped for CQL safety)
async function astraQuery(table, column, value) {
    if (!ASTRA_REST) return { ok: false, data: null };
    const safeValue = String(value).replace(/"/g, '\\"');
    const where = encodeURIComponent(JSON.stringify({ [column]: { $eq: safeValue } }));
    const url = `${ASTRA_REST}/${table}?where=${where}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), ASTRA_TIMEOUT_MS);
    try {
        const resp = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${ASTRA_TOKEN}`,
                'X-Cassandra-Token': ASTRA_TOKEN,
            },
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        const text = await resp.text();
        let data = null;
        try { data = JSON.parse(text); } catch {}
        if (!resp.ok) {
            console.error(`[Astra] QUERY ${table} WHERE ${column}=${value} → ${resp.status}`);
            return { ok: false, data: null };
        }
        return { ok: true, data: data?.data || [] };
    } catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            console.error(`[Astra] QUERY ${table} → timeout`);
            return { ok: false, error: 'timeout' };
        }
        console.error(`[Astra] QUERY ${table} → error:`, e.message);
        return { ok: false, error: e.message };
    }
}

// ── Pagination helper: fetch all pages (with max limit to prevent OOM) ──────────────────────────
async function loadAllPages(table, pageSize = 500, maxRows = 1000) {
    if (!ASTRA_REST) return [];
    const all = [];
    let pageState = null;
    do {
        let url = `${ASTRA_REST}/${table}?pageSize=${pageSize}`;
        if (pageState) url += `&pageState=${encodeURIComponent(pageState)}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), ASTRA_TIMEOUT_MS);
        try {
            const resp = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${ASTRA_TOKEN}`,
                    'X-Cassandra-Token': ASTRA_TOKEN,
                },
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            const text = await resp.text();
            let data = null;
            try { data = JSON.parse(text); } catch {}
            if (!resp.ok || !data?.data) break;
            all.push(...data.data);
            if (all.length >= maxRows) {
                console.warn(`[Astra] loadAllPages ${table} → hit maxRows limit (${maxRows}), stopping`);
                break;
            }
            pageState = data.pageState || null;
        } catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') console.error(`[Astra] loadAllPages ${table} → timeout`);
            else console.error(`[Astra] loadAllPages ${table} → error:`, e.message);
            break;
        }
    } while (pageState);
    return all;
}

// ── Cache Load on Startup ──────────────────────────────────────
async function loadCacheFromDB() {
    if (!ASTRA_TOKEN) {
        console.log('[Cache] No ASTRA_TOKEN — running in memory-only mode');
        cacheReady = true;
        return;
    }

    console.log('[Cache] Loading data from Astra DB...');

    // Load servers (all pages, max 1000 to prevent OOM)
    const serverRows = await loadAllPages('servers', 500, 1000);
    for (const row of serverRows) {
        serverCache.set(row.server_id, deserializeServer(row));
    }
    console.log(`[Cache] Loaded ${serverCache.size} servers`);

    // Load sessions (only non-expired, max 2000)
    const sessionRows = await loadAllPages('sessions', 500, 2000);
    const now = Date.now();
    let loadedSessions = 0;
    for (const row of sessionRows) {
        if (row.expires > now) {
            const session = deserializeSession(row);
            const tokenKey = row.session_token; // PK is the tokenHash stored in session_token column
            sessionCache.set(tokenKey, session);
            loadedSessions++;
        }
    }
    console.log(`[Cache] Loaded ${loadedSessions} active sessions`);

    // Load purchases (only pending, not stale, max 2000)
    const purchaseRows = await loadAllPages('purchases', 500, 2000);
    const now2 = Date.now();
    let loadedPurchases = 0;
    for (const row of purchaseRows) {
        const age = now2 - row.created_at;
        if (row.status === 'pending' && age < 600_000) {
            purchaseCache.set(row.purchase_id, deserializePurchase(row));
            loadedPurchases++;
        } else if (row.status !== 'pending' && age < 300_000) {
            purchaseCache.set(row.purchase_id, deserializePurchase(row));
            loadedPurchases++;
        }
    }
    console.log(`[Cache] Loaded ${loadedPurchases} recent purchases`);

    cacheReady = true;
    console.log('[Cache] Ready');
}

// ── Serialization Helpers (with encryption) ─────────────────────
// Serialization ENCRYPTS sensitive fields before writing to Astra DB.
// Deserialization DECRYPTS fields when reading from Astra DB.
// The in-memory cache always stores plaintext (decrypted) values.

function serializeServer(s) {
    return {
        server_id: s.serverId,
        api_key: encrypt(s.apiKey),
        server_name: s.serverName || 'Minecraft Server',
        last_sync: s.lastSync || Date.now(),
        categories_json: JSON.stringify(s.categories || []),
        items_json: JSON.stringify(s.items || {}),
        auctions_json: s.auctionsJson || '[]',
        orders_json: s.ordersJson || '[]',
        stocks_json: s.stocksJson || '[]',
        price_history_json: s.priceHistoryJson || '{}',
    };
}

function deserializeServer(row) {
    let categories = [], items = {};
    try { categories = JSON.parse(row.categories_json || '[]'); } catch {}
    try { items = JSON.parse(row.items_json || '{}'); } catch {}
    return {
        serverId: row.server_id,
        apiKey: decrypt(row.api_key),
        serverName: row.server_name,
        lastSync: row.last_sync,
        categories,
        items,
        auctionsJson: row.auctions_json || '[]',
        ordersJson: row.orders_json || '[]',
        stocksJson: row.stocks_json || '[]',
        priceHistoryJson: row.price_history_json || '{}',
    };
}

function serializeSession(token, s) {
    return {
        session_token: tokenHash(token), // PK is deterministic hash
        server_id: s.serverId,
        player_uuid: encrypt(s.playerUuid),
        player_name: s.playerName || 'Player',
        balances_json: encryptJson(s.balances || {}),
        default_currency: s.defaultCurrency || 'Aurels',
        expires: s.expires,
    };
}

function deserializeSession(row) {
    return {
        serverId: row.server_id,
        playerUuid: decrypt(row.player_uuid),
        playerName: row.player_name || 'Player',
        balances: decryptJson(row.balances_json),
        defaultCurrency: row.default_currency || 'Aurels',
        expires: row.expires,
    };
}

function serializePurchase(id, p) {
    return {
        purchase_id: id,
        server_id: p.serverId,
        player_uuid: encrypt(p.playerUuid),
        type: p.type,
        item_key: p.item || p.itemKey || '',
        auction_id: p.auctionId || 0,
        order_id: p.orderId || 0,
        amount: String(p.amount || 0),
        status: p.status,
        created_at: p.createdAt,
        result_json: p.result ? encrypt(JSON.stringify(p.result)) : '',
    };
}

function deserializePurchase(row) {
    let result = null;
    const resultRaw = decrypt(row.result_json || '');
    try { result = JSON.parse(resultRaw || 'null'); } catch {}
    return {
        serverId: row.server_id,
        playerUuid: decrypt(row.player_uuid),
        type: row.type,
        item: row.item_key,
        itemKey: row.item_key,
        auctionId: row.auction_id,
        orderId: row.order_id,
        amount: row.type === 'bid' || row.type === 'fill_order' ? parseFloat(row.amount) : parseInt(row.amount),
        status: row.status,
        createdAt: row.created_at,
        result,
    };
}

// ── Security Middleware ──────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: 'https://webaureliummc.onrender.com' }));

// Rate limit: 330 requests per minute per IP (before body parser to avoid parsing large payloads)
app.use('/api/', rateLimit({
    windowMs: 60_000,
    max: 330,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please slow down.' },
    skip: (req) => {
        const sid = req.headers['x-server-id'];
        const s = serverCache.get(sid);
        return s && s.apiKey === req.headers['x-api-key'];
    }
}));

// Trust proxy for Render (behind single proxy)
app.set('trust proxy', 1);

// Body parser with 50mb limit for large sync payloads
app.use(express.json({ limit: '50mb' }));

// ── Middleware: API Key Auth ─────────────────────────────────────
function requireApiKey(req, res, next) {
    const serverId = req.params.serverId || req.body.serverId || req.query.serverId;
    const apiKey = req.headers['x-api-key'];

    if (!serverId || !apiKey) {
        return res.status(401).json({ error: 'Missing server ID or API key' });
    }

    const server = serverCache.get(serverId);
    if (!server || server.apiKey !== apiKey) {
        return res.status(403).json({ error: 'Invalid server ID or API key' });
    }

    req.serverId = serverId;
    req.server = server;
    next();
}

// ═══════════════════════════════════════════════════════════════════
// PLUGIN → RENDER  (MC server pushes data here)
// ═══════════════════════════════════════════════════════════════════

/** POST /api/register — MC plugin registers on startup */
app.post('/api/register', async (req, res) => {
    const regSecret = process.env.REGISTRATION_SECRET || '';
    const { serverId, apiKey, serverName } = req.body;

    if (!serverId || !apiKey) {
        return res.status(400).json({ error: 'Missing serverId or apiKey' });
    }

    // Check if server already exists in cache
    if (serverCache.has(serverId)) {
        const existing = serverCache.get(serverId);
        if (existing.apiKey !== apiKey) {
            // API key mismatch — allow rotation if caller proves knowledge of
            // current key (x-current-api-key header) OR REGISTRATION_SECRET is set.
            // This prevents takeover via public /shop/:serverId URL while allowing
            // legitimate server restarts (which know their current key).
            const currentKeyHeader = req.headers['x-current-api-key'];
            const knowsCurrentKey = currentKeyHeader && currentKeyHeader === existing.apiKey;
            const hasRegSecret = regSecret && req.headers['x-registration-secret'] === regSecret;

            if (!knowsCurrentKey && !hasRegSecret) {
                console.log(`[Register] API key mismatch for ${serverId} — rejecting (no proof of current key or REGISTRATION_SECRET)`);
                return res.status(403).json({ error: 'Server ID already registered with different API key. Provide x-current-api-key header with current key, or configure REGISTRATION_SECRET.' });
            }
            console.log(`[Register] API key updated for ${serverId} (authorized key rotation)`);
            const oldApiKey = existing.apiKey;
            const oldServerName = existing.serverName;
            const oldLastSync = existing.lastSync;
            existing.apiKey = apiKey;
            existing.serverName = serverName || existing.serverName;
            existing.lastSync = Date.now();
            if (ASTRA_TOKEN) {
                const updateResult = await astraUpdate('servers', serverId, {
                    api_key: encrypt(apiKey),
                    server_name: existing.serverName,
                    last_sync: existing.lastSync,
                });
                if (!updateResult.ok) {
                    // Rollback cache to pre-rotation state so a retry takes the mismatch path again
                    existing.apiKey = oldApiKey;
                    existing.serverName = oldServerName;
                    existing.lastSync = oldLastSync;
                    console.error('[Register] Failed to persist API key rotation to Astra:', updateResult.error);
                    return res.status(500).json({ error: 'Failed to update server credentials' });
                }
            }
            return res.json({ success: true, reRegistered: true });
        } else {
            // Same key — re-register: update lastSync
            existing.lastSync = Date.now();
            if (ASTRA_TOKEN) {
                await astraUpdate('servers', serverId, { last_sync: existing.lastSync });
            }
            return res.json({ success: true });
        }
    }

    // Check Astra DB for existing server (may have survived a restart)
    if (ASTRA_TOKEN) {
        const dbResult = await astraGet('servers', serverId);
        if (dbResult.ok && dbResult.data?.data) {
            const existing = deserializeServer(dbResult.data.data);
            if (existing.apiKey !== apiKey) {
                // API key mismatch — allow rotation if caller proves knowledge of
                // current key (x-current-api-key header) OR REGISTRATION_SECRET is set.
                const currentKeyHeader = req.headers['x-current-api-key'];
                const knowsCurrentKey = currentKeyHeader && currentKeyHeader === existing.apiKey;
                const hasRegSecret = regSecret && req.headers['x-registration-secret'] === regSecret;
                
                if (!knowsCurrentKey && !hasRegSecret) {
                    console.log(`[Register] DB API key mismatch for ${serverId} — rejecting (no proof of current key or REGISTRATION_SECRET)`);
                    return res.status(403).json({ error: 'Server ID already registered with different API key. Provide x-current-api-key header with current key, or configure REGISTRATION_SECRET.' });
                }
                console.log(`[Register] DB API key updated for ${serverId} (authorized key rotation)`);
                const oldApiKey = existing.apiKey;
                existing.apiKey = apiKey;
                existing.serverName = serverName || existing.serverName;
                existing.lastSync = Date.now();
                const updateResult = await astraUpdate('servers', serverId, {
                    api_key: encrypt(apiKey),
                    server_name: existing.serverName,
                    last_sync: existing.lastSync,
                });
                if (!updateResult.ok) {
                    // Don't cache the new key — leave Astra as source of truth with old key
                    console.error('[Register] Failed to persist API key rotation to Astra:', updateResult.error);
                    return res.status(500).json({ error: 'Failed to update server credentials' });
                }
                serverCache.set(serverId, existing);
                return res.json({ success: true, reRegistered: true });
            } else {
                // Same key — restore to cache
                existing.lastSync = Date.now();
                serverCache.set(serverId, existing);
                await astraUpdate('servers', serverId, { last_sync: existing.lastSync });
                console.log(`[Register] Restored server "${existing.serverName}" from DB (${serverId})`);
                return res.json({ success: true });
            }
        }
    }

    // New server — create it. Require REGISTRATION_SECRET if set on the dashboard.
    if (regSecret && req.headers['x-registration-secret'] !== regSecret) {
        return res.status(403).json({ error: 'Invalid registration secret. New servers must provide x-registration-secret header matching REGISTRATION_SECRET env var.' });
    }

    const server = {
        serverId,
        apiKey,
        serverName: serverName || 'Minecraft Server',
        lastSync: Date.now(),
        categories: [],
        items: {},
        auctionsJson: '[]',
        ordersJson: '[]',
        stocksJson: '[]',
        priceHistoryJson: '{}',
    };

    serverCache.set(serverId, server);

    if (ASTRA_TOKEN) {
        await astraInsert('servers', serializeServer(server));
    }

    console.log(`[Register] Server "${serverName}" registered as ${serverId}`);
    res.json({ success: true });
});

/** DELETE /api/servers/:serverId — admin endpoint to clear a stuck server registration (requires REGISTRATION_SECRET) */
app.delete('/api/servers/:serverId', async (req, res) => {
    const regSecret = process.env.REGISTRATION_SECRET;
    if (!regSecret) {
        return res.status(403).json({ error: 'Admin endpoint disabled — REGISTRATION_SECRET not configured' });
    }
    if (req.headers['x-registration-secret'] !== regSecret) {
        return res.status(403).json({ error: 'Invalid registration secret' });
    }
    const { serverId } = req.params;
    serverCache.delete(serverId);
    if (ASTRA_TOKEN) {
        const delResult = await astraDelete('servers', serverId);
        if (!delResult.ok) {
            console.error(`[Admin] Failed to delete ${serverId} from Astra:`, delResult.error);
            return res.status(500).json({ error: 'Failed to delete from DB' });
        }
    }
    console.log(`[Admin] Deleted server ${serverId}`);
    res.json({ success: true });
});

/** POST /api/sync — MC plugin pushes market data + auctions + orders + stocks */
app.post('/api/sync', requireApiKey, async (req, res) => {
    const { categories, items, auctions, orders, stocks, priceHistory, customItems } = req.body;
    const server = req.server;

    if (categories) server.categories = categories;
    if (items) server.items = items;

    // ── Custom Items from Aurelium Scanner ─────────────────
    const safeItems = Array.isArray(customItems) ? customItems : [];
    const mapped = safeItems
        .filter(item => typeof item === 'object' && item !== null && typeof item.name === 'string')
        .map(item => {
            const price = item.buyPrice ?? item.price ?? 0;
            return {
                key: item.id ?? item.key ?? '',
                name: item.name,
                material: item.material ?? 'stone',
                price,
                priceFormatted: (item.currencySymbol ?? '$') + Number(price).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }),
                currency: item.currency ?? '',
                currencySymbol: item.currencySymbol ?? '$',
            };
        });
    server.items['CUSTOM_ITEMS'] = mapped;
    const catIdx = server.categories.findIndex(c => c.id === 'CUSTOM_ITEMS');
    if (mapped.length > 0) {
        if (catIdx === -1) {
            server.categories.push({
                id: 'CUSTOM_ITEMS',
                name: 'Custom Items',
                icon: 'knowledge_book',
                itemCount: mapped.length,
            });
        } else {
            server.categories[catIdx].itemCount = mapped.length;
        }
    } else {
        delete server.items['CUSTOM_ITEMS'];
        if (catIdx !== -1) server.categories.splice(catIdx, 1);
    }

    // Store bulk data as raw JSON strings
    if (auctions) server.auctionsJson = JSON.stringify(auctions);
    if (orders) server.ordersJson = JSON.stringify(orders);
    if (stocks) server.stocksJson = JSON.stringify(stocks);
    if (priceHistory) server.priceHistoryJson = JSON.stringify(priceHistory);
    server.lastSync = Date.now();

    // Persist to Astra (await for durability)
    // Only persist lightweight data — auctions/orders/stocks/priceHistory are large
    // and cause 413 errors. Plugin resends full data on every sync anyway.
    if (ASTRA_TOKEN) {
        await astraUpdate('servers', req.serverId, {
            categories_json: JSON.stringify(server.categories),
            items_json: JSON.stringify(server.items),
            last_sync: server.lastSync,
        });
    }

    res.json({
        success: true,
        pendingPurchases: getPendingPurchases(req.serverId).map(p => ({
            id: p.id, itemKey: p.itemKey, amount: p.amount,
            currency: p.currency, status: p.status,
        })),
    });
});

/** POST /api/session — MC plugin creates a player session */
app.post('/api/session', requireApiKey, async (req, res) => {
    const { token, playerUuid, playerName, balances, defaultCurrency } = req.body;

    if (!token || !playerUuid) {
        return res.status(400).json({ error: 'Missing token or playerUuid' });
    }

    const session = {
        serverId: req.serverId,
        playerUuid,
        playerName: playerName || 'Player',
        balances: balances || {},
        defaultCurrency: defaultCurrency || 'Aurels',
        expires: Date.now() + 3_600_000,
    };

    // Cache key is deterministic tokenHash — encryption only applies to DB storage
    const tokenKey = tokenHash(token);
    sessionCache.set(tokenKey, session);

    if (ASTRA_TOKEN) {
        await astraInsert('sessions', serializeSession(token, session));
    }

    res.json({ success: true });
});

/** POST /api/session-update — MC plugin updates a player's balance after purchase */
app.post('/api/session-update', requireApiKey, async (req, res) => {
    const { playerUuid, balances } = req.body;

    // Update all sessions for this player on this server
    const updates = [];
    for (const [tokenKey, session] of sessionCache) {
        if (session.serverId === req.serverId && session.playerUuid === playerUuid) {
            session.balances = balances;
            if (ASTRA_TOKEN) {
                // Need to find the original token to get the PK (tokenHash)
                // Since we only have tokenKey (which IS the tokenHash), we can use it directly
                updates.push(astraUpdate('sessions', tokenKey, {
                    balances_json: encryptJson(balances),
                }).catch(e => console.error('[Astra] Session update failed:', e.message)));
            }
        }
    }

    await Promise.allSettled(updates);
    res.json({ success: true });
});

/** POST /api/confirm-purchase — MC plugin confirms a purchase was executed */
app.post('/api/confirm-purchase', requireApiKey, async (req, res) => {
    const { purchaseId, success, newBalance, spent } = req.body;

    const purchase = purchaseCache.get(purchaseId);
    if (!purchase || purchase.serverId !== req.serverId) {
        return res.status(404).json({ error: 'Purchase not found' });
    }

    purchase.status = success ? 'completed' : 'failed';
    purchase.result = { newBalance, spent, success };

    if (ASTRA_TOKEN) {
        await astraUpdate('purchases', purchaseId, {
            status: purchase.status,
            result_json: encrypt(JSON.stringify(purchase.result)),
        });
    }

    res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
// BROWSER → RENDER  (player dashboard requests)
// ═══════════════════════════════════════════════════════════════════

/** Middleware: validate session token for browser requests */
async function requireSession(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const tokenKey = tokenHash(token);
    const session = sessionCache.get(tokenKey);
    if (!session) return res.status(401).json({ error: 'Invalid or expired session. Use /web in-game.' });
    if (session.expires < Date.now()) {
        sessionCache.delete(tokenKey);
        if (ASTRA_TOKEN) await astraDelete('sessions', tokenKey).catch(() => {});
        return res.status(401).json({ error: 'Session expired. Use /web in-game.' });
    }

    // Rolling 1-hour timeout
    session.expires = Date.now() + 3_600_000;
    if (ASTRA_TOKEN) {
        await astraUpdate('sessions', tokenKey, { expires: session.expires }).catch(() => {});
    }

    req.session = session;
    req.serverId = session.serverId;
    req.server = serverCache.get(session.serverId);

    if (!req.server) {
        return res.status(503).json({ error: 'Server is offline' });
    }

    next();
}

/** GET /api/:serverId/player — Browser gets player info */
app.get('/api/:serverId/player', requireSession, (req, res) => {
    const s = req.session;
    res.json({
        name: s.playerName,
        uuid: s.playerUuid,
        defaultCurrency: s.defaultCurrency,
        balances: s.balances,
    });
});

/** GET /api/:serverId/categories — Browser gets categories */
app.get('/api/:serverId/categories', requireSession, (req, res) => {
    res.json(req.server.categories || []);
});

/** GET /api/:serverId/items?category=X&page=0 — Browser gets items */
app.get('/api/:serverId/items', requireSession, (req, res) => {
    const catId = req.query.category || '';
    const page = parseInt(req.query.page) || 0;
    const perPage = 28;

    const allItems = req.server.items?.[catId] || [];
    const totalPages = Math.max(1, Math.ceil(allItems.length / perPage));
    const start = page * perPage;
    const pageItems = allItems.slice(start, start + perPage);

    res.json({ page, totalPages, totalItems: allItems.length, items: pageItems });
});

/** GET /api/:serverId/search?q=X&page=0 — Browser searches items */
app.get('/api/:serverId/search', requireSession, (req, res) => {
    const query = (req.query.q || '').toLowerCase();
    const page = parseInt(req.query.page) || 0;
    const perPage = 28;

    if (!query) return res.status(400).json({ error: 'Missing search query' });

    const results = [];
    const seen = new Set();
    const items = req.server.items || {};
    for (const catItems of Object.values(items)) {
        for (const item of catItems) {
            const key = item.key || item.name;
            if (!seen.has(key) && item.name.toLowerCase().includes(query)) {
                seen.add(key);
                results.push(item);
            }
        }
    }

    const totalPages = Math.max(1, Math.ceil(results.length / perPage));
    const start = page * perPage;
    const pageItems = results.slice(start, start + perPage);

    res.json({ page, totalPages, totalItems: results.length, items: pageItems });
});

/** GET /api/:serverId/auctions — Browser gets active auctions */
app.get('/api/:serverId/auctions', requireSession, (req, res) => {
    res.type('json').send(req.server.auctionsJson || '[]');
});

/** GET /api/:serverId/orders — Browser gets active buy orders */
app.get('/api/:serverId/orders', requireSession, (req, res) => {
    res.type('json').send(req.server.ordersJson || '[]');
});

/** GET /api/:serverId/stocks — Browser gets stock/price data */
app.get('/api/:serverId/stocks', requireSession, (req, res) => {
    res.type('json').send(req.server.stocksJson || '[]');
});

/** GET /api/:serverId/price-history — Browser gets price history for charts */
app.get('/api/:serverId/price-history', requireSession, (req, res) => {
    res.type('json').send(req.server.priceHistoryJson || '{}');
});

/** POST /api/:serverId/buy — Browser submits a purchase */
app.post('/api/:serverId/buy', requireSession, async (req, res) => {
    const { item, amount } = req.body;

    // Strict validation: amount must be a finite integer 1-64
    const quantity = Number(amount);
    if (!item || !Number.isInteger(quantity) || quantity < 1 || quantity > 64) {
        return res.status(400).json({ error: 'Invalid item or amount' });
    }

    const purchaseId = crypto.randomUUID();
    const purchase = {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: 'buy',
        item,
        itemKey: item,
        amount: quantity,
        status: 'pending',
        createdAt: Date.now(),
    };

    purchaseCache.set(purchaseId, purchase);

    if (ASTRA_TOKEN) {
        await astraInsert('purchases', serializePurchase(purchaseId, purchase));
    }

    res.json({ success: true, purchaseId, message: 'Purchase queued — delivering in-game...' });
});

/** POST /api/:serverId/bid — Browser submits an auction bid */
app.post('/api/:serverId/bid', requireSession, async (req, res) => {
    const { auctionId, amount } = req.body;

    // Strict validation: auctionId must be integer, amount must be finite > 0
    const parsedAuctionId = parseInt(auctionId);
    const parsedAmount = parseFloat(amount);
    if (!auctionId || !Number.isInteger(parsedAuctionId) || parsedAuctionId <= 0 ||
        amount == null || !Number.isFinite(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Invalid auction or amount' });
    }

    const purchaseId = crypto.randomUUID();
    const purchase = {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: 'bid',
        auctionId: parsedAuctionId,
        amount: parsedAmount,
        status: 'pending',
        createdAt: Date.now(),
    };

    purchaseCache.set(purchaseId, purchase);

    if (ASTRA_TOKEN) {
        await astraInsert('purchases', serializePurchase(purchaseId, purchase));
    }

    res.json({ success: true, purchaseId, message: 'Bid queued — confirming in-game...' });
});

/** POST /api/:serverId/fill-order — Browser submits items to fulfill a buy order */
app.post('/api/:serverId/fill-order', requireSession, async (req, res) => {
    const { orderId, amount } = req.body;

    // Strict validation: orderId must be integer, amount must be integer > 0
    const parsedOrderId = parseInt(orderId);
    const parsedAmount = parseInt(amount);
    if (!orderId || !Number.isInteger(parsedOrderId) || parsedOrderId <= 0 ||
        amount == null || !Number.isInteger(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Invalid order or amount' });
    }

    const purchaseId = crypto.randomUUID();
    const purchase = {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: 'fill_order',
        orderId: parsedOrderId,
        amount: parsedAmount,
        status: 'pending',
        createdAt: Date.now(),
    };

    purchaseCache.set(purchaseId, purchase);

    if (ASTRA_TOKEN) {
        await astraInsert('purchases', serializePurchase(purchaseId, purchase));
    }

    res.json({ success: true, purchaseId, message: 'Fulfillment queued — verifying in-game inventory...' });
});

/** GET /api/:serverId/purchase-status?id=X — Browser polls purchase result */
app.get('/api/:serverId/purchase-status', requireSession, (req, res) => {
    const id = req.query.id;
    const purchase = purchaseCache.get(id);

    if (!purchase) return res.status(404).json({ error: 'Purchase not found' });

    // IDOR protection
    if (purchase.playerUuid !== req.session.playerUuid) {
        return res.status(403).json({ error: 'Not your purchase' });
    }

    res.json({
        status: purchase.status,
        result: purchase.result || null,
    });
});

// ═══════════════════════════════════════════════════════════════════
// STATIC FILES + DASHBOARD PAGE
// ═══════════════════════════════════════════════════════════════════

app.use('/static', express.static(path.join(__dirname, 'public')));

// Landing page
app.get('/', (req, res) => {
    const gaId = process.env.GA_MEASUREMENT_ID || 'G-RCQKF2LJVQ';
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Aurelium Web Market</title>
<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=${gaId}"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', '${gaId}');
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#111218; color:#e8e8ec; font-family:'Inter', sans-serif; }
.box { text-align:center; padding:48px 40px; border-radius:12px; background:#1e1f25; border:1px solid #2d2e36; box-shadow:0 8px 32px rgba(0,0,0,0.5); max-width:400px; width:90%; }
.logo { display:flex; align-items:center; justify-content:center; gap:12px; margin-bottom:24px; }
.logo svg { width:32px; height:32px; color:#f59e0b; fill:none; stroke:currentColor; stroke-width:2.2; stroke-linecap:round; stroke-linejoin:round; }
.logo-title { font-size:24px; font-weight:800; background:linear-gradient(135deg, #f59e0b, #eab308); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin:0; }
p { color:#9a9aad; font-size:15px; line-height:1.5; margin:0 0 32px 0; }
code { background:#111218; padding:4px 8px; border-radius:6px; color:#1bd96a; font-weight:600; font-family:monospace; border:1px solid #2d2e36; }
.link-btn { display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:12px 24px; background:#3b82f6; color:#fff; text-decoration:none; border-radius:8px; font-weight:600; font-size:14px; transition:all 0.2s ease; width:100%; box-sizing:border-box; }
.link-btn:hover { background:#2563eb; transform:translateY(-1px); box-shadow:0 4px 12px rgba(59,130,246,0.3); }
</style></head><body>
<div class="box">
    <div class="logo">
        <svg viewBox="0 0 24 24"><path d="M14.5 2l7.5 7.5-7 7-7.5-7.5z"/><path d="M2 22l7-7"/><path d="M11 13l3.5-3.5"/></svg>
        <h1 class="logo-title">Server Market</h1>
    </div>
    <p>Run <code>/web</code> in-game to get your personal dashboard link and start trading!</p>
    <a href="https://modrinth.com/plugin/aurelium" target="_blank" class="link-btn">
        <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width:18px;height:18px;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Download Plugin
    </a>
</div>
</body></html>`);
});

// Dashboard entry point
let indexHtmlCache = null;
setInterval(() => { indexHtmlCache = null; }, 3600_000);
app.get('/shop/:serverId', (req, res) => {
    try {
        if (!indexHtmlCache) {
            indexHtmlCache = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
        }
        const gaId = process.env.GA_MEASUREMENT_ID || 'G-RCQKF2LJVQ';
        const finalHtml = indexHtmlCache.replace(/G-XXXXXXXXXX/g, gaId);
        res.send(finalHtml);
    } catch (e) {
        console.error('Failed to serve index.html:', e);
        res.status(500).send('Server Error');
    }
});

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function getPendingPurchases(serverId, playerUuid) {
    const pending = [];
    for (const [id, p] of purchaseCache) {
        if (p.serverId === serverId && p.status === 'pending' && (!playerUuid || p.playerUuid === playerUuid)) {
            pending.push({ id, ...p });
        }
    }
    return pending;
}

// Cleanup expired sessions and old purchases every 60 seconds
setInterval(async () => {
    const now = Date.now();
    const sessionDeletes = [];
    const purchaseDeletes = [];
    const serverDeletes = [];

    for (const [tokenKey, session] of sessionCache) {
        if (session.expires < now) {
            sessionCache.delete(tokenKey);
            sessionDeletes.push(tokenKey);
        }
    }

    for (const [id, p] of purchaseCache) {
        if (p.status !== 'pending' && now - p.createdAt > 300_000) {
            purchaseCache.delete(id);
            purchaseDeletes.push(id);
        } else if (p.status === 'pending' && now - p.createdAt > 600_000) {
            purchaseCache.delete(id);
            purchaseDeletes.push(id);
        }
    }

    for (const [id, server] of serverCache) {
        if (now - server.lastSync > 300_000) {
            const hasActive = [...sessionCache.values()].some(s => s.serverId === id);
            if (!hasActive) {
                console.log(`[Cleanup] Removing stale server "${server.serverName}" (${id})`);
                serverCache.delete(id);
                serverDeletes.push(id);
            }
        }
    }

    // Batch delete from Astra (tokenKey is already the PK for sessions)
    if (ASTRA_TOKEN) {
        for (const tokenKey of sessionDeletes) {
            await astraDelete('sessions', tokenKey).catch(() => {});
        }
        for (const id of purchaseDeletes) {
            await astraDelete('purchases', id).catch(() => {});
        }
        for (const id of serverDeletes) {
            await astraDelete('servers', id).catch(() => {});
        }
    }
}, 60_000);

// ═══════════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;

async function start() {
    // Load cache from Astra DB before serving requests
    await loadCacheFromDB();

    app.listen(PORT, () => {
        console.log(`Aurelium Web Dashboard running on port ${PORT}`);
        console.log(`Persistence: ${ASTRA_TOKEN ? 'Astra DB + in-memory cache' : 'in-memory only (no ASTRA_TOKEN)'}`);
        console.log(`Encryption: ${encryptionEnabled ? 'AES-256-GCM (field-level)' : 'disabled (no ENCRYPTION_KEY)'}`);
    });
}

start().catch(e => {
    console.error('Failed to start:', e);
    process.exit(1);
});
