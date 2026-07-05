/**
 * Aurelium Web Dashboard — Central Server
 * 
 * A single Express instance that handles market dashboards
 * for multiple Minecraft servers. Each MC server syncs its
 * data here via outbound HTTP — no ports needed on the MC side.
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
const ASTRA_DB_ID = process.env.ASTRA_DB_ID || '165b585e-7ece-4015-987f-165032706b56';
const ASTRA_REGION = process.env.ASTRA_REGION || 'us-east-2';
const ASTRA_KEYSPACE = process.env.ASTRA_KEYSPACE || 'webmarketmc';
const ASTRA_BASE = `https://${ASTRA_DB_ID}-${ASTRA_REGION}.apps.astra.datastax.com`;
const ASTRA_REST = `${ASTRA_BASE}/api/rest/v2/keyspaces/${ASTRA_KEYSPACE}`;

const MAX_RAM_MB = 500;
const MAX_QUEUE_SIZE = 50;
const registrationQueue = [];

// ── In-Memory Write-Through Cache ──────────────────────────────
// These cache Astra DB data for fast reads; writes go to DB first
/** @type {Map<string, object>} serverId → server data */
const serverCache = new Map();
/** @type {Map<string, object>} token → session data */
const sessionCache = new Map();
/** @type {Map<string, object>} purchaseId → purchase data */
const purchaseCache = new Map();

// Track if initial cache load is done
let cacheReady = false;
let cacheReadyPromise = null;

// ── Astra DB Helper ─────────────────────────────────────────────
async function astraFetch(table, method, pathSuffix, body) {
    const url = `${ASTRA_REST}/${table}${pathSuffix ? '/' + pathSuffix : ''}`;
    const headers = {
        'Authorization': `Bearer ${ASTRA_TOKEN}`,
        'X-Cassandra-Token': ASTRA_TOKEN,
        'Content-Type': 'application/json',
    };
    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);

    const resp = await fetch(url, opts);
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
}

// Get a single row by primary key
async function astraGet(table, pk) {
    return astraFetch(table, 'GET', pk);
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
    const safeValue = String(value).replace(/"/g, '\\"');
    const url = `${ASTRA_REST}/${table}?where={"${column}":{"$eq":"${safeValue}"}}`;
    const resp = await fetch(url, {
        headers: {
            'Authorization': `Bearer ${ASTRA_TOKEN}`,
            'X-Cassandra-Token': ASTRA_TOKEN,
        },
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch {}
    if (!resp.ok) {
        console.error(`[Astra] QUERY ${table} WHERE ${column}=${value} → ${resp.status}`);
        return { ok: false, data: null };
    }
    return { ok: true, data: data?.data || [] };
}

// ── Cache Load on Startup ──────────────────────────────────────
async function loadCacheFromDB() {
    if (!ASTRA_TOKEN) {
        console.log('[Cache] No ASTRA_TOKEN — running in memory-only mode');
        cacheReady = true;
        return;
    }

    console.log('[Cache] Loading data from Astra DB...');

    // Load servers
    const serversResp = await astraFetch('servers', 'GET', '?pageSize=100');
    if (serversResp.ok && serversResp.data?.data) {
        for (const row of serversResp.data.data) {
            serverCache.set(row.server_id, deserializeServer(row));
        }
        console.log(`[Cache] Loaded ${serverCache.size} servers`);
    }

    // Load sessions (only non-expired)
    const sessionsResp = await astraFetch('sessions', 'GET', '?pageSize=500');
    if (sessionsResp.ok && sessionsResp.data?.data) {
        const now = Date.now();
        let loaded = 0;
        for (const row of sessionsResp.data.data) {
            if (row.expires > now) {
                sessionCache.set(row.session_token, deserializeSession(row));
                loaded++;
            }
        }
        console.log(`[Cache] Loaded ${loaded} active sessions`);
    }

    // Load purchases (only pending, not stale)
    const purchasesResp = await astraFetch('purchases', 'GET', '?pageSize=500');
    if (purchasesResp.ok && purchasesResp.data?.data) {
        const now = Date.now();
        let loaded = 0;
        for (const row of purchasesResp.data.data) {
            const age = now - row.created_at;
            if (row.status === 'pending' && age < 600_000) {
                purchaseCache.set(row.purchase_id, deserializePurchase(row));
                loaded++;
            } else if (row.status !== 'pending' && age < 300_000) {
                purchaseCache.set(row.purchase_id, deserializePurchase(row));
                loaded++;
            }
        }
        console.log(`[Cache] Loaded ${loaded} recent purchases`);
    }

    cacheReady = true;
    console.log('[Cache] Ready');
}

// ── Serialization Helpers ──────────────────────────────────────
function serializeServer(s) {
    return {
        server_id: s.serverId,
        api_key: s.apiKey,
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
        apiKey: row.api_key,
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
        session_token: token,
        server_id: s.serverId,
        player_uuid: s.playerUuid,
        player_name: s.playerName || 'Player',
        balances_json: JSON.stringify(s.balances || {}),
        default_currency: s.defaultCurrency || 'Aurels',
        expires: s.expires,
    };
}

function deserializeSession(row) {
    let balances = {};
    try { balances = JSON.parse(row.balances_json || '{}'); } catch {}
    return {
        serverId: row.server_id,
        playerUuid: row.player_uuid,
        playerName: row.player_name || 'Player',
        balances,
        defaultCurrency: row.default_currency || 'Aurels',
        expires: row.expires,
    };
}

function serializePurchase(id, p) {
    return {
        purchase_id: id,
        server_id: p.serverId,
        player_uuid: p.playerUuid,
        type: p.type,
        item_key: p.item || p.itemKey || '',
        auction_id: p.auctionId || 0,
        order_id: p.orderId || 0,
        amount: String(p.amount || 0),
        status: p.status,
        created_at: p.createdAt,
        result_json: p.result ? JSON.stringify(p.result) : '',
    };
}

function deserializePurchase(row) {
    let result = null;
    try { result = JSON.parse(row.result_json || 'null'); } catch {}
    return {
        serverId: row.server_id,
        playerUuid: row.player_uuid,
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
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabled for inline styles
app.use(cors({ origin: 'https://webaureliummc.onrender.com' }));
app.use(express.json({ limit: '15mb' }));

// Rate limit: 330 requests per minute per IP
app.use('/api/', rateLimit({
    windowMs: 60_000,
    max: 330, // Increased to 330 as requested
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please slow down.' },
    // Skip rate limiting for MC servers that provide a valid API Key
    // Server-to-server sync endpoints have their own auth, but purchases/bids still get rate-limited
    skip: (req) => {
        const sid = req.headers['x-server-id']; const s = servers.get(sid);
        const isServerAuthed = s && s.apiKey === req.headers['x-api-key'];
        if (!isServerAuthed) return false;
        // Only skip rate limit for read/sync endpoints, NOT for purchase/bid/fill-order
        const purchasePaths = ['/buy', '/bid', '/fill-order'];
        return !purchasePaths.some(p => req.path.endsWith(p));
    }
}));

// ── In-Memory Data Stores ────────────────────────────────────────

/** @type {Map<string, ServerData>} serverId → full dashboard data */
const servers = new Map();

/** @type {Map<string, SessionData>} token → session data */
const sessions = new Map();

/** @type {Map<string, PurchaseData>} purchaseId → purchase data */
const purchases = new Map();

/** @type {Map<string, number>} "serverId:auctionId:playerUuid" → timestamp of last bid/purchase */
const recentActions = new Map();
const ACTION_COOLDOWN_MS = 3000; // 3s cooldown between actions on same auction

// ── Types (for documentation) ────────────────────────────────────
// ServerData:  { apiKey, serverName, lastSync, categories[], items{},
//               auctionsJson, ordersJson, stocksJson, priceHistoryJson }
//   → auctions/orders/stocks/priceHistory stored as raw JSON strings for RAM efficiency
// SessionData: { serverId, playerUuid, playerName, balances, defaultCurrency, expires }
// PurchaseData: { serverId, playerUuid, item, amount, status, createdAt }

// ── Middleware: API Key Auth ─────────────────────────────────────

function requireApiKey(req, res, next) {
    const serverId = req.params.serverId || req.body.serverId || req.query.serverId;
    const apiKey = req.headers['x-api-key'];

    if (!serverId || !apiKey) {
        return res.status(401).json({ error: 'Missing server ID or API key' });
    }

    const server = servers.get(serverId);
    if (!server || server.apiKey !== apiKey) {
        return res.status(403).json({ error: 'Invalid server ID or API key' });
    }

    req.serverId = serverId;
    req.server = server;
    next();
}

// ══════════════════════════════════════════════════════════════════
// PLUGIN → RENDER  (MC server pushes data here)
// ══════════════════════════════════════════════════════════════════

/** POST /api/register — MC plugin registers on startup */
app.post('/api/register', (req, res) => {
  const regSecret = process.env.REGISTRATION_SECRET || '';
  if (regSecret && req.headers['x-registration-secret'] !== regSecret) {
    return res.status(403).json({ error: 'Invalid registration secret' });
  }
    const { serverId, apiKey, serverName } = req.body;

    if (!serverId || !apiKey) {
        return res.status(400).json({ error: 'Missing serverId or apiKey' });
    }

    // If server already exists with a different API key, accept the new key
    // (server may have regenerated its key on restart; serverId is a persistent UUID)
    if (servers.has(serverId)) {
        const existing = servers.get(serverId);
        if (existing.apiKey !== apiKey) {
            console.log(`[Register] API key updated for ${serverId} (was ${existing.apiKey.slice(0,8)}... → ${apiKey.slice(0,8)}...)`);
            existing.apiKey = apiKey;
            existing.serverName = serverName || existing.serverName;
            existing.lastSync = Date.now();
            res.json({ success: true, reRegistered: true });
            return;
        }
    } else {
        // Enforce Max RAM Activation Queue
        const memoryUsage = process.memoryUsage();
        const rssMB = memoryUsage.rss / 1024 / 1024;

        if (rssMB > MAX_RAM_MB) {
            if (registrationQueue.length >= MAX_QUEUE_SIZE) {
                return res.status(503).json({ error: 'Registration queue is full. Try again later.' });
            }
            if (!registrationQueue.includes(serverId)) {
                registrationQueue.push(serverId);
            }
            const position = registrationQueue.indexOf(serverId) + 1;
            console.log(`[Queue] Waitlisting "${serverName}" (${serverId}). RAM at ${Math.round(rssMB)}MB. Queue pos: ${position}`);
            return res.status(503).json({ error: 'Server waitlisted due to max RAM usage', queued: true, position });
        }

        // If memory is okay, but they are in the queue, only allow them if they are first (fairness)
        if (registrationQueue.includes(serverId)) {
            if (registrationQueue[0] !== serverId) {
                const position = registrationQueue.indexOf(serverId) + 1;
                return res.status(503).json({ error: 'Waiting in registration queue', queued: true, position });
            } else {
                registrationQueue.shift(); // Proceed to register
            }
        }
    }

    servers.set(serverId, {
        apiKey,
        serverName: serverName || 'Minecraft Server',
        lastSync: Date.now(),
        categories: [],
        items: {},
        auctionsJson: '[]',
        ordersJson: '[]',
        stocksJson: '[]',
        priceHistoryJson: '{}',
    });

    console.log(`[Register] Server "${serverName}" registered as ${serverId}`);
    res.json({ success: true });
});

/** POST /api/sync — MC plugin pushes market data + auctions + orders + stocks */
app.post('/api/sync', requireApiKey, (req, res) => {
    const { categories, items, auctions, orders, stocks, priceHistory, customItems } = req.body;
    const server = req.server;

    if (categories) server.categories = categories;
    if (items) server.items = items;

    // ── Custom Items from Aurelium Scanner ─────────────────
    // Merge scanner-discovered custom items — refreshed every sync
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

    // Store bulk data as raw JSON strings to minimize RAM footprint
    if (auctions) server.auctionsJson = JSON.stringify(auctions);
    if (orders) server.ordersJson = JSON.stringify(orders);
    if (stocks) server.stocksJson = JSON.stringify(stocks);
    if (priceHistory) server.priceHistoryJson = JSON.stringify(priceHistory);
    server.lastSync = Date.now();

    res.json({ success: true, pendingPurchases: getPendingPurchases(req.serverId).map(p => ({ id: p.id, type: p.type, itemKey: p.itemKey, auctionId: p.auctionId, orderId: p.orderId, amount: p.amount, quantity: p.quantity, currency: p.currency, playerUuid: p.playerUuid, status: p.status })) });
});

/** POST /api/session — MC plugin creates a player session */
app.post('/api/session', requireApiKey, (req, res) => {
    const { token, playerUuid, playerName, balances, defaultCurrency } = req.body;

    if (!token || !playerUuid) {
        return res.status(400).json({ error: 'Missing token or playerUuid' });
    }

    sessions.set(token, {
        serverId: req.serverId,
        playerUuid,
        playerName: playerName || 'Player',
        balances: balances || {},
        defaultCurrency: defaultCurrency || 'Aurels',
        expires: Date.now() + 3_600_000, // 1 hour hardcoded
    });

    res.json({ success: true });
});

/** POST /api/session-update — MC plugin updates a player's balance after purchase */
app.post('/api/session-update', requireApiKey, (req, res) => {
    const { playerUuid, balances } = req.body;

    // Update all sessions for this player on this server
    for (const [token, session] of sessions) {
        if (session.serverId === req.serverId && session.playerUuid === playerUuid) {
            session.balances = balances;
        }
    }

    res.json({ success: true });
});

/** POST /api/confirm-purchase — MC plugin confirms a purchase was executed */
app.post('/api/confirm-purchase', requireApiKey, (req, res) => {
    const { purchaseId, success, newBalance, spent } = req.body;

    const purchase = purchases.get(purchaseId);
    if (!purchase || purchase.serverId !== req.serverId) {
        return res.status(404).json({ error: 'Purchase not found' });
    }

    purchase.status = success ? 'completed' : 'failed';
    purchase.result = { newBalance, spent, success };

    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════
// BROWSER → RENDER  (player dashboard requests)
// ══════════════════════════════════════════════════════════════════

/** Middleware: validate session token for browser requests */
function requireSession(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const session = sessions.get(token);
    if (!session) return res.status(401).json({ error: 'Invalid or expired session. Use /web in-game.' });
    if (session.expires < Date.now()) {
        sessions.delete(token);
        return res.status(401).json({ error: 'Session expired. Use /web in-game.' });
    }

    // Rolling 1-hour timeout: reset on every activity
    session.expires = Date.now() + 3_600_000;

    req.session = session;
    req.serverId = session.serverId;
    req.server = servers.get(session.serverId);

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

/** GET /api/:serverId/auctions — Browser gets active auctions (streamed from cache) */
app.get('/api/:serverId/auctions', requireSession, (req, res) => {
    res.type('json').send(req.server.auctionsJson || '[]');
});

/** GET /api/:serverId/orders — Browser gets active buy orders (streamed from cache) */
app.get('/api/:serverId/orders', requireSession, (req, res) => {
    res.type('json').send(req.server.ordersJson || '[]');
});

/** GET /api/:serverId/stocks — Browser gets stock/price data (streamed from cache) */
app.get('/api/:serverId/stocks', requireSession, (req, res) => {
    res.type('json').send(req.server.stocksJson || '[]');
});

/** GET /api/:serverId/price-history — Browser gets price history for charts (streamed from cache) */
app.get('/api/:serverId/price-history', requireSession, (req, res) => {
    res.type('json').send(req.server.priceHistoryJson || '{}');
});

/** POST /api/:serverId/buy — Browser submits a purchase */
app.post('/api/:serverId/buy', requireSession, (req, res) => {
    const { item, amount } = req.body;

    if (!item || !amount || amount < 1 || amount > 64) {
        return res.status(400).json({ error: 'Invalid item or amount' });
    }

    // Duplicate purchase guard: 3s cooldown per player+item
    const actionKey = `buy:${req.serverId}:${item}:${req.session.playerUuid}`;
    const lastAction = recentActions.get(actionKey);
    if (lastAction && (Date.now() - lastAction) < ACTION_COOLDOWN_MS) {
        return res.status(429).json({ error: 'Too fast — please wait before buying this item again' });
    }
    recentActions.set(actionKey, Date.now());

    const purchaseId = crypto.randomUUID();

    purchases.set(purchaseId, {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: 'buy',
        item,
        amount: Math.min(64, Math.max(1, parseInt(amount))),
        status: 'pending',
        createdAt: Date.now(),
    });

    res.json({ success: true, purchaseId, message: 'Purchase queued — delivering in-game...' });
});

/** POST /api/:serverId/bid — Browser submits an auction bid or BIN purchase */
app.post('/api/:serverId/bid', requireSession, (req, res) => {
    const { auctionId, amount, quantity, type } = req.body;

    if (!auctionId || amount == null || amount <= 0) {
        return res.status(400).json({ error: 'Invalid auction or amount' });
    }

    // Validate type field
    const actionType = type === 'bin' ? 'bin' : 'bid';

    // For BIN purchases, quantity must be a positive integer
    if (actionType === 'bin' && quantity != null) {
        if (!Number.isInteger(quantity) || quantity < 1 || quantity > 64) {
            return res.status(400).json({ error: 'Invalid quantity' });
        }
    }

    // Duplicate purchase guard: 3s cooldown per player+auctionId
    const actionKey = `${req.serverId}:${auctionId}:${req.session.playerUuid}`;
    const lastAction = recentActions.get(actionKey);
    if (lastAction && (Date.now() - lastAction) < ACTION_COOLDOWN_MS) {
        return res.status(429).json({ error: 'Too fast — please wait before acting on this auction again' });
    }
    recentActions.set(actionKey, Date.now());

    // Server-side quantity validation for BIN purchases against cached auction data
    if (actionType === 'bin' && quantity != null && quantity > 1) {
        try {
            const auctions = JSON.parse(req.server.auctionsJson || '[]');
            const auction = auctions.find(a => a.id === parseInt(auctionId));
            if (auction) {
                const maxQty = auction.remaining != null ? auction.remaining : (auction.amount || 1);
                if (quantity > maxQty) {
                    return res.status(400).json({ error: `Only ${maxQty} available` });
                }
            }
        } catch (e) { /* If auction data unavailable, let plugin validate */ }
    }

    const purchaseId = crypto.randomUUID();

    purchases.set(purchaseId, {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: actionType,
        auctionId: parseInt(auctionId),
        amount: isNaN(parseFloat(amount)) ? 0 : parseFloat(amount),
        quantity: actionType === 'bin' ? (parseInt(quantity) || 1) : undefined,
        status: 'pending',
        createdAt: Date.now(),
    });

    res.json({ success: true, purchaseId, message: actionType === 'bin' ? 'Purchase queued — confirming in-game...' : 'Bid queued — confirming in-game...' });
});

/** POST /api/:serverId/fill-order — Browser submits items to fulfill a buy order */
app.post('/api/:serverId/fill-order', requireSession, (req, res) => {
    const { orderId, amount } = req.body;

    if (!orderId || amount == null || isNaN(Number(amount)) || amount <= 0) {
        return res.status(400).json({ error: 'Invalid order or amount' });
    }

    // Duplicate fill guard: 3s cooldown per player+orderId
    const actionKey = `fill:${req.serverId}:${orderId}:${req.session.playerUuid}`;
    const lastAction = recentActions.get(actionKey);
    if (lastAction && (Date.now() - lastAction) < ACTION_COOLDOWN_MS) {
        return res.status(429).json({ error: 'Too fast — please wait before filling this order again' });
    }
    recentActions.set(actionKey, Date.now());

    const purchaseId = crypto.randomUUID();

    purchases.set(purchaseId, {
        serverId: req.serverId,
        playerUuid: req.session.playerUuid,
        type: 'fill_order',
        orderId: parseInt(orderId),
        amount: parseInt(amount),
        status: 'pending',
        createdAt: Date.now(),
    });

    res.json({ success: true, purchaseId, message: 'Fulfillment queued — verifying in-game inventory...' });
});

/** GET /api/:serverId/purchase-status?id=X — Browser polls purchase result */
app.get('/api/:serverId/purchase-status', requireSession, (req, res) => {
    const id = req.query.id;
    const purchase = purchases.get(id);

    if (!purchase) return res.status(404).json({ error: 'Purchase not found' });

    // IDOR protection: only the purchase owner can check status
    if (purchase.playerUuid !== req.session.playerUuid) {
        return res.status(403).json({ error: 'Not your purchase' });
    }

    res.json({
        status: purchase.status,
        result: purchase.result || null,
    });
});

// Clean up stale recentActions entries every 60s
setInterval(() => {
    const cutoff = Date.now() - 60_000;
    for (const [key, ts] of recentActions) {
        if (ts < cutoff) recentActions.delete(key);
    }
}, 60_000);

// ══════════════════════════════════════════════════════════════════
// STATIC FILES + DASHBOARD PAGE
// ══════════════════════════════════════════════════════════════════

// Serve static frontend files
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
</style></head>
<body>
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

// Dashboard entry point — serves index.html with GA4 injection
let indexHtmlCache = null;
// Invalidate cache hourly so redeploys take effect without restart
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

// ══════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════

function getPendingPurchases(serverId, playerUuid) {
    const pending = [];
    for (const [id, p] of purchases) {
        if (p.serverId === serverId && p.status === 'pending' && (!playerUuid || p.playerUuid === playerUuid)) {
            pending.push({ id, ...p });
        }
    }
    return pending;
}

// Cleanup expired sessions and old purchases every 60 seconds
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (session.expires < now) sessions.delete(token);
    }
    // Remove completed/failed purchases older than 5 minutes
    // Remove pending purchases older than 10 minutes (server went offline)
    for (const [id, p] of purchases) {
        if (p.status !== 'pending' && now - p.createdAt > 300_000) purchases.delete(id);
        else if (p.status === 'pending' && now - p.createdAt > 600_000) purchases.delete(id);
    }
    // Remove stale servers (no sync in 5 minutes, no active sessions)
    for (const [id, server] of servers) {
        if (now - server.lastSync > 300_000) {
            const hasActive = [...sessions.values()].some(s => s.serverId === id);
            if (!hasActive) {
                console.log(`[Cleanup] Removing stale server "${server.serverName}" (${id})`);
                servers.delete(id);
            }
        }
    }
}, 60_000);

// ══════════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Aurelium Web Dashboard running on port ${PORT}`);
});
