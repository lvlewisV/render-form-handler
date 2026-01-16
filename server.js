/**
 * HalfCourse Vendor API v2 – OAuth (Stabilized)
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// ================= CONFIG =================

const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_SCOPES =
  process.env.SHOPIFY_SCOPES ||
  'read_products,write_products,read_metafields,write_metafields,read_collections';
const APP_URL = process.env.APP_URL;
const API_VERSION = '2024-01';

// ⚠️ In-memory token store (replace with DB / Redis later)
const accessTokens = {};

// ================= MIDDLEWARE =================

app.use(
  cors({
    origin: [
      'https://halfcourse.com',
      'https://www.halfcourse.com',
      /\.myshopify\.com$/,
    ],
    credentials: true,
  })
);

app.use(express.json());

// ================= VENDOR MAP =================

const VENDOR_MAP = {
  liandros: "Liandro's",
};

function getVendorName(handle) {
  return VENDOR_MAP[handle] || handle;
}

// ================= HELPERS =================

function normalizeShop(shop) {
  return shop?.trim().toLowerCase();
}

/**
 * Returns the currently connected shop.
 * (Single-store app assumption — fine for HalfCourse)
 */
function getActiveShop() {
  return Object.keys(accessTokens)[0] || null;
}

function getAccessToken() {
  const shop = getActiveShop();
  return shop ? accessTokens[shop] : null;
}

function getShopifyHeaders(shop) {
  const token = accessTokens[shop];
  if (!token) throw new Error('No access token');
  return {
    'Content-Type': 'application/json',
    'X-Shopify-Access-Token': token,
  };
}

function getBaseUrl(shop) {
  return `https://${shop}/admin/api/${API_VERSION}`;
}

// ================= OAUTH =================

// Start OAuth
app.get('/auth', (req, res) => {
  // ⚠️ OAuth must target the shop being installed
  const shop = req.query.shop;

  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  const normalizedShop = normalizeShop(shop);
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/auth/callback`;

  const authUrl =
    `https://${normalizedShop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  res.redirect(authUrl);
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, shop } = req.query;

  if (!code || !shop) {
    return res.status(400).send('Missing OAuth parameters');
  }

  const normalizedShop = normalizeShop(shop);

  try {
    const response = await fetch(
      `https://${normalizedShop}/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: SHOPIFY_CLIENT_ID,
          client_secret: SHOPIFY_CLIENT_SECRET,
          code,
        }),
      }
    );

    const data = await response.json();

    if (!data.access_token) {
      console.error('OAuth token error:', data);
      throw new Error(data.error || 'No access token returned');
    }

    // ✅ Store token under normalized shop domain
    accessTokens[normalizedShop] = data.access_token;

    console.log('✅ Shopify connected:', normalizedShop);
    console.log('🔐 Connected shops:', Object.keys(accessTokens));

    res.send(`
      <html>
        <body style="font-family:sans-serif;text-align:center;padding:50px;">
          <h1>✅ Connected!</h1>
          <p>Your store is now connected.</p>
          <p>You can close this window.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send('OAuth failed');
  }
});

// ================= AUTH MIDDLEWARE =================

function requireAuth(req, res, next) {
  const shop = getActiveShop();
  const token = getAccessToken();

  if (!shop || !token) {
    return res.status(401).json({
      error: 'Not authenticated',
      authUrl: `${APP_URL}/auth`,
    });
  }

  req.shop = shop;
  req.accessToken = token;
  next();
}

// ================= API =================

// Health / debug
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    authenticated: !!getAccessToken(),
    connectedShops: Object.keys(accessTokens),
    timestamp: new Date().toISOString(),
  });
});

// Vendor products
app.get('/api/vendors/:handle/products', requireAuth, async (req, res) => {
  const vendorName = getVendorName(req.params.handle);

  try {
    const response = await fetch(
      `${getBaseUrl(req.shop)}/products.json?vendor=${encodeURIComponent(
        vendorName
      )}&limit=250`,
      { headers: getShopifyHeaders(req.shop) }
    );

    const data = await response.json();
    res.json(data.products || []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// ================= UI =================

app.get('/', (req, res) => {
  const connected = !!getAccessToken();

  res.send(`
    <html>
      <head><title>HalfCourse Vendor API</title></head>
      <body style="font-family:sans-serif;text-align:center;padding:50px;">
        <h1>HalfCourse Vendor API</h1>
        ${
          connected
            ? '<p style="color:green;">✅ Connected to Shopify</p>'
            : `<p style="color:orange;">⚠️ Not connected</p>
               <p>Install the app via the Shopify Partner Dashboard</p>`
        }
      </body>
    </html>
  `);
});

// ================= START =================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 HalfCourse Vendor API running on port ${PORT}`);
});

module.exports = app;
