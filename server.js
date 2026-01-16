/**
 * HalfCourse Vendor API v2 - OAuth (Fixed)
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
const SHOPIFY_STORE = process.env.SHOPIFY_STORE; // FULL DOMAIN: half-course.myshopify.com
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL = process.env.APP_URL;
const API_VERSION = '2024-01';

// In-memory token store (replace with DB later)
const accessTokens = {};

// ================= MIDDLEWARE =================

app.use(cors({
  origin: [
    'https://halfcourse.com',
    'https://www.halfcourse.com',
    /\.myshopify\.com$/
  ],
  credentials: true
}));

app.use(express.json());

// ================= VENDOR MAP =================

const VENDOR_MAP = {
  liandros: "Liandro's",
};

function getVendorName(handle) {
  return VENDOR_MAP[handle] || handle;
}

// ================= OAUTH =================

// Start OAuth
app.get('/auth', (req, res) => {
  const shop = SHOPIFY_STORE;
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/auth/callback`;

  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
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

  try {
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code
      })
    });

    const data = await response.json();

    if (!data.access_token) {
      throw new Error(data.error || 'No access token returned');
    }

    // ✅ Store token under FULL shop domain
    accessTokens[shop] = data.access_token;

    console.log(`✅ Shopify connected: ${shop}`);

    res.send(`
      <html>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
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

// ================= HELPERS =================

function getAccessToken(shop = SHOPIFY_STORE) {
  return accessTokens[shop] || null;
}

function getShopifyHeaders(shop) {
  const token = getAccessToken(shop);
  if (!token) {
    throw new Error('No access token');
  }
  return {
    'Content-Type': 'application/json',
    'X-Shopify-Access-Token': token
  };
}

function getBaseUrl(shop = SHOPIFY_STORE) {
  return `https://${shop}/admin/api/${API_VERSION}`;
}

// ================= AUTH MIDDLEWARE =================

function requireAuth(req, res, next) {
  const shop = SHOPIFY_STORE;
  const token = getAccessToken(shop);

  if (!token) {
    return res.status(401).json({
      error: 'Not authenticated',
      authUrl: `${APP_URL}/auth`
    });
  }

  req.shop = shop;
  req.accessToken = token;
  next();
}

// ================= API =================

// Status check
app.get('/api/status', (req, res) => {
  res.json({
    authenticated: !!getAccessToken()
  });
});

// Vendor products
app.get('/api/vendors/:handle/products', requireAuth, async (req, res) => {
  const vendorName = getVendorName(req.params.handle);

  try {
    const response = await fetch(
      `${getBaseUrl(req.shop)}/products.json?vendor=${encodeURIComponent(vendorName)}&limit=250`,
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
      <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>HalfCourse Vendor API</h1>
        ${
          connected
            ? '<p style="color: green;">✅ Connected to Shopify</p>'
            : `<p style="color: orange;">⚠️ Not connected</p>
               <a href="/auth"
                  style="padding:12px 24px;background:#ac380b;color:#fff;
                  text-decoration:none;border-radius:8px;">
                  Connect to Shopify
               </a>`
        }
      </body>
    </html>
  `);
});

// ================= HEALTH =================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    authenticated: !!getAccessToken(),
    timestamp: new Date().toISOString()
  });
});

// ================= START =================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 HalfCourse Vendor API running on port ${PORT}`);
});

module.exports = app;
