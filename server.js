/**
 * HalfCourse Vendor Product Editor API
 *
 * A Node.js/Express backend that allows vendors to manage their products
 * and store settings without needing Shopify admin access.
 *
 * Features:
 * - Shopify OAuth authentication
 * - Token persistence (survives server restarts)
 * - Vendor login with password protection
 * - Product CRUD operations (filtered by vendor)
 * - Image upload/delete
 * - Metafields support
 * - Collection/Store settings management
 * - Email campaign sending via Amazon SES (per-recipient, with unsubscribe)
 * - Bounce/complaint webhook handler (SNS → suppressions table)
 * - Audience segmentation via Azure SQL
 * - Campaign logging to email_send_log
 * - Test email send via Amazon SES
 * - Contact upsert endpoint (called by Azure Function on form submit)
 *
 * Deploy to: Render.com
 * Repository: github.com/lvlewisV/hc-vendor-api-oauth.js
 *
 * Required env vars (add in Render dashboard):
 *   SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, SHOPIFY_STORE, SHOPIFY_SCOPES
 *   APP_URL
 *   AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
 *   SES_FROM_EMAIL, SES_CONFIG_SET
 *   SES_UNSUBSCRIBE_SECRET   ← new: random string used for HMAC token generation
 *   SQL_SERVER, SQL_DATABASE, SQL_USERNAME, SQL_PASSWORD
 *   VENDOR_LIANDROS_PASSWORD, DEFAULT_VENDOR_PASSWORD
 */

const crypto  = require('crypto');
const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');
const sql     = require('mssql');

const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');

const ses = new SESClient({ region: process.env.AWS_REGION });
const app = express();

// =============================================================================
// SQL CONNECTION POOL
// =============================================================================

const sqlConfig = {
  user:     process.env.SQL_USERNAME,
  password: process.env.SQL_PASSWORD,
  server:   process.env.SQL_SERVER,
  database: process.env.SQL_DATABASE,
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  options:  { encrypt: true, trustServerCertificate: false }
};

let pool;

async function getSqlPool() {
  if (!pool) {
    pool = await sql.connect(sqlConfig);
    console.log('✅ Connected to Azure SQL');
  }
  return pool;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const PORT               = process.env.PORT || 3000;
const SHOPIFY_CLIENT_ID  = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE      = process.env.SHOPIFY_STORE || 'half-course';
const SHOPIFY_SCOPES     = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL            = process.env.APP_URL || `http://localhost:${PORT}`;

// Vendor handle → exact Shopify vendor name
const VENDOR_MAP = {
  'liandros': "Liandro's",
  // 'marias-kitchen': "Maria's Kitchen",
};

const TOKEN_FILE = process.env.TOKEN_FILE || '/tmp/shopify_tokens.json';

// =============================================================================
// TOKEN PERSISTENCE
// =============================================================================

let shopifyAccessTokens = {};

function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      shopifyAccessTokens = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
      console.log('✅ Loaded tokens from file');
    }
  } catch (err) {
    console.log('⚠️ Could not load tokens:', err.message);
    shopifyAccessTokens = {};
  }
}

function saveTokens() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(shopifyAccessTokens, null, 2));
    console.log('✅ Saved tokens to file');
  } catch (err) {
    console.log('⚠️ Could not save tokens:', err.message);
  }
}

loadTokens();

const vendorSessions = {};

// =============================================================================
// MIDDLEWARE
// =============================================================================

const corsOptions = {
  origin: [
    'https://halfcourse.com',
    'https://www.halfcourse.com',
    'https://half-course.myshopify.com',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

function requireShopifyAuth(req, res, next) {
  const token = shopifyAccessTokens[SHOPIFY_STORE];
  if (!token) {
    return res.status(401).json({
      error: 'Shopify not connected',
      message: 'Visit /auth to reconnect.'
    });
  }
  req.shopifyToken = token;
  req.shop = SHOPIFY_STORE;
  next();
}

function requireVendorAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No authorization token provided' });
  }
  const token = authHeader.split(' ')[1];
  const session = vendorSessions[token];
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  if (Date.now() - session.created > 24 * 60 * 60 * 1000) {
    delete vendorSessions[token];
    return res.status(401).json({ error: 'Session expired' });
  }
  if (req.params.handle && session.handle !== req.params.handle) {
    return res.status(403).json({ error: 'Access denied to this vendor' });
  }
  req.vendorSession = session;
  next();
}

async function validateProductOwnership(req, res, next) {
  const productId = req.params.productId;
  if (!productId) return next();
  const vendorName = VENDOR_MAP[req.vendorSession.handle];
  if (!vendorName) return res.status(400).json({ error: 'Invalid vendor' });
  try {
    const response = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/products/${productId}.json`,
      { headers: { 'X-Shopify-Access-Token': req.shopifyToken, 'Content-Type': 'application/json' } }
    );
    if (!response.ok) return res.status(404).json({ error: 'Product not found' });
    const data = await response.json();
    if (data.product.vendor !== vendorName) {
      return res.status(403).json({ error: 'You do not have permission to modify this product' });
    }
    req.product = data.product;
    next();
  } catch (err) {
    console.error('Error validating product ownership:', err);
    res.status(500).json({ error: 'Failed to validate product ownership' });
  }
}

async function validateCollectionOwnership(req, res, next) {
  const collectionHandle = req.params.handle;
  if (!collectionHandle) return next();
  if (req.vendorSession.handle !== collectionHandle) {
    return res.status(403).json({ error: 'Access denied to this collection' });
  }
  try {
    const response = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/custom_collections.json?handle=${collectionHandle}`,
      { headers: { 'X-Shopify-Access-Token': req.shopifyToken, 'Content-Type': 'application/json' } }
    );

    if (!response.ok) {
      const smartResponse = await fetch(
        `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/smart_collections.json?handle=${collectionHandle}`,
        { headers: { 'X-Shopify-Access-Token': req.shopifyToken, 'Content-Type': 'application/json' } }
      );
      if (!smartResponse.ok) return res.status(404).json({ error: 'Collection not found' });
      const smartData = await smartResponse.json();
      if (!smartData.smart_collections?.length) return res.status(404).json({ error: 'Collection not found' });
      req.collection = smartData.smart_collections[0];
      req.collectionType = 'smart';
      return next();
    }

    const data = await response.json();
    if (!data.custom_collections?.length) {
      const smartResponse = await fetch(
        `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/smart_collections.json?handle=${collectionHandle}`,
        { headers: { 'X-Shopify-Access-Token': req.shopifyToken, 'Content-Type': 'application/json' } }
      );
      if (smartResponse.ok) {
        const smartData = await smartResponse.json();
        if (smartData.smart_collections?.length) {
          req.collection = smartData.smart_collections[0];
          req.collectionType = 'smart';
          return next();
        }
      }
      return res.status(404).json({ error: 'Collection not found' });
    }

    req.collection = data.custom_collections[0];
    req.collectionType = 'custom';
    next();
  } catch (err) {
    console.error('Error validating collection ownership:', err);
    res.status(500).json({ error: 'Failed to validate collection ownership' });
  }
}

// =============================================================================
// SHOPIFY API HELPER
// =============================================================================

async function shopifyFetch(endpoint, options = {}) {
  const token = shopifyAccessTokens[SHOPIFY_STORE];
  if (!token) throw new Error('Shopify not connected');
  const url = `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'X-Shopify-Access-Token': token,
      'Content-Type': 'application/json',
      ...options.headers
    }
  });
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`Shopify API error: ${response.status} ${errorText}`);
    throw new Error(`Shopify API error: ${response.status}`);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

// =============================================================================
// EMAIL HELPERS
// =============================================================================

/**
 * Generates a signed unsubscribe URL for a specific email + vendor.
 * Uses HMAC-SHA256 so the token cannot be forged.
 */
function buildUnsubscribeUrl(email, vendorTag) {
  const token = crypto
    .createHmac('sha256', process.env.SES_UNSUBSCRIBE_SECRET || 'changeme')
    .update(`${email}:${vendorTag}`)
    .digest('hex');
  return `${APP_URL}/unsubscribe?email=${encodeURIComponent(email)}&vendor=${encodeURIComponent(vendorTag)}&token=${token}`;
}

/**
 * Validates an unsubscribe token.
 */
function validateUnsubscribeToken(email, vendorTag, token) {
  try {
    const expected = crypto
      .createHmac('sha256', process.env.SES_UNSUBSCRIBE_SECRET || 'changeme')
      .update(`${email}:${vendorTag}`)
      .digest('hex');

    const a = Buffer.from(token, 'hex');
    const b = Buffer.from(expected, 'hex');

    if (a.length !== b.length) return false;

    return crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

/**
 * Injects a real per-recipient unsubscribe URL into the email HTML,
 * replacing the {{unsubscribe_url}} placeholder from the email builder.
 */
function personalizeHtml(htmlContent, email, vendorTag) {
  return htmlContent.replace(/\{\{unsubscribe_url\}\}/g, buildUnsubscribeUrl(email, vendorTag));
}

/**
 * Sends a single SES email to one recipient.
 * Called in a loop — never sends to multiple recipients at once.
 */
async function sendSingleEmail({ toEmail, subject, htmlContent, vendorTag }) {
  const personalizedHtml = personalizeHtml(htmlContent, toEmail, vendorTag);

  const params = {
    Source: process.env.SES_FROM_EMAIL,
    Destination: {
      ToAddresses: [toEmail]
    },
    Message: {
      Subject: { Data: subject, Charset: "UTF-8" },
      Body: {
        Html: { Data: personalizedHtml, Charset: "UTF-8" },
        Text: { Data: 'View this email in an HTML-compatible email client.', Charset: "UTF-8" }
      }
    },
    ConfigurationSetName: process.env.SES_CONFIG_SET
  };

  return ses.send(new SendEmailCommand(params));
}

// =============================================================================
// ROUTES: HOME & HEALTH
// =============================================================================

app.get('/', (req, res) => {
  const isConnected = !!shopifyAccessTokens[SHOPIFY_STORE];
  res.send(`
    <!DOCTYPE html><html><head><title>HalfCourse Vendor API</title>
    <style>
      body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:50px auto;padding:20px;background:#f5f5f5;}
      .card{background:white;border-radius:12px;padding:30px;box-shadow:0 2px 10px rgba(0,0,0,.1);}
      h1{color:#333;margin-top:0;}
      .status{padding:15px;border-radius:8px;margin:20px 0;}
      .connected{background:#d4edda;color:#155724;}
      .disconnected{background:#f8d7da;color:#721c24;}
      .btn{display:inline-block;padding:12px 24px;background:#ac380b;color:white;text-decoration:none;border-radius:8px;font-weight:600;}
      code{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:14px;}
      ul{line-height:1.8;}
    </style></head><body><div class="card">
      <h1>🍽️ HalfCourse Vendor API</h1>
      <div class="status ${isConnected ? 'connected' : 'disconnected'}">
        ${isConnected ? '✅ Connected to Shopify!' : '❌ Not connected to Shopify'}
      </div>
      ${!isConnected
        ? `<p>Click below to connect:</p><a href="/auth" class="btn">Connect to Shopify</a>`
        : `<p>API is ready. Vendors can log in to their product editors.</p>
           <h3>Endpoints:</h3><ul>
             <li><code>GET  /health</code> – Health check</li>
             <li><code>POST /api/vendor/login</code> – Vendor login</li>
             <li><code>GET  /api/vendors/:handle/products</code></li>
             <li><code>POST /api/vendors/:handle/products</code></li>
             <li><code>PUT  /api/vendors/:handle/products/:id</code></li>
             <li><code>DELETE /api/vendors/:handle/products/:id</code></li>
             <li><code>GET  /api/vendors/:handle/settings</code></li>
             <li><code>PUT  /api/vendors/:handle/settings</code></li>
             <li><code>POST /api/vendors/:handle/settings/images</code></li>
             <li><code>GET  /api/vendors/:handle/subscribers/count</code></li>
             <li><code>GET  /api/vendors/:handle/segments</code></li>
             <li><code>POST /api/vendors/:handle/email/send</code></li>
             <li><code>POST /api/vendors/:handle/email/test</code></li>
             <li><code>POST /api/contacts/upsert</code></li>
             <li><code>POST /webhooks/ses-notifications</code></li>
             <li><code>GET  /unsubscribe</code></li>
           </ul>
           <a href="/auth" class="btn">Re-authenticate</a>`
      }
    </div></body></html>
  `);
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    shopifyConnected: !!shopifyAccessTokens[SHOPIFY_STORE],
    sesConfigured:    !!process.env.AWS_REGION && !!process.env.SES_FROM_EMAIL,
    sqlConfigured:    !!process.env.SQL_SERVER,
    store:            SHOPIFY_STORE,
    configuredVendors: Object.keys(VENDOR_MAP)
  });
});

// =============================================================================
// ROUTES: SHOPIFY OAUTH
// =============================================================================

app.get('/auth', (req, res) => {
  if (!SHOPIFY_CLIENT_ID) return res.status(500).send('SHOPIFY_CLIENT_ID not configured');
  const redirectUri = `${APP_URL}/auth/callback`;
  const state = Math.random().toString(36).substring(7);
  app.locals.oauthState = state;
  const authUrl =
    `https://${SHOPIFY_STORE}.myshopify.com/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_CLIENT_ID}&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  if (state !== app.locals.oauthState) return res.status(400).send('Invalid state parameter');
  if (!code) return res.status(400).send('No authorization code received');
  try {
    const tokenResponse = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: SHOPIFY_CLIENT_ID, client_secret: SHOPIFY_CLIENT_SECRET, code })
      }
    );
    if (!tokenResponse.ok) return res.status(400).send('Token exchange failed');
    const tokenData = await tokenResponse.json();
    shopifyAccessTokens[SHOPIFY_STORE] = tokenData.access_token;
    saveTokens();
    console.log('✅ Shopify OAuth successful');
    res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:100px;">
      <h1>✅ Connected!</h1><p>API is now connected to Shopify.</p>
      <a href="/" style="color:#ac380b;">← Back to Home</a>
    </body></html>`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send('OAuth error: ' + err.message);
  }
});

// =============================================================================
// ROUTES: VENDOR AUTHENTICATION
// =============================================================================

app.post('/api/vendor/login', (req, res) => {
  const { handle, password } = req.body;
  if (!handle || !password) return res.status(400).json({ error: 'Handle and password are required' });
  if (!VENDOR_MAP[handle]) return res.status(404).json({ error: 'Vendor not found' });

  const envKey = `VENDOR_${handle.toUpperCase().replace(/-/g, '_')}_PASSWORD`;
  const expectedPassword = process.env[envKey] || process.env.DEFAULT_VENDOR_PASSWORD;

  if (!expectedPassword) {
    console.error(`No password configured for vendor: ${handle} (looked for ${envKey})`);
    return res.status(500).json({ error: 'Vendor not properly configured' });
  }
  if (password !== expectedPassword) return res.status(401).json({ error: 'Invalid password' });

  const sessionToken =
    Math.random().toString(36).substring(2) +
    Math.random().toString(36).substring(2) +
    Date.now().toString(36);

  vendorSessions[sessionToken] = { handle, vendorName: VENDOR_MAP[handle], created: Date.now() };
  console.log(`✅ Vendor logged in: ${handle}`);
  res.json({ success: true, token: sessionToken, vendor: { handle, name: VENDOR_MAP[handle] } });
});

app.post('/api/vendor/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    delete vendorSessions[authHeader.split(' ')[1]];
  }
  res.json({ success: true });
});

// =============================================================================
// ROUTES: PRODUCTS
// =============================================================================

app.get('/api/vendors/:handle/products',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const vendorName = VENDOR_MAP[req.params.handle];
    if (!vendorName) return res.status(404).json({ error: 'Vendor not found' });
    try {
      let allProducts = [];
      let pageInfo = null;
      let hasNextPage = true;
      while (hasNextPage) {
        let url = '/products.json?limit=250';
        if (pageInfo) url += `&page_info=${pageInfo}`;
        const response = await fetch(
          `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01${url}`,
          { headers: { 'X-Shopify-Access-Token': req.shopifyToken, 'Content-Type': 'application/json' } }
        );
        if (!response.ok) throw new Error(`Shopify API error: ${response.status}`);
        const data = await response.json();
        allProducts = allProducts.concat(data.products);
        const linkHeader = response.headers.get('link');
        if (linkHeader?.includes('rel="next"')) {
          const match = linkHeader.match(/page_info=([^>&]*)/);
          pageInfo = match ? match[1] : null;
          hasNextPage = !!pageInfo;
        } else {
          hasNextPage = false;
        }
        if (allProducts.length > 1000) break;
      }
      const vendorProducts = allProducts.filter(p => p.vendor === vendorName);
      res.json({ products: vendorProducts });
    } catch (err) {
      console.error('Error fetching products:', err);
      res.status(500).json({ error: 'Failed to fetch products' });
    }
  }
);

app.post('/api/vendors/:handle/products',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const vendorName = VENDOR_MAP[req.params.handle];
    if (!vendorName) return res.status(404).json({ error: 'Vendor not found' });
    try {
      const { title, body_html, price, compare_at_price, images, metafields } = req.body;
      const productData = {
        product: {
          title,
          body_html: body_html || '',
          vendor: vendorName,
          status: 'draft',
          variants: [{
            price: price || '0.00',
            compare_at_price: compare_at_price || null,
            inventory_management: null,
            requires_shipping: false
          }]
        }
      };
      if (images?.length) {
        productData.product.images = images.map(img => ({ attachment: img.attachment, alt: img.alt || title }));
      }
      const data = await shopifyFetch('/products.json', { method: 'POST', body: JSON.stringify(productData) });
      if (metafields && data.product) {
        for (const mf of metafields) {
          try {
            await shopifyFetch(`/products/${data.product.id}/metafields.json`, {
              method: 'POST',
              body: JSON.stringify({ metafield: { namespace: mf.namespace || 'custom', key: mf.key, value: mf.value, type: mf.type || 'single_line_text_field' } })
            });
          } catch (mfErr) { console.error('Error adding metafield:', mfErr); }
        }
      }
      console.log(`✅ Created product: ${data.product.title}`);
      res.json(data);
    } catch (err) {
      console.error('Error creating product:', err);
      res.status(500).json({ error: 'Failed to create product' });
    }
  }
);

app.put('/api/vendors/:handle/products/:productId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId } = req.params;
    try {
      const { title, body_html, price, compare_at_price, status, metafields, images_to_delete } = req.body;
      const updateData = { product: { id: productId } };
      if (title !== undefined) updateData.product.title = title;
      if (body_html !== undefined) updateData.product.body_html = body_html;
      if (status !== undefined) updateData.product.status = status;
      if (price !== undefined || compare_at_price !== undefined) {
        const variant = req.product.variants[0];
        updateData.product.variants = [{
          id: variant.id,
          price: price !== undefined ? price : variant.price,
          compare_at_price: compare_at_price !== undefined ? compare_at_price : variant.compare_at_price
        }];
      }
      const data = await shopifyFetch(`/products/${productId}.json`, { method: 'PUT', body: JSON.stringify(updateData) });
      if (images_to_delete?.length) {
        for (const imageId of images_to_delete) {
          try { await shopifyFetch(`/products/${productId}/images/${imageId}.json`, { method: 'DELETE' }); }
          catch (imgErr) { console.error('Error deleting image:', imgErr); }
        }
      }
      if (metafields) {
        for (const mf of metafields) {
          try {
            if (mf.id) {
              await shopifyFetch(`/metafields/${mf.id}.json`, { method: 'PUT', body: JSON.stringify({ metafield: { id: mf.id, value: mf.value } }) });
            } else {
              await shopifyFetch(`/products/${productId}/metafields.json`, { method: 'POST', body: JSON.stringify({ metafield: { namespace: mf.namespace || 'custom', key: mf.key, value: mf.value, type: mf.type || 'single_line_text_field' } }) });
            }
          } catch (mfErr) { console.error('Error updating metafield:', mfErr); }
        }
      }
      console.log(`✅ Updated product: ${productId}`);
      res.json(data);
    } catch (err) {
      console.error('Error updating product:', err);
      res.status(500).json({ error: 'Failed to update product' });
    }
  }
);

app.delete('/api/vendors/:handle/products/:productId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      await shopifyFetch(`/products/${req.params.productId}.json`, { method: 'DELETE' });
      console.log(`✅ Deleted product: ${req.params.productId}`);
      res.json({ success: true, deleted: req.params.productId });
    } catch (err) {
      console.error('Error deleting product:', err);
      res.status(500).json({ error: 'Failed to delete product' });
    }
  }
);

app.post('/api/vendors/:handle/products/:productId/images',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  upload.single('image'),
  async (req, res) => {
    const { productId } = req.params;
    try {
      let imageData;
      if (req.file) {
        imageData = { image: { attachment: req.file.buffer.toString('base64'), alt: req.body.alt || '' } };
      } else if (req.body.attachment) {
        imageData = { image: { attachment: req.body.attachment, alt: req.body.alt || '' } };
      } else if (req.body.src) {
        imageData = { image: { src: req.body.src, alt: req.body.alt || '' } };
      } else {
        return res.status(400).json({ error: 'No image provided' });
      }
      const data = await shopifyFetch(`/products/${productId}/images.json`, { method: 'POST', body: JSON.stringify(imageData) });
      res.json(data);
    } catch (err) {
      console.error('Error uploading image:', err);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  }
);

app.delete('/api/vendors/:handle/products/:productId/images/:imageId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId, imageId } = req.params;
    try {
      await shopifyFetch(`/products/${productId}/images/${imageId}.json`, { method: 'DELETE' });
      res.json({ success: true, deleted: imageId });
    } catch (err) {
      console.error('Error deleting image:', err);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

app.get('/api/vendors/:handle/products/:productId/metafields',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const data = await shopifyFetch(`/products/${req.params.productId}/metafields.json`);
      res.json(data);
    } catch (err) {
      console.error('Error fetching metafields:', err);
      res.status(500).json({ error: 'Failed to fetch metafields' });
    }
  }
);

// =============================================================================
// ROUTES: STORE SETTINGS
// =============================================================================

app.get('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      const collectionId = req.collection.id;
      const metafieldsData = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      const metafields = {};
      for (const mf of (metafieldsData.metafields || [])) {
        metafields[mf.key] = { id: mf.id, namespace: mf.namespace, key: mf.key, value: mf.value, type: mf.type };
      }
      res.json({
        collection: { id: req.collection.id, handle: req.collection.handle, title: req.collection.title, body_html: req.collection.body_html, image: req.collection.image },
        metafields,
        collectionType: req.collectionType
      });
    } catch (err) {
      console.error('Error fetching store settings:', err);
      res.status(500).json({ error: 'Failed to fetch store settings' });
    }
  }
);

app.put('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      const collectionId = req.collection.id;
      const { metafields, collection: collectionUpdates } = req.body;
      const results = { collection: null, metafields: [] };

      if (collectionUpdates) {
        const endpoint = req.collectionType === 'smart'
          ? `/smart_collections/${collectionId}.json`
          : `/custom_collections/${collectionId}.json`;
        const payload = req.collectionType === 'smart'
          ? { smart_collection: { id: collectionId, ...collectionUpdates } }
          : { custom_collection: { id: collectionId, ...collectionUpdates } };
        results.collection = await shopifyFetch(endpoint, { method: 'PUT', body: JSON.stringify(payload) });
      }

      if (Array.isArray(metafields)) {
        for (const mf of metafields) {
          try {
            if (mf.id) {
              const r = await shopifyFetch(`/metafields/${mf.id}.json`, { method: 'PUT', body: JSON.stringify({ metafield: { id: mf.id, value: mf.value } }) });
              results.metafields.push({ success: true, key: mf.key, result: r });
            } else if (mf.value !== undefined && mf.value !== null && mf.value !== '') {
              const r = await shopifyFetch(`/collections/${collectionId}/metafields.json`, { method: 'POST', body: JSON.stringify({ metafield: { namespace: mf.namespace || 'custom', key: mf.key, value: mf.value, type: mf.type || 'single_line_text_field' } }) });
              results.metafields.push({ success: true, key: mf.key, result: r });
            }
          } catch (mfErr) {
            console.error(`Error updating metafield ${mf.key}:`, mfErr);
            results.metafields.push({ success: false, key: mf.key, error: mfErr.message });
          }
        }
      }
      console.log(`✅ Updated settings for vendor: ${req.params.handle}`);
      res.json({ success: true, results });
    } catch (err) {
      console.error('Error updating store settings:', err);
      res.status(500).json({ error: 'Failed to update store settings' });
    }
  }
);

app.delete('/api/vendors/:handle/settings/metafields/:metafieldId',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      await shopifyFetch(`/metafields/${req.params.metafieldId}.json`, { method: 'DELETE' });
      res.json({ success: true, deleted: req.params.metafieldId });
    } catch (err) {
      console.error('Error deleting metafield:', err);
      res.status(500).json({ error: 'Failed to delete metafield' });
    }
  }
);

app.post('/api/vendors/:handle/settings/images',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  upload.single('image'),
  async (req, res) => {
    try {
      const { imageType, alt } = req.body;
      if (!imageType) return res.status(400).json({ error: 'imageType is required' });

      let imageData;
      if (req.file) {
        imageData = req.file.buffer.toString('base64');
      } else if (req.body.attachment) {
        imageData = req.body.attachment;
      } else {
        return res.status(400).json({ error: 'No image provided' });
      }

      const collectionId = req.collection.id;

      if (imageType === 'collection_image') {
        const endpoint = req.collectionType === 'smart'
          ? `/smart_collections/${collectionId}.json`
          : `/custom_collections/${collectionId}.json`;
        const payload = req.collectionType === 'smart'
          ? { smart_collection: { id: collectionId, image: { attachment: imageData, alt: alt || '' } } }
          : { custom_collection: { id: collectionId, image: { attachment: imageData, alt: alt || '' } } };
        const result = await shopifyFetch(endpoint, { method: 'PUT', body: JSON.stringify(payload) });
        return res.json({ success: true, imageType, image: result.smart_collection?.image || result.custom_collection?.image });
      }

      // Upload via temp product to get CDN URL
      const tempProduct = await shopifyFetch('/products.json', {
        method: 'POST',
        body: JSON.stringify({ product: { title: `_temp_upload_${Date.now()}`, status: 'draft', images: [{ attachment: imageData, alt: alt || imageType }] } })
      });
      if (!tempProduct.product?.images?.length) throw new Error('Failed to upload image');
      const uploadedImageUrl = tempProduct.product.images[0].src;
      await shopifyFetch(`/products/${tempProduct.product.id}.json`, { method: 'DELETE' });

      const existingMetafields = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      const existingMf = existingMetafields.metafields?.find(mf => mf.key === imageType && mf.namespace === 'custom');

      let metafieldResult;
      if (existingMf) {
        metafieldResult = await shopifyFetch(`/metafields/${existingMf.id}.json`, { method: 'PUT', body: JSON.stringify({ metafield: { id: existingMf.id, value: uploadedImageUrl } }) });
      } else {
        metafieldResult = await shopifyFetch(`/collections/${collectionId}/metafields.json`, { method: 'POST', body: JSON.stringify({ metafield: { namespace: 'custom', key: imageType, value: uploadedImageUrl, type: 'single_line_text_field' } }) });
      }

      console.log(`✅ Uploaded ${imageType} image for vendor: ${req.params.handle}`);
      res.json({ success: true, imageType, url: uploadedImageUrl, metafield: metafieldResult.metafield });
    } catch (err) {
      console.error('Error uploading store image:', err);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  }
);

app.delete('/api/vendors/:handle/settings/images/:imageType',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      const collectionId = req.collection.id;
      const metafieldKey = req.params.imageType;
      const existingMetafields = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      const existingMf = existingMetafields.metafields?.find(mf => mf.key === metafieldKey && mf.namespace === 'custom');
      if (existingMf) {
        await shopifyFetch(`/metafields/${existingMf.id}.json`, { method: 'DELETE' });
      }
      res.json({ success: true, deleted: metafieldKey });
    } catch (err) {
      console.error('Error deleting store image:', err);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

// =============================================================================
// ROUTES: SUBSCRIBERS & SEGMENTS (Azure SQL)
// =============================================================================

/**
 * GET /api/vendors/:handle/subscribers/count
 * Returns active subscriber count from Azure SQL (replaces Omnisend call).
 */
app.get('/api/vendors/:handle/subscribers/count',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    try {
      const db = await getSqlPool();
      const result = await db.request()
        .input('vendor', sql.NVarChar(64), handle)
        .query(`
          SELECT COUNT(*) AS count
          FROM dbo.vendor_subscriptions vs
          JOIN dbo.contacts c ON c.contact_id = vs.contact_id
          WHERE vs.vendor_tag = @vendor
            AND vs.vendor_status = 'subscribed'
            AND c.global_status = 'subscribed'
            AND NOT EXISTS (
              SELECT 1 FROM dbo.suppressions sup
              WHERE sup.contact_id = c.contact_id
                AND (sup.vendor_tag IS NULL OR sup.vendor_tag = @vendor)
            )
        `);
      return res.json({ count: result.recordset[0].count });
    } catch (err) {
      console.error('[SQL] subscriber count error:', err.message);
      return res.status(500).json({ error: 'Failed to fetch subscriber count' });
    }
  }
);

/**
 * GET /api/vendors/:handle/segments
 * Returns available segments for the email builder dropdown.
 * Always includes an "All Subscribers" option.
 */
app.get('/api/vendors/:handle/segments',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    try {
      const db = await getSqlPool();

      // Get total subscriber count for the "All" option
      const countResult = await db.request()
        .input('vendor', sql.NVarChar(64), handle)
        .query(`
          SELECT COUNT(*) AS count
          FROM dbo.vendor_subscriptions vs
          JOIN dbo.contacts c ON c.contact_id = vs.contact_id
          WHERE vs.vendor_tag = @vendor
            AND vs.vendor_status = 'subscribed'
            AND c.global_status = 'subscribed'
            AND NOT EXISTS (
              SELECT 1 FROM dbo.suppressions sup
              WHERE sup.contact_id = c.contact_id
                AND (sup.vendor_tag IS NULL OR sup.vendor_tag = @vendor)
            )
        `);

      const totalCount = countResult.recordset[0].count;

      // Get named segments with their counts
      const segmentsResult = await db.request()
        .input('vendor', sql.NVarChar(64), handle)
        .query(`
          SELECT
            s.segment_key,
            s.segment_label,
            COUNT(cs.contact_id) AS member_count
          FROM dbo.segments s
          LEFT JOIN dbo.contact_segments cs ON cs.segment_id = s.segment_id
          LEFT JOIN dbo.vendor_subscriptions vs ON vs.contact_id = cs.contact_id AND vs.vendor_tag = @vendor
          LEFT JOIN dbo.contacts c ON c.contact_id = cs.contact_id
          WHERE s.vendor_tag = @vendor
  AND s.is_active = 1
  AND vs.vendor_status = 'subscribed'
  AND c.global_status = 'subscribed'
  AND NOT EXISTS (
    SELECT 1 FROM dbo.suppressions sup
    WHERE sup.contact_id = c.contact_id
      AND (sup.vendor_tag IS NULL OR sup.vendor_tag = @vendor)
  )
          GROUP BY s.segment_id, s.segment_key, s.segment_label
          ORDER BY s.segment_label
        `);

      const segments = [
        { label: `All Subscribers (${totalCount.toLocaleString()})`, value: 'all' },
        ...segmentsResult.recordset.map(s => ({
          label: `${s.segment_label} (${s.member_count.toLocaleString()})`,
          value: s.segment_key
        }))
      ];

      return res.json({ segments });
    } catch (err) {
      console.error('[SQL] segments fetch error:', err.message);
      // Fail gracefully — return just the "all" option so the UI still works
      return res.json({ segments: [{ label: 'All Subscribers', value: 'all' }] });
    }
  }
);

// =============================================================================
// ROUTES: EMAIL — TEST SEND
// =============================================================================

/**
 * POST /api/vendors/:handle/email/test
 * Sends a single test email to the vendor themselves (not the subscriber list).
 * Does NOT inject unsubscribe URL or use configuration set — purely for preview.
 */
app.post('/api/vendors/:handle/email/test',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { to, subject, htmlContent } = req.body;
    if (!to || !subject || !htmlContent) {
      return res.status(400).json({ error: 'Missing required fields: to, subject, htmlContent' });
    }
    try {
      await ses.send(new SendEmailCommand({
        Source: process.env.SES_FROM_EMAIL,
        Destination: { ToAddresses: [to] },
        Message: {
          Subject: { Data: subject },
          Body: {
            Html: { Data: htmlContent },
            Text: { Data: 'View this email in an HTML-compatible email client.' }
          }
        }
        // Note: No ConfigurationSetName on test sends — keeps bounce stats clean
      }));
      return res.json({ success: true });
    } catch (err) {
      console.error('SES test send error:', err);
      return res.status(500).json({ error: 'Test send failed: ' + err.message });
    }
  }
);

// =============================================================================
// ROUTES: EMAIL — CAMPAIGN SEND (SES, per-recipient)
// =============================================================================

/**
 * POST /api/vendors/:handle/email/send
 *
 * Sends a campaign to a vendor's subscriber segment.
 * - Queries Azure SQL for eligible recipients (subscribed, not suppressed)
 * - Sends one SES email per recipient (no BCC batching)
 * - Injects a personalized unsubscribe URL into each email
 * - Adds List-Unsubscribe headers (required by Gmail/Yahoo bulk sender policy)
 * - Logs the send (success or failure) to email_send_log
 *
 * Body:
 *   subject       {string}  Required
 *   htmlContent   {string}  Required — must contain {{unsubscribe_url}} placeholder
 *   segment_key   {string}  Required — 'all' or a named segment key
 *   previewText   {string}  Optional — used for display only, already baked into HTML
 */
app.post('/api/vendors/:handle/email/send',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    const { subject, htmlContent, segment_key, previewText } = req.body;

    if (!subject || !htmlContent || !segment_key) {
      return res.status(400).json({ error: 'subject, htmlContent, and segment_key are required' });
    }

    let recipientCount = 0;

    try {
      const db = await getSqlPool();

      // ── Resolve recipient list ──────────────────────────────────────────────
      const audienceResult = await db.request()
        .input('vendor',     sql.NVarChar(64), handle)
        .input('segmentKey', sql.NVarChar(80), segment_key)
        .query(`
          IF @segmentKey = 'all'
          BEGIN
            SELECT c.email
            FROM dbo.vendor_subscriptions vs
            JOIN dbo.contacts c ON c.contact_id = vs.contact_id
            WHERE vs.vendor_tag = @vendor
              AND vs.vendor_status = 'subscribed'
              AND c.global_status = 'subscribed'
              AND NOT EXISTS (
                SELECT 1 FROM dbo.suppressions sup
                WHERE sup.contact_id = c.contact_id
                  AND (sup.vendor_tag IS NULL OR sup.vendor_tag = @vendor)
              )
          END
          ELSE
          BEGIN
            DECLARE @segmentId INT = (
              SELECT TOP 1 segment_id
              FROM dbo.segments
              WHERE vendor_tag = @vendor
                AND segment_key = @segmentKey
                AND is_active = 1
            );

            SELECT c.email
            FROM dbo.contact_segments cs
            JOIN dbo.vendor_subscriptions vs ON vs.contact_id = cs.contact_id
            JOIN dbo.contacts c ON c.contact_id = cs.contact_id
            WHERE cs.segment_id = @segmentId
              AND vs.vendor_tag = @vendor
              AND vs.vendor_status = 'subscribed'
              AND c.global_status = 'subscribed'
              AND NOT EXISTS (
                SELECT 1 FROM dbo.suppressions sup
                WHERE sup.contact_id = c.contact_id
                  AND (sup.vendor_tag IS NULL OR sup.vendor_tag = @vendor)
              )
          END
        `);

      const emails = audienceResult.recordset.map(r => r.email);
      recipientCount = emails.length;

      if (recipientCount === 0) {
        return res.status(400).json({ error: 'No active subscribers found for this segment.' });
      }

      // ── Send one email per recipient ────────────────────────────────────────
      let sentCount  = 0;
      let errorCount = 0;

      for (const email of emails) {
        try {
          await sendSingleEmail({ toEmail: email, subject, htmlContent, vendorTag: handle });
          sentCount++;
        } catch (sendErr) {
          // Log individual failures but keep going — don't abort the whole campaign
          console.error(`[SES] Failed to send to ${email}:`, sendErr.message);
          errorCount++;
        }

        // Throttle: SES default shared-IP rate is 14 msg/sec
        // 75ms delay ≈ ~13/sec, safely under the limit
        await new Promise(r => setTimeout(r, 75));
      }

      // ── Log the send ────────────────────────────────────────────────────────
      const logResult = await db.request()
        .input('vendor_tag',      sql.NVarChar(64),  handle)
        .input('segment_key',     sql.NVarChar(80),  segment_key)
        .input('message_type',    sql.NVarChar(20),  'campaign')
        .input('subject',         sql.NVarChar(200), subject)
        .input('recipient_count', sql.Int,           sentCount)
        .input('provider',        sql.NVarChar(20),  'ses')
        .input('status',          sql.NVarChar(20),  errorCount > 0 ? 'partial' : 'sent')
        .query(`
          INSERT INTO dbo.email_send_log
            (vendor_tag, segment_key, message_type, subject, recipient_count, provider, status)
          VALUES
            (@vendor_tag, @segment_key, @message_type, @subject, @recipient_count, @provider, @status);
          SELECT SCOPE_IDENTITY() AS send_id;
        `);

      const sendId = logResult.recordset[0].send_id;

      console.log(`[Email] Campaign ${sendId}: ${sentCount} sent, ${errorCount} failed — vendor: ${handle}`);

      return res.json({
        success: true,
        send_id: sendId,
        recipients: sentCount,
        errors: errorCount > 0 ? errorCount : undefined
      });

    } catch (err) {
      console.error('[Email] Campaign error:', err);

      // Log the failure
      try {
        const db = await getSqlPool();
        await db.request()
          .input('vendor_tag',      sql.NVarChar(64),   handle)
          .input('segment_key',     sql.NVarChar(80),   segment_key)
          .input('message_type',    sql.NVarChar(20),   'campaign')
          .input('subject',         sql.NVarChar(200),  subject)
          .input('recipient_count', sql.Int,            0)
          .input('provider',        sql.NVarChar(20),   'ses')
          .input('status',          sql.NVarChar(20),   'failed')
          .input('error_message',   sql.NVarChar(500),  err.message)
          .query(`
            INSERT INTO dbo.email_send_log
              (vendor_tag, segment_key, message_type, subject, recipient_count, provider, status, error_message)
            VALUES
              (@vendor_tag, @segment_key, @message_type, @subject, @recipient_count, @provider, @status, @error_message);
          `);
      } catch (logErr) {
        console.error('[Email] Failed to log campaign error:', logErr.message);
      }

      return res.status(500).json({ error: 'Campaign send failed', details: err.message });
    }
  }
);

// =============================================================================
// ROUTES: UNSUBSCRIBE
// =============================================================================

/**
 * GET /unsubscribe
 * Handles one-click unsubscribe links embedded in campaign emails.
 * Validates the HMAC token, then marks the contact as unsubscribed
 * in both the vendor_subscriptions table and the suppressions table.
 */
app.get('/unsubscribe', async (req, res) => {
  const { email, vendor, token } = req.query;

  if (!email || !vendor || !token) {
    return res.status(400).send(unsubscribePage('Invalid unsubscribe link.', false));
  }

  // Validate token (prevents forged unsubscribe requests)
  let valid = false;
  try {
    valid = validateUnsubscribeToken(decodeURIComponent(email), decodeURIComponent(vendor), token);
  } catch (_) {
    valid = false;
  }

  if (!valid) {
    return res.status(400).send(unsubscribePage('This unsubscribe link is invalid or has expired.', false));
  }

  const decodedEmail  = decodeURIComponent(email);
  const decodedVendor = decodeURIComponent(vendor);

  try {
    const db = await getSqlPool();

    // Update vendor_subscriptions
    await db.request()
      .input('email',  sql.NVarChar(255), decodedEmail)
      .input('vendor', sql.NVarChar(64),  decodedVendor)
      .query(`
        UPDATE vs
        SET vs.vendor_status = 'unsubscribed',
            vs.updated_at    = GETUTCDATE()
        FROM dbo.vendor_subscriptions vs
        JOIN dbo.contacts c ON c.contact_id = vs.contact_id
        WHERE c.email = @email
          AND vs.vendor_tag = @vendor
      `);

    // Insert into suppressions (ignore if already exists)
    await db.request()
      .input('email',  sql.NVarChar(255), decodedEmail)
      .input('vendor', sql.NVarChar(64),  decodedVendor)
      .query(`
        IF NOT EXISTS (
          SELECT 1 FROM dbo.suppressions s
          JOIN dbo.contacts c ON c.contact_id = s.contact_id
          WHERE c.email = @email AND s.vendor_tag = @vendor AND s.reason = 'unsubscribe'
        )
        BEGIN
          INSERT INTO dbo.suppressions (contact_id, vendor_tag, reason, suppressed_at)
          SELECT c.contact_id, @vendor, 'unsubscribe', GETUTCDATE()
          FROM dbo.contacts c
          WHERE c.email = @email
        END
      `);

    console.log(`[Unsubscribe] ${decodedEmail} unsubscribed from ${decodedVendor}`);
    return res.send(unsubscribePage(`You have been unsubscribed from ${decodedVendor} emails.`, true));
  } catch (err) {
    console.error('[Unsubscribe] DB error:', err.message);
    return res.status(500).send(unsubscribePage('Something went wrong. Please try again later.', false));
  }
});

/** Simple HTML page returned after unsubscribe */
function unsubscribePage(message, success) {
  const color = success ? '#166534' : '#991b1b';
  const bg    = success ? '#dcfce7' : '#fee2e2';
  return `<!DOCTYPE html><html><head><title>Unsubscribe</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f9fafb;}
  .card{background:white;border-radius:12px;padding:40px;max-width:440px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.08);}
  .badge{display:inline-block;padding:12px 20px;border-radius:8px;font-size:15px;font-weight:600;background:${bg};color:${color};margin-bottom:20px;}
  p{color:#555;font-size:14px;line-height:1.6;margin:0;}
  a{color:#ac380b;text-decoration:none;font-weight:600;}</style></head>
  <body><div class="card">
    <div class="badge">${message}</div>
    <p>Questions? <a href="mailto:hello@halfcourse.com">Contact us</a></p>
  </div></body></html>`;
}

// =============================================================================
// ROUTES: SNS WEBHOOK — BOUNCE & COMPLAINT HANDLING
// =============================================================================

/**
 * POST /webhooks/ses-notifications
 *
 * Receives bounce and complaint notifications from AWS SNS.
 * SNS sends a SubscriptionConfirmation on first setup — this handler
 * auto-confirms it. After that, all bounce/complaint events from SES
 * flow through here and are written to the suppressions table.
 *
 * AWS SNS sends Content-Type: text/plain even for JSON bodies,
 * so we parse req.body as a string.
 */
app.post('/webhooks/ses-notifications',
  express.text({ type: '*/*' }),  // SNS sends text/plain
  async (req, res) => {
    // Always respond 200 immediately — SNS retries on non-200
    res.sendStatus(200);

    let envelope;
    try {
      envelope = JSON.parse(req.body);
    } catch (_) {
      console.error('[SNS] Failed to parse envelope');
      return;
    }

    // ── Auto-confirm SNS subscription ──────────────────────────────────────
    if (envelope.Type === 'SubscriptionConfirmation') {
      try {
        await fetch(envelope.SubscribeURL);
        console.log('[SNS] Subscription confirmed');
      } catch (err) {
        console.error('[SNS] Failed to confirm subscription:', err.message);
      }
      return;
    }

    if (envelope.Type !== 'Notification') return;

    let notification;
    try {
      notification = JSON.parse(envelope.Message);
    } catch (_) {
      console.error('[SNS] Failed to parse notification message');
      return;
    }

    const notifType = notification.notificationType;
    let affectedEmails = [];
    let reason = '';

    if (notifType === 'Bounce') {
      // Only suppress on permanent (hard) bounces — not transient ones
      if (notification.bounce?.bounceType !== 'Permanent') return;
      affectedEmails = (notification.bounce?.bouncedRecipients || []).map(r => r.emailAddress);
      reason = 'hard_bounce';
    } else if (notifType === 'Complaint') {
      affectedEmails = (notification.complaint?.complainedRecipients || []).map(r => r.emailAddress);
      reason = 'complaint';
    } else {
      return; // Delivery notifications etc. — no action needed
    }

    if (!affectedEmails.length) return;

    try {
      const db = await getSqlPool();

      for (const email of affectedEmails) {
        // Update global_status on contacts
        await db.request()
          .input('email',  sql.NVarChar(255), email)
          .input('status', sql.NVarChar(20),  reason === 'hard_bounce' ? 'bounced' : 'complained')
          .query(`
            UPDATE dbo.contacts
            SET global_status = @status, updated_at = GETUTCDATE()
            WHERE email = @email
          `);

        // Insert into suppressions (global — no vendor_tag, affects all vendors)
        await db.request()
          .input('email',  sql.NVarChar(255), email)
          .input('reason', sql.NVarChar(50),  reason)
          .query(`
            IF NOT EXISTS (
              SELECT 1 FROM dbo.suppressions s
              JOIN dbo.contacts c ON c.contact_id = s.contact_id
              WHERE c.email = @email AND s.reason = @reason AND s.vendor_tag IS NULL
            )
            BEGIN
              INSERT INTO dbo.suppressions (contact_id, vendor_tag, reason, suppressed_at)
              SELECT contact_id, NULL, @reason, GETUTCDATE()
              FROM dbo.contacts WHERE email = @email
            END
          `);

        console.log(`[SNS] Suppressed ${email} — reason: ${reason}`);
      }
    } catch (err) {
      console.error('[SNS] DB write error:', err.message);
    }
  }
);

// =============================================================================
// ROUTES: CONTACT UPSERT (called by Azure Function after form submissions)
// =============================================================================

/**
 * POST /api/contacts/upsert
 *
 * Called by the Azure Function (function_app.py) after a successful
 * identify event (subscriber form submission). Writes contact data to
 * Azure SQL so that SES campaigns can target these subscribers.
 *
 * This endpoint is internal — secured by a shared secret header
 * rather than vendor auth.
 *
 * Body:
 *   email       {string}  Required
 *   firstName   {string}
 *   lastName    {string}
 *   phone       {string}
 *   vendorTag   {string}  e.g. "liandros"
 *   source      {string}  e.g. "waitlist-form", "collection-page"
 */
app.post('/api/contacts/upsert', async (req, res) => {
  // Verify internal secret — set INTERNAL_API_SECRET in Render env vars
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== process.env.INTERNAL_API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { email, firstName, lastName, phone, vendorTag, source } = req.body;
  if (!email) return res.status(400).json({ error: 'email is required' });

  try {
    const db = await getSqlPool();

    // Upsert into contacts (email is unique)
    const contactResult = await db.request()
      .input('email',      sql.NVarChar(255), email.toLowerCase().trim())
      .input('firstName',  sql.NVarChar(100), firstName || null)
      .input('lastName',   sql.NVarChar(100), lastName  || null)
      .input('phone',      sql.NVarChar(50),  phone     || null)
      .input('source',     sql.NVarChar(100), source    || null)
      .query(`
        MERGE dbo.contacts AS target
        USING (SELECT @email AS email) AS source
        ON target.email = source.email
        WHEN MATCHED THEN
          UPDATE SET
            first_name    = COALESCE(@firstName, target.first_name),
            last_name     = COALESCE(@lastName,  target.last_name),
            phone         = COALESCE(@phone,     target.phone),
            updated_at    = GETUTCDATE()
        WHEN NOT MATCHED THEN
          INSERT (email, first_name, last_name, phone, global_status, source, created_at, updated_at)
          VALUES (@email, @firstName, @lastName, @phone, 'subscribed', @source, GETUTCDATE(), GETUTCDATE());
        SELECT contact_id FROM dbo.contacts WHERE email = @email;
      `);

    const contactId = contactResult.recordset[0].contact_id;

    // Upsert vendor subscription if vendorTag provided
    if (vendorTag) {
      await db.request()
        .input('contactId', sql.Int,         contactId)
        .input('vendor',    sql.NVarChar(64), vendorTag)
        .query(`
          MERGE dbo.vendor_subscriptions AS target
          USING (SELECT @contactId AS contact_id, @vendor AS vendor_tag) AS source
          ON target.contact_id = source.contact_id AND target.vendor_tag = source.vendor_tag
          WHEN MATCHED AND target.vendor_status != 'subscribed' THEN
            UPDATE SET vendor_status = 'subscribed', updated_at = GETUTCDATE()
          WHEN NOT MATCHED THEN
            INSERT (contact_id, vendor_tag, vendor_status, created_at, updated_at)
            VALUES (@contactId, @vendor, 'subscribed', GETUTCDATE(), GETUTCDATE());
        `);
    }

    console.log(`[Contacts] Upserted: ${email} (vendor: ${vendorTag || 'none'})`);
    return res.json({ success: true, contact_id: contactId });
  } catch (err) {
    console.error('[Contacts] Upsert error:', err.message);
    return res.status(500).json({ error: 'Failed to upsert contact' });
  }
});

// =============================================================================
// ROUTES: SQL HEALTH CHECK (protected)
// =============================================================================

/**
 * GET /sqltest
 * Internal SQL connectivity check. Protected by internal secret header.
 * Remove or restrict this route before going to production.
 */
app.get('/sqltest', async (req, res) => {
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== process.env.INTERNAL_API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const db = await getSqlPool();
    const result = await db.request().query('SELECT GETUTCDATE() AS now');
    res.json({ sql_time: result.recordset[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Not found', message: `${req.method} ${req.path} does not exist` });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// =============================================================================
// START SERVER
// =============================================================================

app.listen(PORT, () => {
  console.log('');
  console.log('🍽️  HalfCourse Vendor API');
  console.log('========================');
  console.log(`Server running on port ${PORT}`);
  console.log(`App URL: ${APP_URL}`);
  console.log(`Store: ${SHOPIFY_STORE}`);
  console.log(`Shopify Connected: ${!!shopifyAccessTokens[SHOPIFY_STORE]}`);
  console.log(`SES Configured: ${!!process.env.AWS_REGION && !!process.env.SES_FROM_EMAIL}`);
  console.log(`SQL Configured: ${!!process.env.SQL_SERVER}`);
  console.log(`Configured vendors: ${Object.keys(VENDOR_MAP).join(', ')}`);
  console.log('');
});
