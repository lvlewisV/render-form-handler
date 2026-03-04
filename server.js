/**
 * HalfCourse Vendor Product Editor API
 *
 * Features:
 * - Shopify OAuth authentication
 * - Token persistence (survives server restarts)
 * - Vendor login with password protection
 * - Product CRUD operations (filtered by vendor)
 * - Image upload/delete
 * - Metafields support
 * - Collection/Store settings management
 * - Email campaigns via Amazon SES + Azure SQL (all sends)
 * - Subscriber counts from Azure SQL
 * - SQL-driven audience segments
 * - HMAC-signed one-click unsubscribe (Gmail/Yahoo compliant)
 * - SNS webhook for bounce/complaint/delivery/open/click suppression & tracking
 * - Campaign logging to email_send_log
 * - Per-recipient SES MessageId logging to email_send_recipients
 *
 * Azure SQL DDL required for per-recipient tracking:
 *
 *   CREATE TABLE email_send_recipients (
 *     id              INT IDENTITY(1,1) PRIMARY KEY,
 *     campaign_id     NVARCHAR(100)  NOT NULL,
 *     contact_id      INT            NOT NULL,
 *     email           NVARCHAR(254)  NOT NULL,
 *     ses_message_id  NVARCHAR(200)  NULL,
 *     status          NVARCHAR(50)   NOT NULL DEFAULT 'sent',
 *     sent_at         DATETIME2      NOT NULL DEFAULT GETUTCDATE(),
 *     event_at        DATETIME2      NULL,
 *     INDEX IX_campaign   (campaign_id),
 *     INDEX IX_message_id (ses_message_id),
 *     INDEX IX_email      (email)
 *   );
 *
 * status values: sent | delivered | opened | clicked | bounced | complained
 *
 * Deploy to: Render.com
 * Repository: github.com/lvlewisV/hc-vendor-api-oauth.js
 */

const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses");
const sql  = require("mssql");
const crypto = require("crypto");

// ── SES client ────────────────────────────────────────────────────────────────
const ses = new SESClient({ region: process.env.AWS_REGION || "us-east-1" });

// ── Azure SQL pool (lazy-initialised) ─────────────────────────────────────────
let sqlPool = null;
async function getPool() {
  if (sqlPool) return sqlPool;
  sqlPool = await sql.connect({
    server:   process.env.SQL_SERVER,
    database: process.env.SQL_DATABASE,
    user:     process.env.SQL_USERNAME,
    password: process.env.SQL_PASSWORD,
    options:  { encrypt: true, trustServerCertificate: false },
    pool:     { max: 10, min: 0, idleTimeoutMillis: 30000 },
  });
  console.log("✅ Azure SQL pool connected");
  return sqlPool;
}

const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');

const app = express();

// =============================================================================
// CONFIGURATION
// =============================================================================

const PORT = process.env.PORT || 3000;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'half-course';
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Vendor handle to Shopify vendor name mapping
// The key is the URL-friendly handle, the value is the exact vendor name in Shopify
const VENDOR_MAP = {
  'liandros': "Liandro's",
  // Add more vendors here as needed:
  // 'marias-kitchen': "Maria's Kitchen",
  // 'bobs-bbq': "Bob's BBQ",
};

// Token storage file path (for persistence across restarts)
const TOKEN_FILE = process.env.TOKEN_FILE || path.join(__dirname, 'shopify_tokens.json');

// =============================================================================
// TOKEN PERSISTENCE
// =============================================================================

// In-memory token storage (loaded from file on startup)
let shopifyAccessTokens = {};

// Load tokens from file on startup
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = fs.readFileSync(TOKEN_FILE, 'utf8');
      shopifyAccessTokens = JSON.parse(data);
      console.log('✅ Loaded tokens from file');
    }
  } catch (error) {
    console.log('⚠️ Could not load tokens from file:', error.message);
    shopifyAccessTokens = {};
  }
}

// Save tokens to file
function saveTokens() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(shopifyAccessTokens, null, 2));
    console.log('✅ Saved tokens to file');
  } catch (error) {
    console.log('⚠️ Could not save tokens to file:', error.message);
  }
}

// Load tokens on startup
loadTokens();

(async () => {
  try {
    const pool = await getPool();
    const result = await pool.request()
      .input('store', sql.NVarChar, SHOPIFY_STORE)
      .query(`
        SELECT access_token
        FROM shopify_tokens
        WHERE store = @store
      `);

    if (result.recordset.length) {
      shopifyAccessTokens[SHOPIFY_STORE] = result.recordset[0].access_token;
      console.log('✅ Loaded Shopify token from SQL');
    }
  } catch (err) {
    console.error('⚠️ Could not load Shopify token from SQL:', err.message);
  }
})();

// Vendor session tokens (in-memory, expire after 24 hours)
const vendorSessions = {};

// =============================================================================
// MIDDLEWARE
// =============================================================================

// CORS configuration - allow requests from Shopify storefront
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

// Handle preflight requests
app.options('*', cors(corsOptions));

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// File upload handling (for product images)
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

/**
 * Middleware: Require Shopify OAuth connection
 * Checks if we have a valid access token for the store
 */
function requireShopifyAuth(req, res, next) {
  const token = shopifyAccessTokens[SHOPIFY_STORE];
  if (!token) {
    return res.status(401).json({ 
      error: 'Shopify not connected',
      message: 'Please connect to Shopify first by visiting the /auth endpoint'
    });
  }
  req.shopifyToken = token;
  req.shop = SHOPIFY_STORE;
  next();
}

/**
 * Middleware: Require vendor authentication
 * Validates the vendor session token from Authorization header
 */
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
  
  // Check if session expired (24 hours)
  if (Date.now() - session.created > 24 * 60 * 60 * 1000) {
    delete vendorSessions[token];
    return res.status(401).json({ error: 'Session expired' });
  }
  
  // Verify vendor handle matches route parameter
  if (req.params.handle && session.handle !== req.params.handle) {
    return res.status(403).json({ error: 'Access denied to this vendor' });
  }
  
  req.vendorSession = session;
  next();
}

/**
 * Middleware: Validate product ownership
 * Ensures the product belongs to the authenticated vendor
 */
async function validateProductOwnership(req, res, next) {
  const productId = req.params.productId;
  if (!productId) return next();
  
  const vendorName = VENDOR_MAP[req.vendorSession.handle];
  if (!vendorName) {
    return res.status(400).json({ error: 'Invalid vendor' });
  }
  
  try {
    const response = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/products/${productId}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': req.shopifyToken,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!response.ok) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    const data = await response.json();
    
    if (data.product.vendor !== vendorName) {
      return res.status(403).json({ error: 'You do not have permission to modify this product' });
    }
    
    req.product = data.product;
    next();
  } catch (error) {
    console.error('Error validating product ownership:', error);
    res.status(500).json({ error: 'Failed to validate product ownership' });
  }
}

/**
 * Middleware: Validate collection ownership
 * Ensures the collection belongs to the authenticated vendor
 */
async function validateCollectionOwnership(req, res, next) {
  const collectionHandle = req.params.handle;
  if (!collectionHandle) return next();
  
  // Vendor can only access their own collection (handle must match)
  if (req.vendorSession.handle !== collectionHandle) {
    return res.status(403).json({ error: 'Access denied to this collection' });
  }
  
  try {
    // Get collection by handle
    const response = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/custom_collections.json?handle=${collectionHandle}`,
      {
        headers: {
          'X-Shopify-Access-Token': req.shopifyToken,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!response.ok) {
      // Try smart collections if custom collection not found
      const smartResponse = await fetch(
        `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/smart_collections.json?handle=${collectionHandle}`,
        {
          headers: {
            'X-Shopify-Access-Token': req.shopifyToken,
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (!smartResponse.ok) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      const smartData = await smartResponse.json();
      if (!smartData.smart_collections || smartData.smart_collections.length === 0) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      req.collection = smartData.smart_collections[0];
      req.collectionType = 'smart';
      return next();
    }
    
    const data = await response.json();
    if (!data.custom_collections || data.custom_collections.length === 0) {
      // Try smart collections
      const smartResponse = await fetch(
        `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01/smart_collections.json?handle=${collectionHandle}`,
        {
          headers: {
            'X-Shopify-Access-Token': req.shopifyToken,
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (smartResponse.ok) {
        const smartData = await smartResponse.json();
        if (smartData.smart_collections && smartData.smart_collections.length > 0) {
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
  } catch (error) {
    console.error('Error validating collection ownership:', error);
    res.status(500).json({ error: 'Failed to validate collection ownership' });
  }
}

// =============================================================================
// SHOPIFY API HELPER
// =============================================================================

async function shopifyFetch(endpoint, options = {}) {
  const token = shopifyAccessTokens[SHOPIFY_STORE];
  if (!token) {
    throw new Error('Shopify not connected');
  }
  
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
  
  // Handle empty responses (like DELETE)
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

// =============================================================================
// EMAIL HELPERS (SES + AZURE SQL)
// =============================================================================

/**
 * Returns the vendor tag / segment key for a given handle.
 * Contacts must be subscribed to vendor_subscriptions with this vendor_handle.
 */
function getVendorTag(handle) {
  return handle.toLowerCase().replace(/\s+/g, '-');
}

/**
 * Generate an HMAC-SHA256 signed unsubscribe token for a contact.
 * Token format: base64url(email):base64url(hmac)
 */
function signUnsubscribeToken(email) {
  const secret = process.env.SES_UNSUBSCRIBE_SECRET || process.env.SHOPIFY_CLIENT_SECRET;
  const hmac = crypto.createHmac("sha256", secret).update(email).digest("base64url");
  return `${Buffer.from(email).toString("base64url")}:${hmac}`;
}

/**
 * Verify an unsubscribe token. Returns email string or null if invalid.
 */
function verifyUnsubscribeToken(token) {
  try {
    const [emailB64, hmac] = token.split(":");
    const email = Buffer.from(emailB64, "base64url").toString();
    const expected = crypto.createHmac("sha256", process.env.SES_UNSUBSCRIBE_SECRET || process.env.SHOPIFY_CLIENT_SECRET)
      .update(email).digest("base64url");
    if (hmac !== expected) return null;
    return email;
  } catch (_) { return null; }
}

/**
 * Build the SQL WHERE clause for an audience segment.
 * Segment values must match the options in the frontend dropdown.
 */
function buildAudienceQuery(audienceKey, vendorHandle) {

  const baseJoin = `
    FROM contacts c
    INNER JOIN vendor_subscriptions vs
      ON vs.contact_id = c.contact_id
  `;

  const baseWhere = `
    WHERE vs.vendor_tag = @vendorHandle
      AND vs.vendor_status = 'subscribed'
      AND c.global_status = 'subscribed'
      AND c.email IS NOT NULL
      AND c.email NOT IN (
        SELECT email
        FROM suppressions
        WHERE vendor_handle = @vendorHandle
           OR vendor_handle IS NULL
      )
  `;

  switch (audienceKey) {

    case 'newsletter':
      return {
        query: `
          ${baseJoin}
          ${baseWhere}
          AND vs.source = 'newsletter'
        `
      };

    case 'sms_opted_in':
      return {
        query: `
          ${baseJoin}
          ${baseWhere}
          AND c.sms_status = 'subscribed'
        `
      };

    case 'recent_buyers':
      return {
        query: `
          ${baseJoin}
          INNER JOIN contact_orders o
            ON o.contact_id = c.contact_id
            AND o.vendor_handle = @vendorHandle
          ${baseWhere}
          AND o.order_date >= DATEADD(day, -30, GETUTCDATE())
        `
      };

    case 'vip':
      return {
        query: `
          ${baseJoin}
          INNER JOIN contact_orders o
            ON o.contact_id = c.contact_id
            AND o.vendor_handle = @vendorHandle
          ${baseWhere}
          GROUP BY c.contact_id, c.email, c.first_name
          HAVING SUM(o.order_total) >= 250
        `
      };

    case 'winback_90':
      return {
        query: `
          ${baseJoin}
          INNER JOIN contact_orders o
            ON o.contact_id = c.contact_id
            AND o.vendor_handle = @vendorHandle
          ${baseWhere}
          GROUP BY c.contact_id, c.email, c.first_name
          HAVING MAX(o.order_date) <= DATEADD(day, -90, GETUTCDATE())
        `
      };

    case 'all':
    default:
      return {
        query: `
          ${baseJoin}
          ${baseWhere}
        `
      };
  }
}

/**
 * Strips HTML tags from a string to produce a plain-text email fallback.
 */
function stripHtmlToText(html) {
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/td>/gi, '  ')
    .replace(/<\/h[1-6]>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Update a recipient row status in email_send_recipients by SES MessageId.
 * Non-fatal — logs errors but does not throw.
 */
async function updateRecipientStatus(pool, sesMessageId, status) {
  if (!sesMessageId) return;
  try {
    await pool.request()
      .input('ses_message_id', sql.NVarChar, sesMessageId)
      .input('status',         sql.NVarChar, status)
      .input('event_at',       sql.DateTime2, new Date())
      .query(`
        UPDATE email_send_recipients
        SET status = @status, event_at = @event_at
        WHERE ses_message_id = @ses_message_id
      `);
  } catch (err) {
    console.error(`[SQL] updateRecipientStatus (${status}) error:`, err.message);
  }
}

// =============================================================================
// ROUTES: HOME & HEALTH
// =============================================================================

/**
 * GET /
 * Home page with OAuth connection status and link
 */
app.get('/', (req, res) => {
  const isConnected = !!shopifyAccessTokens[SHOPIFY_STORE];
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>HalfCourse Vendor API</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          max-width: 600px;
          margin: 50px auto;
          padding: 20px;
          background: #f5f5f5;
        }
        .card {
          background: white;
          border-radius: 12px;
          padding: 30px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #333; margin-top: 0; }
        .status {
          padding: 15px;
          border-radius: 8px;
          margin: 20px 0;
        }
        .connected { background: #d4edda; color: #155724; }
        .disconnected { background: #f8d7da; color: #721c24; }
        .btn {
          display: inline-block;
          padding: 12px 24px;
          background: #ac380b;
          color: white;
          text-decoration: none;
          border-radius: 8px;
          font-weight: 600;
        }
        .btn:hover { background: #8a2d09; }
        code {
          background: #f0f0f0;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 14px;
        }
        ul { line-height: 1.8; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🍽️ HalfCourse Vendor API</h1>
        
        <div class="status ${isConnected ? 'connected' : 'disconnected'}">
          ${isConnected 
            ? '✅ Connected to Shopify!' 
            : '❌ Not connected to Shopify'}
        </div>
        
        ${!isConnected ? `
          <p>Click the button below to connect this API to your Shopify store:</p>
          <a href="/auth" class="btn">Connect to Shopify</a>
        ` : `
          <p>The API is ready to use. Vendors can now log in to their product editors.</p>
          <h3>Available Endpoints:</h3>
          <ul>
            <li><code>GET /health</code> - Health check</li>
            <li><code>POST /api/vendor/login</code> - Vendor login</li>
            <li><code>GET /api/vendors/:handle/products</code> - List products</li>
            <li><code>POST /api/vendors/:handle/products</code> - Create product</li>
            <li><code>PUT /api/vendors/:handle/products/:id</code> - Update product</li>
            <li><code>DELETE /api/vendors/:handle/products/:id</code> - Delete product</li>
            <li><code>GET /api/vendors/:handle/settings</code> - Get store settings</li>
            <li><code>PUT /api/vendors/:handle/settings</code> - Update store settings</li>
            <li><code>POST /api/vendors/:handle/settings/images</code> - Upload store images</li>
            <li><code>GET /api/vendors/:handle/subscribers/count</code> - Subscriber count</li>
            <li><code>POST /api/vendors/:handle/email/send</code> - Send email campaign</li>
            <li><code>POST /api/vendors/:handle/email/test</code> - Send test email (NEW)</li>
          </ul>
          <p style="margin-top: 20px;">
            <a href="/auth" class="btn">Re-authenticate</a>
          </p>
        `}
      </div>
    </body>
    </html>
  `);
});

/**
 * GET /health
 * Health check endpoint for monitoring
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    shopifyConnected: !!shopifyAccessTokens[SHOPIFY_STORE],
    sesConfigured: !!process.env.AWS_REGION && !!process.env.SES_FROM_EMAIL,
    sqlConfigured: !!process.env.SQL_SERVER && !!process.env.SQL_DATABASE,
    store: SHOPIFY_STORE,
    configuredVendors: Object.keys(VENDOR_MAP),
  });
});

// =============================================================================
// ROUTES: SHOPIFY OAUTH
// =============================================================================

/**
 * GET /auth
 * Start Shopify OAuth flow
 */
app.get('/auth', (req, res) => {
  if (!SHOPIFY_CLIENT_ID) {
    return res.status(500).send('SHOPIFY_CLIENT_ID not configured');
  }
  
  const redirectUri = `${APP_URL}/auth/callback`;
  const state = Math.random().toString(36).substring(7);
  
  // Store state for validation (in production, use a proper session store)
  app.locals.oauthState = state;
  
  const authUrl = `https://${SHOPIFY_STORE}.myshopify.com/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;
  
  console.log('Redirecting to Shopify OAuth:', authUrl);
  res.redirect(authUrl);
});

/**
 * GET /auth/callback
 * Shopify OAuth callback - exchange code for access token
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, shop } = req.query;
  
  // Validate state
  if (state !== app.locals.oauthState) {
    return res.status(400).send('Invalid state parameter');
  }
  
  if (!code) {
    return res.status(400).send('No authorization code received');
  }
  
  try {
    // Exchange code for access token
    const tokenResponse = await fetch(
      `https://${SHOPIFY_STORE}.myshopify.com/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: SHOPIFY_CLIENT_ID,
          client_secret: SHOPIFY_CLIENT_SECRET,
          code: code
        })
      }
    );
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);
      return res.status(400).send('Failed to exchange code for token: ' + errorText);
    }
    
    const tokenData = await tokenResponse.json();
    
// Store token in memory
shopifyAccessTokens[SHOPIFY_STORE] = tokenData.access_token;

// Save to SQL
const pool = await getPool();

await pool.request()
  .input('store', sql.NVarChar, SHOPIFY_STORE)
  .input('token', sql.NVarChar, tokenData.access_token)
  .query(`
    MERGE shopify_tokens AS t
    USING (SELECT @store AS store) s
    ON t.store = s.store
    WHEN MATCHED THEN
      UPDATE SET access_token = @token, updated_at = GETUTCDATE()
    WHEN NOT MATCHED THEN
      INSERT (store, access_token, updated_at)
      VALUES (@store, @token, GETUTCDATE());
  `);

// Save to file (optional backup)
saveTokens();
    
    
    console.log('✅ Shopify OAuth successful for store:', SHOPIFY_STORE);
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Connected!</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 100px auto;
            text-align: center;
            padding: 20px;
          }
          .success {
            font-size: 60px;
            margin-bottom: 20px;
          }
          h1 { color: #155724; }
          a {
            color: #ac380b;
            text-decoration: none;
          }
        </style>
      </head>
      <body>
        <div class="success">✅</div>
        <h1>Successfully Connected!</h1>
        <p>The API is now connected to your Shopify store.</p>
        <p><a href="/">← Back to Home</a></p>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('OAuth error: ' + error.message);
  }
});

// =============================================================================
// ROUTES: VENDOR AUTHENTICATION
// =============================================================================

/**
 * POST /api/vendor/login
 * Vendor login - validates password and returns session token
 */
app.post('/api/vendor/login', (req, res) => {
  const { handle, password } = req.body;
  
  if (!handle || !password) {
    return res.status(400).json({ error: 'Handle and password are required' });
  }
  
  // Check if vendor exists in our map
  if (!VENDOR_MAP[handle]) {
    return res.status(404).json({ error: 'Vendor not found' });
  }
  
  // Get password from environment variable
  // Format: VENDOR_LIANDROS_PASSWORD (uppercase handle, hyphens replaced with underscores)
  const envKey = `VENDOR_${handle.toUpperCase().replace(/-/g, '_')}_PASSWORD`;
  const expectedPassword = process.env[envKey] || process.env.DEFAULT_VENDOR_PASSWORD;
  
  if (!expectedPassword) {
    console.error(`No password configured for vendor: ${handle} (looked for ${envKey})`);
    return res.status(500).json({ error: 'Vendor not properly configured' });
  }
  
  if (password !== expectedPassword) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  // Generate session token
  const sessionToken = Math.random().toString(36).substring(2) + 
                       Math.random().toString(36).substring(2) +
                       Date.now().toString(36);
  
  // Store session
  vendorSessions[sessionToken] = {
    handle: handle,
    vendorName: VENDOR_MAP[handle],
    created: Date.now()
  };
  
  console.log(`✅ Vendor logged in: ${handle}`);
  
  res.json({
    success: true,
    token: sessionToken,
    vendor: {
      handle: handle,
      name: VENDOR_MAP[handle]
    }
  });
});

/**
 * POST /api/vendor/logout
 * Vendor logout - invalidates session token
 */
app.post('/api/vendor/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    delete vendorSessions[token];
  }
  
  res.json({ success: true });
});

// =============================================================================
// ROUTES: PRODUCTS
// =============================================================================

/**
 * GET /api/vendors/:handle/products
 * List all products for a vendor
 */
app.get('/api/vendors/:handle/products', 
  requireShopifyAuth, 
  requireVendorAuth,
  async (req, res) => {
    const vendorName = VENDOR_MAP[req.params.handle];
    
    if (!vendorName) {
      return res.status(404).json({ error: 'Vendor not found' });
    }
    
    try {
      // Fetch all products and filter by vendor
      let allProducts = [];
      let pageInfo = null;
      let hasNextPage = true;
      
      while (hasNextPage) {
        let url = '/products.json?limit=250';
        if (pageInfo) {
          url += `&page_info=${pageInfo}`;
        }
        
        const response = await fetch(
          `https://${SHOPIFY_STORE}.myshopify.com/admin/api/2024-01${url}`,
          {
            headers: {
              'X-Shopify-Access-Token': req.shopifyToken,
              'Content-Type': 'application/json'
            }
          }
        );
        
        if (!response.ok) {
          throw new Error(`Shopify API error: ${response.status}`);
        }
        
        const data = await response.json();
        allProducts = allProducts.concat(data.products);
        
        // Check for pagination
        const linkHeader = response.headers.get('link');
        if (linkHeader && linkHeader.includes('rel="next"')) {
          const match = linkHeader.match(/page_info=([^>&]*)/);
          pageInfo = match ? match[1] : null;
          hasNextPage = !!pageInfo;
        } else {
          hasNextPage = false;
        }
        
        // Safety limit
        if (allProducts.length > 1000) break;
      }
      
      // Filter to only this vendor's products
      const vendorProducts = allProducts.filter(p => p.vendor === vendorName);
      
      console.log(`Found ${vendorProducts.length} products for vendor: ${vendorName}`);
      
      res.json({ products: vendorProducts });
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ error: 'Failed to fetch products' });
    }
  }
);

/**
 * POST /api/vendors/:handle/products
 * Create a new product for a vendor
 */
app.post('/api/vendors/:handle/products',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const vendorName = VENDOR_MAP[req.params.handle];
    
    if (!vendorName) {
      return res.status(404).json({ error: 'Vendor not found' });
    }
    
    try {
      const { title, body_html, price, compare_at_price, images, metafields } = req.body;
      
      // Build product data
      const productData = {
        product: {
          title: title,
          body_html: body_html || '',
          vendor: vendorName, // Always set to the authenticated vendor
          status: 'draft', // Start as draft
          variants: [{
            price: price || '0.00',
            compare_at_price: compare_at_price || null,
            inventory_management: null,
            requires_shipping: false
          }]
        }
      };
      
      // Add images if provided
      if (images && images.length > 0) {
        productData.product.images = images.map(img => ({
          attachment: img.attachment, // Base64 encoded image
          alt: img.alt || title
        }));
      }
      
      // Create the product
      const data = await shopifyFetch('/products.json', {
        method: 'POST',
        body: JSON.stringify(productData)
      });
      
      // Add metafields if provided
      if (metafields && data.product) {
        for (const mf of metafields) {
          try {
            await shopifyFetch(`/products/${data.product.id}/metafields.json`, {
              method: 'POST',
              body: JSON.stringify({
                metafield: {
                  namespace: mf.namespace || 'custom',
                  key: mf.key,
                  value: mf.value,
                  type: mf.type || 'single_line_text_field'
                }
              })
            });
          } catch (mfError) {
            console.error('Error adding metafield:', mfError);
          }
        }
      }
      
      console.log(`✅ Created product: ${data.product.title} for vendor: ${vendorName}`);
      
      res.json(data);
    } catch (error) {
      console.error('Error creating product:', error);
      res.status(500).json({ error: 'Failed to create product' });
    }
  }
);

/**
 * PUT /api/vendors/:handle/products/:productId
 * Update an existing product
 */
app.put('/api/vendors/:handle/products/:productId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId } = req.params;
    
    try {
      const { 
        title, 
        body_html, 
        price, 
        compare_at_price, 
        status,
        metafields,
        images_to_delete
      } = req.body;
      
      // Build update data
      const updateData = { product: { id: productId } };
      
      if (title !== undefined) updateData.product.title = title;
      if (body_html !== undefined) updateData.product.body_html = body_html;
      if (status !== undefined) updateData.product.status = status;
      
      // Update variant pricing if provided
      if (price !== undefined || compare_at_price !== undefined) {
        const variant = req.product.variants[0];
        updateData.product.variants = [{
          id: variant.id,
          price: price !== undefined ? price : variant.price,
          compare_at_price: compare_at_price !== undefined ? compare_at_price : variant.compare_at_price
        }];
      }
      
      // Update the product
      const data = await shopifyFetch(`/products/${productId}.json`, {
        method: 'PUT',
        body: JSON.stringify(updateData)
      });
      
      // Delete images if requested
      if (images_to_delete && images_to_delete.length > 0) {
        for (const imageId of images_to_delete) {
          try {
            await shopifyFetch(`/products/${productId}/images/${imageId}.json`, {
              method: 'DELETE'
            });
          } catch (imgError) {
            console.error('Error deleting image:', imgError);
          }
        }
      }
      
      // Update metafields if provided
      if (metafields) {
        for (const mf of metafields) {
          try {
            if (mf.id) {
              // Update existing metafield
              await shopifyFetch(`/metafields/${mf.id}.json`, {
                method: 'PUT',
                body: JSON.stringify({
                  metafield: {
                    id: mf.id,
                    value: mf.value
                  }
                })
              });
            } else {
              // Create new metafield
              await shopifyFetch(`/products/${productId}/metafields.json`, {
                method: 'POST',
                body: JSON.stringify({
                  metafield: {
                    namespace: mf.namespace || 'custom',
                    key: mf.key,
                    value: mf.value,
                    type: mf.type || 'single_line_text_field'
                  }
                })
              });
            }
          } catch (mfError) {
            console.error('Error updating metafield:', mfError);
          }
        }
      }
      
      console.log(`✅ Updated product: ${productId}`);
      
      res.json(data);
    } catch (error) {
      console.error('Error updating product:', error);
      res.status(500).json({ error: 'Failed to update product' });
    }
  }
);

/**
 * DELETE /api/vendors/:handle/products/:productId
 * Delete a product
 */
app.delete('/api/vendors/:handle/products/:productId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId } = req.params;
    
    try {
      await shopifyFetch(`/products/${productId}.json`, {
        method: 'DELETE'
      });
      
      console.log(`✅ Deleted product: ${productId}`);
      
      res.json({ success: true, deleted: productId });
    } catch (error) {
      console.error('Error deleting product:', error);
      res.status(500).json({ error: 'Failed to delete product' });
    }
  }
);

/**
 * POST /api/vendors/:handle/products/:productId/images
 * Upload a new image to a product
 */
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
        // File upload
        imageData = {
          image: {
            attachment: req.file.buffer.toString('base64'),
            alt: req.body.alt || ''
          }
        };
      } else if (req.body.attachment) {
        // Base64 in body
        imageData = {
          image: {
            attachment: req.body.attachment,
            alt: req.body.alt || ''
          }
        };
      } else if (req.body.src) {
        // URL
        imageData = {
          image: {
            src: req.body.src,
            alt: req.body.alt || ''
          }
        };
      } else {
        return res.status(400).json({ error: 'No image provided' });
      }
      
      const data = await shopifyFetch(`/products/${productId}/images.json`, {
        method: 'POST',
        body: JSON.stringify(imageData)
      });
      
      console.log(`✅ Added image to product: ${productId}`);
      
      res.json(data);
    } catch (error) {
      console.error('Error uploading image:', error);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  }
);

/**
 * DELETE /api/vendors/:handle/products/:productId/images/:imageId
 * Delete an image from a product
 */
app.delete('/api/vendors/:handle/products/:productId/images/:imageId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId, imageId } = req.params;
    
    try {
      await shopifyFetch(`/products/${productId}/images/${imageId}.json`, {
        method: 'DELETE'
      });
      
      console.log(`✅ Deleted image ${imageId} from product: ${productId}`);
      
      res.json({ success: true, deleted: imageId });
    } catch (error) {
      console.error('Error deleting image:', error);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

/**
 * GET /api/vendors/:handle/products/:productId/metafields
 * Get metafields for a product
 */
app.get('/api/vendors/:handle/products/:productId/metafields',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    const { productId } = req.params;
    
    try {
      const data = await shopifyFetch(`/products/${productId}/metafields.json`);
      res.json(data);
    } catch (error) {
      console.error('Error fetching metafields:', error);
      res.status(500).json({ error: 'Failed to fetch metafields' });
    }
  }
);

// =============================================================================
// ROUTES: STORE SETTINGS (COLLECTION METAFIELDS)
// =============================================================================

/**
 * GET /api/vendors/:handle/settings
 * Get all store settings (collection + metafields) for a vendor
 */
app.get('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      const collectionId = req.collection.id;
      
      // Get collection metafields
      const metafieldsData = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      
      // Organize metafields by key for easy access
      const metafields = {};
      if (metafieldsData.metafields) {
        for (const mf of metafieldsData.metafields) {
          metafields[mf.key] = {
            id: mf.id,
            namespace: mf.namespace,
            key: mf.key,
            value: mf.value,
            type: mf.type
          };
        }
      }
      
      console.log(`✅ Fetched settings for vendor: ${req.params.handle}`);
      
      res.json({
        collection: {
          id: req.collection.id,
          handle: req.collection.handle,
          title: req.collection.title,
          body_html: req.collection.body_html,
          image: req.collection.image
        },
        metafields: metafields,
        collectionType: req.collectionType
      });
    } catch (error) {
      console.error('Error fetching store settings:', error);
      res.status(500).json({ error: 'Failed to fetch store settings' });
    }
  }
);

/**
 * PUT /api/vendors/:handle/settings
 * Update store settings (collection metafields)
 */
app.put('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    try {
      const collectionId = req.collection.id;
      const { metafields, collection: collectionUpdates } = req.body;
      
      const results = {
        collection: null,
        metafields: []
      };
      
      // Update collection if provided (title, body_html)
      if (collectionUpdates) {
        const collectionEndpoint = req.collectionType === 'smart' 
          ? `/smart_collections/${collectionId}.json`
          : `/custom_collections/${collectionId}.json`;
        
        const collectionData = req.collectionType === 'smart'
          ? { smart_collection: { id: collectionId, ...collectionUpdates } }
          : { custom_collection: { id: collectionId, ...collectionUpdates } };
        
        const collectionResult = await shopifyFetch(collectionEndpoint, {
          method: 'PUT',
          body: JSON.stringify(collectionData)
        });
        
        results.collection = collectionResult;
      }
      
      // Update metafields
      if (metafields && Array.isArray(metafields)) {
        for (const mf of metafields) {
          try {
            if (mf.id) {
              // Update existing metafield
              const result = await shopifyFetch(`/metafields/${mf.id}.json`, {
                method: 'PUT',
                body: JSON.stringify({
                  metafield: {
                    id: mf.id,
                    value: mf.value
                  }
                })
              });
              results.metafields.push({ success: true, key: mf.key, result });
            } else if (mf.value !== undefined && mf.value !== null && mf.value !== '') {
              // Create new metafield (only if value is not empty)
              const result = await shopifyFetch(`/collections/${collectionId}/metafields.json`, {
                method: 'POST',
                body: JSON.stringify({
                  metafield: {
                    namespace: mf.namespace || 'custom',
                    key: mf.key,
                    value: mf.value,
                    type: mf.type || 'single_line_text_field'
                  }
                })
              });
              results.metafields.push({ success: true, key: mf.key, result });
            }
          } catch (mfError) {
            console.error(`Error updating metafield ${mf.key}:`, mfError);
            results.metafields.push({ success: false, key: mf.key, error: mfError.message });
          }
        }
      }
      
      console.log(`✅ Updated settings for vendor: ${req.params.handle}`);
      
      res.json({ success: true, results });
    } catch (error) {
      console.error('Error updating store settings:', error);
      res.status(500).json({ error: 'Failed to update store settings' });
    }
  }
);

/**
 * DELETE /api/vendors/:handle/settings/metafields/:metafieldId
 * Delete a specific metafield
 */
app.delete('/api/vendors/:handle/settings/metafields/:metafieldId',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    const { metafieldId } = req.params;
    
    try {
      await shopifyFetch(`/metafields/${metafieldId}.json`, {
        method: 'DELETE'
      });
      
      console.log(`✅ Deleted metafield: ${metafieldId}`);
      
      res.json({ success: true, deleted: metafieldId });
    } catch (error) {
      console.error('Error deleting metafield:', error);
      res.status(500).json({ error: 'Failed to delete metafield' });
    }
  }
);

/**
 * POST /api/vendors/:handle/settings/images
 * Upload an image for store settings (logo, banner, story images)
 * Returns the Shopify CDN URL for the uploaded image
 */
app.post('/api/vendors/:handle/settings/images',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  upload.single('image'),
  async (req, res) => {
    try {
      const { imageType, alt } = req.body;
      
      if (!imageType) {
        return res.status(400).json({ error: 'imageType is required' });
      }
      
      let imageData;
      
      if (req.file) {
        imageData = req.file.buffer.toString('base64');
      } else if (req.body.attachment) {
        imageData = req.body.attachment;
      } else {
        return res.status(400).json({ error: 'No image provided' });
      }
      
      const collectionId = req.collection.id;
      const metafieldKey = imageType;
      
      // Handle collection image separately
      if (imageType === 'collection_image') {
        const collectionEndpoint = req.collectionType === 'smart' 
          ? `/smart_collections/${collectionId}.json`
          : `/custom_collections/${collectionId}.json`;
        
        const collectionData = req.collectionType === 'smart'
          ? { smart_collection: { id: collectionId, image: { attachment: imageData, alt: alt || '' } } }
          : { custom_collection: { id: collectionId, image: { attachment: imageData, alt: alt || '' } } };
        
        const result = await shopifyFetch(collectionEndpoint, {
          method: 'PUT',
          body: JSON.stringify(collectionData)
        });
        
        console.log(`✅ Updated collection image for vendor: ${req.params.handle}`);
        
        return res.json({ 
          success: true, 
          imageType,
          image: result.smart_collection?.image || result.custom_collection?.image 
        });
      }
      
      // ── CDN Upload via persistent image-bucket product ──────────────────────
      // We use a single long-lived draft product per vendor as an image store.
      // Deleting the product would also delete its images from Shopify's CDN,
      // so we NEVER delete it — only add images to it.
      const bucketTitle = `_hc_image_bucket_${req.params.handle}`;
      let bucketProductId = null;

      // Try to find an existing bucket product for this vendor
      const searchResult = await shopifyFetch(
        `/products.json?title=${encodeURIComponent(bucketTitle)}&status=draft&limit=1`
      );
      if (searchResult.products && searchResult.products.length > 0) {
        bucketProductId = searchResult.products[0].id;
      }

      let uploadedImageUrl;

      if (bucketProductId) {
        // Add image to the existing bucket product
        const imgResult = await shopifyFetch(`/products/${bucketProductId}/images.json`, {
          method: 'POST',
          body: JSON.stringify({
            image: {
              attachment: imageData,
              alt: alt || imageType
            }
          })
        });
        if (!imgResult.image || !imgResult.image.src) {
          throw new Error('Failed to upload image to bucket product');
        }
        uploadedImageUrl = imgResult.image.src;
      } else {
        // Create the bucket product for this vendor (first time)
        const newBucket = await shopifyFetch('/products.json', {
          method: 'POST',
          body: JSON.stringify({
            product: {
              title: bucketTitle,
              status: 'draft',
              published: false,
              images: [{
                attachment: imageData,
                alt: alt || imageType
              }]
            }
          })
        });
        if (!newBucket.product || !newBucket.product.images || newBucket.product.images.length === 0) {
          throw new Error('Failed to create image bucket product');
        }
        uploadedImageUrl = newBucket.product.images[0].src;
      }

      // For email-builder image types (email_logo, email_block_*), skip metafield
      // storage — we only need the CDN URL for email delivery.
      if (imageType === 'email_logo' || imageType.startsWith('email_block_')) {
        console.log(`✅ Uploaded email image (${imageType}) for vendor: ${req.params.handle}`);
        return res.json({ success: true, imageType, url: uploadedImageUrl });
      }

      // Check if metafield exists and upsert
      const existingMetafields = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      const existingMf = existingMetafields.metafields?.find(mf => mf.key === metafieldKey && mf.namespace === 'custom');
      
      let metafieldResult;
      if (existingMf) {
        metafieldResult = await shopifyFetch(`/metafields/${existingMf.id}.json`, {
          method: 'PUT',
          body: JSON.stringify({ metafield: { id: existingMf.id, value: uploadedImageUrl } })
        });
      } else {
        metafieldResult = await shopifyFetch(`/collections/${collectionId}/metafields.json`, {
          method: 'POST',
          body: JSON.stringify({
            metafield: {
              namespace: 'custom',
              key: metafieldKey,
              value: uploadedImageUrl,
              type: 'single_line_text_field'
            }
          })
        });
      }
      
      console.log(`✅ Uploaded ${imageType} image for vendor: ${req.params.handle}`);
      
      res.json({ 
        success: true, 
        imageType,
        url: uploadedImageUrl,
        metafield: metafieldResult.metafield
      });
    } catch (error) {
      console.error('Error uploading store image:', error);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  }
);

/**
 * DELETE /api/vendors/:handle/settings/images/:imageType
 * Delete an image metafield
 */
app.delete('/api/vendors/:handle/settings/images/:imageType',
  requireShopifyAuth,
  requireVendorAuth,
  validateCollectionOwnership,
  async (req, res) => {
    const { imageType } = req.params;
    
    try {
      const collectionId = req.collection.id;
      const metafieldKey = imageType;
      
      const existingMetafields = await shopifyFetch(`/collections/${collectionId}/metafields.json`);
      const existingMf = existingMetafields.metafields?.find(mf => mf.key === metafieldKey && mf.namespace === 'custom');
      
      if (existingMf) {
        await shopifyFetch(`/metafields/${existingMf.id}.json`, {
          method: 'DELETE'
        });
        
        console.log(`✅ Deleted ${imageType} image for vendor: ${req.params.handle}`);
        
        res.json({ success: true, deleted: imageType });
      } else {
        res.json({ success: true, message: 'Image not found' });
      }
    } catch (error) {
      console.error('Error deleting store image:', error);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

// =============================================================================
// SUBSCRIBER COLLECTION — POST /api/vendors/:vendor/subscribe
// =============================================================================

/**
 * POST /api/vendors/:vendor/subscribe
 * Collects an email subscriber and stores them in Azure SQL.
 * No vendor auth required (public-facing form endpoint).
 */
app.post('/api/vendors/:vendor/subscribe', async (req, res) => {
  const { vendor } = req.params;
  const { email, firstName, lastName, phone, smsOptin, source } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required.' });
  }

  const vendorHandle = vendor.toLowerCase().trim();

  try {
    const pool = await getPool();

    // 1. Upsert contact
    await pool.request()
      .input('email',        sql.NVarChar, email.toLowerCase().trim())
      .input('firstName',    sql.NVarChar, firstName  || null)
      .input('lastName',     sql.NVarChar, lastName   || null)
      .input('phone',        sql.NVarChar, phone      || null)
      .input('smsStatus',    sql.NVarChar, smsOptin ? 'subscribed' : 'not_subscribed')
      .input('vendorHandle', sql.NVarChar, vendorHandle)
      .query(`
        MERGE contacts AS target
        USING (SELECT @email AS email) AS src ON target.email = src.email
        WHEN MATCHED THEN
          UPDATE SET
            first_name    = COALESCE(@firstName, target.first_name),
            last_name     = COALESCE(@lastName,  target.last_name),
            phone         = COALESCE(@phone,     target.phone),
            sms_status    = CASE WHEN @smsStatus = 'subscribed' THEN 'subscribed' ELSE target.sms_status END,
            updated_at    = GETUTCDATE()
        WHEN NOT MATCHED THEN
          INSERT (email, first_name, last_name, phone, sms_status, vendor_handle, global_status, created_at, updated_at)
          VALUES (@email, @firstName, @lastName, @phone, @smsStatus, @vendorHandle, 'subscribed', GETUTCDATE(), GETUTCDATE());
      `);

    // 2. Get contact_id
    const contactResult = await pool.request()
      .input('email', sql.NVarChar, email.toLowerCase().trim())
      .query(`SELECT contact_id FROM contacts WHERE email = @email`);

    const contactId = contactResult.recordset[0]?.contact_id;
    if (!contactId) throw new Error('Contact not found after upsert.');

    // 3. Upsert vendor_subscriptions
    await pool.request()
      .input('contactId',   sql.BigInt,   contactId)
      .input('vendorTag',   sql.NVarChar, vendorHandle)
      .input('source',      sql.NVarChar, source || 'form')
      .query(`
        MERGE vendor_subscriptions AS target
        USING (SELECT @contactId AS contact_id, @vendorTag AS vendor_handle) AS src
          ON target.contact_id = src.contact_id AND target.vendor_handle = src.vendor_handle
        WHEN MATCHED THEN
          UPDATE SET
            vendor_status  = 'subscribed',
            updated_at     = GETUTCDATE()
        WHEN NOT MATCHED THEN
          INSERT (vendor_handle, contact_id, vendor_status, source, subscribed_at, created_at, updated_at)
          VALUES (@vendorTag, @contactId, 'subscribed', @source, GETUTCDATE(), GETUTCDATE(), GETUTCDATE());
      `);

    console.log(`[Subscribe] ${email} → ${vendorHandle}`);
    return res.json({ success: true });

  } catch (err) {
    console.error('[Subscribe] error:', err.message);
    return res.status(500).json({ error: 'Subscription failed: ' + err.message });
  }
});

// =============================================================================
// ROUTES: EMAIL CAMPAIGNS (AMAZON SES + AZURE SQL)
// =============================================================================

/**
 * GET /api/vendors/:handle/subscribers/count
 * Returns subscriber count from Azure SQL for a given audience segment.
 * Query param: ?audience=all|newsletter|sms_opted_in|recent_buyers
 */
app.get('/api/vendors/:handle/subscribers/count',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { handle } = req.params;
      const { audience = 'all' } = req.query;

      const pool = await getPool();

      // 🔹 Build dynamic audience query
      const { query } = buildAudienceQuery(audience, handle);

      const countQuery = `
        SELECT COUNT(DISTINCT c.contact_id) AS cnt
        ${query}
      `;

      const result = await pool.request()
        .input('vendorHandle', sql.NVarChar, handle)
        .query(countQuery);

      const count = result.recordset[0]?.cnt || 0;

      return res.json({ count });

    } catch (err) {
      console.error('[SQL] subscriber count error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  }
);

// =============================================================================
// ROUTES: EMAIL SEGMENTS
// =============================================================================

/**
 * GET /api/vendors/:handle/email/segments
 *
 * Returns audience segments that have at least 1 eligible subscriber.
 * Empty segments are omitted so the frontend dropdown never shows an option
 * that would produce a "0 recipients" send error.
 *
 * Each segment is counted using the same buildAudienceQuery() used by
 * /subscribers/count and /email/send, so counts are always consistent.
 *
 * Response: [{ key: 'all', label: 'All Subscribers', count: 42 }, ...]
 */
app.get('/api/vendors/:handle/email/segments',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;

    const SEGMENT_DEFINITIONS = [
      { key: 'all',           label: 'All Subscribers'        },
      { key: 'newsletter',    label: 'Newsletter Subscribers'  },
      { key: 'sms_opted_in',  label: 'SMS Opted-In'           },
      { key: 'recent_buyers', label: 'Recent Buyers (30d)'    },
    ];

    try {
      const pool = await getPool();

      // Count all segments in parallel
      const counted = await Promise.all(
        SEGMENT_DEFINITIONS.map(async (seg) => {
          try {
            const { query } = buildAudienceQuery(seg.key, handle);
const result = await pool.request()
  .input('vendorHandle', sql.NVarChar, handle)
  .query(`
    SELECT COUNT(DISTINCT c.contact_id) AS cnt
    ${query}
  `);
            return { ...seg, count: result.recordset[0]?.cnt ?? 0 };
          } catch (segErr) {
            // If one segment fails (e.g. missing column), skip it rather than
            // blowing up the entire response.
            console.warn(`[Segments] count failed for "${seg.key}":`, segErr.message);
            return { ...seg, count: 0 };
          }
        })
      );

      // Only return segments with at least one eligible subscriber
      const nonEmpty = counted.filter(s => s.count > 0);

      console.log(`[Segments] ${handle}: ${nonEmpty.map(s => `${s.key}=${s.count}`).join(', ')}`);
      return res.json(nonEmpty);

    } catch (err) {
      console.error('[Segments] error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  }
);

/**
 * POST /api/vendors/:handle/email/send
 * Sends an email campaign via Amazon SES to all contacts in the chosen
 * audience segment fetched from Azure SQL. Suppression-safe, one message
 * per recipient, HMAC-signed unsubscribe links, fully logged.
 *
 * Body:
 *   subject      {string}  Subject line (required)
 *   previewText  {string}  Inbox preview snippet
 *   htmlContent  {string}  Full rendered HTML from the email builder
 *   audience     {string}  all|newsletter|sms_opted_in|recent_buyers
 */
app.post('/api/vendors/:handle/email/send',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle }  = req.params;
    const { subject, previewText, htmlContent, audience = 'all' } = req.body;
    const vendorDisplayName = VENDOR_MAP[handle] || handle;
    const fromEmail = process.env.SES_FROM_EMAIL || 'hello@halfcourse.com';
    const fromName  = `${vendorDisplayName} @ HalfCourse`;
    const appUrl    = process.env.APP_URL || 'https://halfcourse.com';

    // ── Validation ────────────────────────────────────────────────────────
    if (!subject?.trim())
      return res.status(400).json({ error: 'Subject line is required.' });
    if (!htmlContent || htmlContent.length < 100)
      return res.status(400).json({ error: 'Email content is missing or too short.' });

    try {
      // ── 1. Fetch recipient list from Azure SQL ─────────────────────────
      const pool  = await getPool();
      const { query } = buildAudienceQuery(audience, handle);
      const result = await pool.request()
        .input('vendorHandle', sql.NVarChar, handle)
        .query(`
  SELECT DISTINCT c.contact_id, c.email, c.first_name
  ${query}
`);

      const recipients = result.recordset;
      if (recipients.length === 0) {
        return res.status(400).json({ error: 'No eligible subscribers found for this audience.' });
      }

      console.log(`[SES] Sending "${subject}" to ${recipients.length} recipients for ${handle}/${audience}`);

      // ── 2. Send one SES message per recipient ──────────────────────────
      const campaignId = `${handle}-${Date.now()}`;
      let sent = 0, failed = 0;

      for (const contact of recipients) {
        try {
          const token      = signUnsubscribeToken(contact.email);
          const unsubUrl   = `${appUrl}/api/unsubscribe?token=${token}&vendor=${encodeURIComponent(handle)}`;
          const listUnsub  = `<${unsubUrl}>, <mailto:unsubscribe@halfcourse.com?subject=unsubscribe>`;

          // Personalise HTML — inject first name if present, inject unsubscribe link
          const personalised = htmlContent
            .replace(/{{\s*first_name\s*}}/gi, contact.first_name || 'there')
            .replace(/UNSUBSCRIBE_LINK/g, unsubUrl);

          const plainText = stripHtmlToText(personalised)
            + `\n\nTo unsubscribe: ${unsubUrl}`;

          // ── Send and capture the SES MessageId ────────────────────────
          const sesResponse = await ses.send(new SendEmailCommand({
            Source: `${fromName} <${fromEmail}>`,
            Destination: { ToAddresses: [contact.email] },
            Message: {
              Subject: { Data: subject.trim() },
              Body: {
                Html: { Data: personalised },
                Text: { Data: plainText },
              },
            },
            ConfigurationSetName: process.env.SES_CONFIG_SET || undefined,
            Headers: [
              { Name: 'List-Unsubscribe',      Value: listUnsub },
              { Name: 'List-Unsubscribe-Post',  Value: 'List-Unsubscribe=One-Click' },
              { Name: 'X-Campaign-ID',          Value: campaignId },
              { Name: 'X-Vendor-Handle',        Value: handle },
            ],
          }));

          const sesMessageId = sesResponse.MessageId;

          // ── Write per-recipient row with MessageId ─────────────────────
          await pool.request()
            .input('campaign_id',    sql.NVarChar,  campaignId)
            .input('contact_id',     sql.Int, contact.contact_id)
            .input('email',          sql.NVarChar,  contact.email)
            .input('ses_message_id', sql.NVarChar,  sesMessageId)
            .input('status',         sql.NVarChar,  'sent')
            .input('sent_at',        sql.DateTime2, new Date())
            .query(`
              INSERT INTO email_send_recipients
                (campaign_id, contact_id, email, ses_message_id, status, sent_at)
              VALUES
                (@campaign_id, @contact_id, @email, @ses_message_id, @status, @sent_at)
            `);

          console.log(`[SES] Sent to ${contact.email} — MessageId: ${sesMessageId}`);
          sent++;
        } catch (sendErr) {
          console.error(`[SES] failed to send to ${contact.email}:`, sendErr.message);
          failed++;
        }
      }

      // ── 3. Log campaign to Azure SQL ───────────────────────────────────
      try {
        await pool.request()
          .input('campaign_id',    sql.NVarChar,  campaignId)
          .input('vendor_handle',  sql.NVarChar,  handle)
          .input('audience',       sql.NVarChar,  audience)
          .input('subject',        sql.NVarChar,  subject.trim())
          .input('sent_count',     sql.Int,       sent)
          .input('failed_count',   sql.Int,       failed)
          .input('sent_at',        sql.DateTime2, new Date())
          .query(`
            INSERT INTO email_send_log
              (campaign_id, vendor_handle, audience, subject, sent_count, failed_count, sent_at)
            VALUES
              (@campaign_id, @vendor_handle, @audience, @subject, @sent_count, @failed_count, @sent_at)
          `);
      } catch (logErr) {
        console.error('[SQL] campaign log error:', logErr.message);
        // Non-fatal — don't fail the response over a logging issue
      }

      console.log(`[SES] Campaign ${campaignId} complete: ${sent} sent, ${failed} failed`);
      return res.json({
        success: true,
        campaignId,
        sent,
        failed,
        message: `Campaign sent to ${sent} subscriber${sent !== 1 ? 's' : ''}` + (failed ? ` (${failed} failed)` : '') + '.',
      });

    } catch (err) {
      console.error('[Email] send error:', err.message);
      return res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
  }
);

// =============================================================================
// AMAZON SES — TEST SEND
// =============================================================================

/**
 * POST /api/vendors/:vendor/email/test
 * Sends a single test email via SES. Requires vendor auth.
 */
app.post("/api/vendors/:vendor/email/test",
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { to, subject, htmlContent } = req.body;
      const handle = req.params.vendor;
      const vendorDisplayName = VENDOR_MAP[handle] || handle;
      const fromEmail = process.env.SES_FROM_EMAIL || "hello@halfcourse.com";

      if (!to || !subject || !htmlContent) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const sesResponse = await ses.send(new SendEmailCommand({
        Source: `${vendorDisplayName} @ HalfCourse <${fromEmail}>`,
        Destination: { ToAddresses: [to] },
        Message: {
          Subject: { Data: subject },
          Body: {
            Html: { Data: htmlContent },
            Text: { Data: stripHtmlToText(htmlContent) },
          },
        },
        ConfigurationSetName: process.env.SES_CONFIG_SET || undefined,
      }));

      console.log(`[SES] Test email sent to ${to} for vendor ${handle} — MessageId: ${sesResponse.MessageId}`);
      return res.json({ success: true, messageId: sesResponse.MessageId });
    } catch (err) {
      console.error("SES test send error:", err);
      return res.status(500).json({ error: "Test send failed: " + err.message });
    }
  }
);


// =============================================================================
// UNSUBSCRIBE ENDPOINT
// =============================================================================

/**
 * GET /api/unsubscribe?token=...&vendor=...
 * One-click unsubscribe. Validates HMAC, inserts into suppressions.
 */
app.get("/api/unsubscribe", async (req, res) => {
  const { token, vendor } = req.query;
  const email = verifyUnsubscribeToken(token);
  if (!email) return res.status(400).send("Invalid or expired unsubscribe link.");
  try {
    const pool = await getPool();
    await pool.request()
      .input("email",        sql.NVarChar, email)
      .input("vendorHandle", sql.NVarChar, vendor || null)
      .input("reason",       sql.NVarChar, "unsubscribe")
      .query(`
        IF NOT EXISTS (SELECT 1 FROM suppressions WHERE email = @email AND (vendor_handle = @vendorHandle OR vendor_handle IS NULL))
          INSERT INTO suppressions (email, vendor_handle, reason, created_at)
          VALUES (@email, @vendorHandle, @reason, GETUTCDATE())
      `);
    await pool.request()
      .input("email",        sql.NVarChar, email)
      .input("vendorHandle", sql.NVarChar, vendor || null)
      .query(`
        UPDATE vendor_subscriptions
        SET vendor_status = 'unsubscribed', unsubscribed_at = GETUTCDATE()
        WHERE contact_id = (
  SELECT contact_id FROM contacts WHERE email = @email
)
          AND (@vendorHandle IS NULL OR vendor_handle = @vendorHandle)
      `);
    console.log(`[Unsubscribe] ${email} unsubscribed from ${vendor || "all"}`);
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px;">
      <h2>You have been unsubscribed.</h2>
      <p>You will no longer receive emails from ${vendor ? vendor + " via " : ""}HalfCourse.</p>
    </body></html>`);
  } catch (err) {
    console.error("[Unsubscribe] error:", err.message);
    res.status(500).send("Something went wrong. Please try again.");
  }
});

/** POST /api/unsubscribe — RFC 8058 one-click unsubscribe for email clients */
app.post("/api/unsubscribe", express.urlencoded({ extended: false }), async (req, res) => {
  const token  = req.query.token  || req.body.token;
  const vendor = req.query.vendor || req.body.vendor;
  const email  = verifyUnsubscribeToken(token);
  if (!email) return res.status(400).json({ error: "Invalid token" });
  try {
    const pool = await getPool();
    await pool.request()
      .input("email",        sql.NVarChar, email)
      .input("vendorHandle", sql.NVarChar, vendor || null)
      .input("reason",       sql.NVarChar, "unsubscribe")
      .query(`
        IF NOT EXISTS (SELECT 1 FROM suppressions WHERE email = @email AND (vendor_handle = @vendorHandle OR vendor_handle IS NULL))
          INSERT INTO suppressions (email, vendor_handle, reason, created_at)
          VALUES (@email, @vendorHandle, @reason, GETUTCDATE())
      `);
    await pool.request()
      .input("email",        sql.NVarChar, email)
      .input("vendorHandle", sql.NVarChar, vendor || null)
      .query(`
        UPDATE vendor_subscriptions SET vendor_status = 'unsubscribed', unsubscribed_at = GETUTCDATE()
        WHERE contact_id = (
  SELECT contact_id FROM contacts WHERE email = @email
)
          AND (@vendorHandle IS NULL OR vendor_handle = @vendorHandle)
      `);
    res.json({ success: true });
  } catch (err) {
    console.error("[Unsubscribe POST] error:", err.message);
    res.status(500).json({ error: "Unsubscribe failed" });
  }
});

// =============================================================================
// SNS WEBHOOK — BOUNCE, COMPLAINT, DELIVERY, OPEN, CLICK
// =============================================================================

/**
 * POST /api/sns/bounce
 *
 * Receives SES event notifications via AWS SNS for the configured
 * Configuration Set. Handles:
 *
 *   Bounce (Permanent)  → suppresses email + sets recipient status = 'bounced'
 *   Bounce (Transient)  → logs only, does not suppress
 *   Complaint           → suppresses email + sets recipient status = 'complained'
 *   Delivery            → sets recipient status = 'delivered'
 *   Open                → sets recipient status = 'opened'
 *   Click               → sets recipient status = 'clicked'
 *
 * MessageId reconciliation: every event includes mail.messageId, which is
 * matched against email_send_recipients.ses_message_id to identify the exact
 * recipient row. This is the core of per-recipient deliverability tracking.
 *
 * Setup: In your SES Configuration Set, add an SNS destination for each
 * event type (Bounce, Complaint, Delivery, Open, Click) pointing at:
 *   POST https://<your-render-url>/api/sns/bounce
 */
app.post("/api/sns/bounce", express.json({ type: "*/*" }), async (req, res) => {
  try {
    let body = req.body;

    // SNS wraps the SES notification as a JSON string inside body.Message
    if (typeof body.Message === "string") {
      try { body = { ...body, Message: JSON.parse(body.Message) }; } catch (_) {}
    }

    // ── SNS subscription confirmation (one-time handshake) ──────────────────
    if (body.Type === "SubscriptionConfirmation" && body.SubscribeURL) {
      await fetch(body.SubscribeURL);
      console.log("[SNS] Subscription confirmed");
      return res.sendStatus(200);
    }

    const msg       = body.Message || body;
    const notifType = msg.notificationType;
    const messageId = msg.mail?.messageId || null;
    const pool      = await getPool();

    // ── Bounce ───────────────────────────────────────────────────────────────
    if (notifType === "Bounce") {
      const bounceType = msg.bounce?.bounceType;

      for (const r of msg.bounce?.bouncedRecipients || []) {
        if (bounceType === "Permanent") {
          // Hard bounce — suppress permanently
          await pool.request()
            .input("email",  sql.NVarChar, r.emailAddress)
            .input("reason", sql.NVarChar, "hard_bounce")
            .query(`
              IF NOT EXISTS (SELECT 1 FROM suppressions WHERE email = @email)
                INSERT INTO suppressions (email, vendor_handle, reason, created_at)
                VALUES (@email, NULL, @reason, GETUTCDATE())
            `);
          console.log(`[SNS] Hard bounce suppressed: ${r.emailAddress}`);
        } else {
          // Soft bounce — log only, do not suppress
          console.log(`[SNS] Soft bounce (${msg.bounce?.bounceSubType}) for: ${r.emailAddress}`);
        }
      }

      await updateRecipientStatus(pool, messageId, "bounced");
    }

    // ── Complaint ────────────────────────────────────────────────────────────
    else if (notifType === "Complaint") {
      for (const r of msg.complaint?.complainedRecipients || []) {
        await pool.request()
          .input("email",  sql.NVarChar, r.emailAddress)
          .input("reason", sql.NVarChar, "complaint")
          .query(`
            IF NOT EXISTS (SELECT 1 FROM suppressions WHERE email = @email)
              INSERT INTO suppressions (email, vendor_handle, reason, created_at)
              VALUES (@email, NULL, @reason, GETUTCDATE())
          `);
        console.log(`[SNS] Complaint suppressed: ${r.emailAddress}`);
      }

      await updateRecipientStatus(pool, messageId, "complained");
    }

    // ── Delivery ─────────────────────────────────────────────────────────────
    else if (notifType === "Delivery") {
      await updateRecipientStatus(pool, messageId, "delivered");
      console.log(`[SNS] Delivered — MessageId: ${messageId}`);
    }

    // ── Open ─────────────────────────────────────────────────────────────────
    else if (notifType === "Open") {
      await updateRecipientStatus(pool, messageId, "opened");
      console.log(`[SNS] Opened — MessageId: ${messageId}`);
    }

    // ── Click ────────────────────────────────────────────────────────────────
    else if (notifType === "Click") {
      await updateRecipientStatus(pool, messageId, "clicked");
      console.log(`[SNS] Clicked — MessageId: ${messageId}, URL: ${msg.click?.link}`);
    }

    else {
      console.log(`[SNS] Unhandled event type: ${notifType}`);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("[SNS] webhook error:", err.message);
    res.sendStatus(500);
  }
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    message: `The endpoint ${req.method} ${req.path} does not exist`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
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
  console.log(`SES Region:        ${process.env.AWS_REGION || '(not set)'}`);
  console.log(`SES From Email:    ${process.env.SES_FROM_EMAIL || '(not set)'}`);
  console.log(`SES Config Set:    ${process.env.SES_CONFIG_SET || '(not set)'}`);
  console.log(`Azure SQL Server:  ${process.env.SQL_SERVER || '(not set)'}`);
  console.log(`Azure SQL DB:      ${process.env.SQL_DATABASE || '(not set)'}`);
  console.log(`Configured vendors: ${Object.keys(VENDOR_MAP).join(', ')}`);
  console.log('');
});
