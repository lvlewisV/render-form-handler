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
 * - Email campaign sending via Omnisend
 * - Email test send via Omnisend (NEW)
 * - Subscriber count from Omnisend
 * 
 * Deploy to: Render.com
 * Repository: github.com/lvlewisV/hc-vendor-api-oauth.js
 */

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

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
const TOKEN_FILE = process.env.TOKEN_FILE || '/tmp/shopify_tokens.json';

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
// OMNISEND API HELPER
// =============================================================================

/**
 * Returns the Omnisend tag used to segment contacts for a given vendor.
 * Contacts must be tagged with this value at subscribe time (e.g. "liandros").
 */
function getVendorTag(handle) {
  return handle.toLowerCase().replace(/\s+/g, '-');
}

/**
 * Strips HTML tags from a string to produce a plain-text email fallback.
 * Omnisend requires both HTML and plain-text content.
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
    omnisendConfigured: !!process.env.OMNISEND_API_KEY,
    store: SHOPIFY_STORE,
    configuredVendors: Object.keys(VENDOR_MAP)
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
    
    // Store the access token
    shopifyAccessTokens[SHOPIFY_STORE] = tokenData.access_token;
    
    // Persist to file
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
      
      // Create temporary product to get a Shopify CDN URL
      const tempProduct = await shopifyFetch('/products.json', {
        method: 'POST',
        body: JSON.stringify({
          product: {
            title: `_temp_upload_${Date.now()}`,
            status: 'draft',
            images: [{
              attachment: imageData,
              alt: alt || imageType
            }]
          }
        })
      });
      
      if (!tempProduct.product || !tempProduct.product.images || tempProduct.product.images.length === 0) {
        throw new Error('Failed to upload image');
      }
      
      const uploadedImageUrl = tempProduct.product.images[0].src;
      
      // Delete the temporary product
      await shopifyFetch(`/products/${tempProduct.product.id}.json`, {
        method: 'DELETE'
      });
      
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
// ROUTES: EMAIL CAMPAIGNS (OMNISEND)
// =============================================================================

/**
 * GET /api/vendors/:handle/subscribers/count
 * Returns the number of subscribed contacts tagged with this vendor's handle.
 * Used by the email builder to show "X subscribers will receive this."
 *
 * Requires env: OMNISEND_API_KEY
 */
app.get('/api/vendors/:handle/subscribers/count',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    const tag = getVendorTag(handle);
    const apiKey = process.env.OMNISEND_API_KEY;

    if (!apiKey) {
      return res.json({ count: 0, note: 'OMNISEND_API_KEY not configured' });
    }

    try {
      const url = `https://api.omnisend.com/v3/contacts?tags=${encodeURIComponent(tag)}&status=subscribed&limit=1`;

      const response = await fetch(url, {
        headers: {
          'X-API-KEY': apiKey,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errText = await response.text();
        console.error('[Omnisend] subscriber count error:', errText);
        return res.json({ count: 0 });
      }

      const data = await response.json();
      const count = data.paging?.totalCount ?? (data.contacts?.length ?? 0);

      console.log(`[Omnisend] ${handle} subscriber count: ${count}`);
      return res.json({ count });
    } catch (err) {
      console.error('[Omnisend] subscriber count fetch failed:', err.message);
      return res.json({ count: 0 });
    }
  }
);

/**
 * POST /api/vendors/:handle/email/send
 * Creates and schedules an email campaign via Omnisend.
 * Targets contacts tagged with the vendor's handle.
 *
 * Body:
 *   subject      {string}  Subject line (required)
 *   previewText  {string}  Inbox preview snippet
 *   htmlContent  {string}  Full rendered HTML from the email builder
 *
 * Requires env: OMNISEND_API_KEY, OMNISEND_FROM_EMAIL
 */
app.post('/api/vendors/:handle/email/send',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    const { subject, previewText, htmlContent } = req.body;
    const tag = getVendorTag(handle);
    const apiKey = process.env.OMNISEND_API_KEY;

    // ── Validation ────────────────────────────────────────────
    if (!subject || !subject.trim()) {
      return res.status(400).json({ error: 'Subject line is required.' });
    }
    if (!htmlContent || htmlContent.length < 100) {
      return res.status(400).json({ error: 'Email content is missing or too short.' });
    }
    if (!apiKey) {
      return res.status(500).json({
        error: 'OMNISEND_API_KEY is not configured. Add it to your Render environment variables.',
      });
    }

    // ── Sender identity ───────────────────────────────────────
    const vendorDisplayName = VENDOR_MAP[handle] || handle;
    const fromName  = `${vendorDisplayName} @ HalfCourse`;
    const fromEmail = process.env.OMNISEND_FROM_EMAIL || 'hello@halfcourse.com';

    try {
      // ── Step 1: Create campaign ───────────────────────────────
      const campaignPayload = {
        name: `${vendorDisplayName} — ${subject.substring(0, 50)} (${new Date().toLocaleDateString('en-US')})`,
        type: 'regular',
        options: {
          trackLinks: true,
        },
        sendingSettings: {
          contactsFilter: {
            tags: [tag],
            status: 'subscribed',
          },
          fromName:     fromName,
          fromEmail:    fromEmail,
          replyToEmail: process.env.OMNISEND_REPLY_EMAIL || fromEmail,
        },
        content: {
          subject:          subject.trim(),
          preheader:        previewText ? previewText.trim() : '',
          htmlContent:      htmlContent,
          plainTextContent: stripHtmlToText(htmlContent),
        },
      };

      const createRes = await fetch('https://api.omnisend.com/v3/campaigns', {
        method: 'POST',
        headers: {
          'X-API-KEY': apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(campaignPayload),
      });

      const createText = await createRes.text();
      let createData;
      try { createData = JSON.parse(createText); } catch (_) { createData = {}; }

      if (!createRes.ok) {
        console.error('[Omnisend] create campaign failed:', createText);
        const omniError = createData?.error?.message
          || createData?.message
          || `Omnisend returned status ${createRes.status}`;
        return res.status(502).json({ error: 'Campaign creation failed: ' + omniError });
      }

      const campaignId = createData.campaignID || createData.id;
      if (!campaignId) {
        console.error('[Omnisend] no campaignID in response:', createData);
        return res.status(502).json({ error: 'Omnisend did not return a campaign ID.' });
      }

      console.log(`[Email] Campaign created: ${campaignId} for vendor ${handle}`);

      // ── Step 2: Schedule for immediate send ───────────────────
      // scheduledFor set 60 seconds ahead to give Omnisend time to process
      const sendAt = new Date(Date.now() + 60000).toISOString();

      const scheduleRes = await fetch(
        `https://api.omnisend.com/v3/campaigns/${campaignId}/actions/start`,
        {
          method: 'POST',
          headers: {
            'X-API-KEY': apiKey,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ scheduledFor: sendAt }),
        }
      );

      const scheduleText = await scheduleRes.text();
      let scheduleData;
      try { scheduleData = JSON.parse(scheduleText); } catch (_) { scheduleData = {}; }

      if (!scheduleRes.ok) {
        console.error('[Omnisend] schedule campaign failed:', scheduleText);
        const omniError = scheduleData?.error?.message
          || scheduleData?.message
          || `Status ${scheduleRes.status}`;
        // Campaign created but not scheduled — return partial info
        return res.status(502).json({
          error: 'Campaign was created but could not be scheduled: ' + omniError,
          campaignId,
          hint: 'You can manually start it from your Omnisend dashboard.',
        });
      }

      console.log(`[Email] Campaign scheduled: ${campaignId} at ${sendAt}`);

      return res.json({
        success: true,
        campaignId,
        scheduledFor: sendAt,
        message: 'Campaign created and scheduled successfully.',
      });

    } catch (err) {
      console.error('[Email] send error:', err.message);
      return res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
  }
);

/**
 * POST /api/vendors/:handle/email/test
 * Sends a test email to a single address via Omnisend.
 * Upserts a temporary contact with a unique tag, fires a campaign to only
 * that contact, then cleans up the temp tag.
 *
 * Body:
 *   to           {string}  Recipient email address (required)
 *   subject      {string}  Subject line — frontend prepends [TEST] (required)
 *   previewText  {string}  Inbox preview snippet
 *   htmlContent  {string}  Full rendered HTML from the email builder
 *
 * Requires env: OMNISEND_API_KEY, OMNISEND_FROM_EMAIL
 */
app.post('/api/vendors/:handle/email/test',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    const { handle } = req.params;
    const { to, subject, previewText, htmlContent } = req.body;
    const apiKey = process.env.OMNISEND_API_KEY;

    // ── Validation ────────────────────────────────────────────
    if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
      return res.status(400).json({ error: 'A valid recipient email address is required.' });
    }
    if (!subject || !subject.trim()) {
      return res.status(400).json({ error: 'Subject line is required.' });
    }
    if (!htmlContent || htmlContent.length < 50) {
      return res.status(400).json({ error: 'Email content is missing or too short.' });
    }
    if (!apiKey) {
      return res.status(500).json({ error: 'OMNISEND_API_KEY is not configured.' });
    }

    const vendorDisplayName = VENDOR_MAP[handle] || handle;
    const fromName  = `${vendorDisplayName} @ HalfCourse`;
    const fromEmail = process.env.OMNISEND_FROM_EMAIL || 'hello@halfcourse.com';

    // Unique temp tag scoped to this vendor + timestamp — cleaned up after send
    const testTag = `_test_${handle}_${Date.now()}`;

    try {
      // ── Step 1: Upsert the test recipient with the temp tag ───
      const upsertRes = await fetch('https://api.omnisend.com/v3/contacts', {
        method: 'POST',
        headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: to,
          status: 'subscribed',
          statusDate: new Date().toISOString(),
          tags: [testTag],
          sendWelcomeEmail: false,
        }),
      });

      if (!upsertRes.ok) {
        const errText = await upsertRes.text();
        console.error('[Email Test] Contact upsert failed:', errText);
        return res.status(502).json({ error: 'Failed to register test recipient with Omnisend.' });
      }

      console.log(`[Email Test] Upserted contact ${to} with tag ${testTag}`);

      // ── Step 2: Create a campaign targeting only the temp tag ─
      const campaignPayload = {
        name: `[TEST] ${vendorDisplayName} — ${subject.substring(0, 40)} (${new Date().toLocaleDateString('en-US')})`,
        type: 'regular',
        options: { trackLinks: false },
        sendingSettings: {
          contactsFilter: {
            tags: [testTag],
            status: 'subscribed',
          },
          fromName,
          fromEmail,
          replyToEmail: process.env.OMNISEND_REPLY_EMAIL || fromEmail,
        },
        content: {
          subject:          subject.trim(),
          preheader:        previewText ? previewText.trim() : '',
          htmlContent:      htmlContent,
          plainTextContent: stripHtmlToText(htmlContent),
        },
      };

      const createRes = await fetch('https://api.omnisend.com/v3/campaigns', {
        method: 'POST',
        headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify(campaignPayload),
      });

      const createText = await createRes.text();
      let createData;
      try { createData = JSON.parse(createText); } catch (_) { createData = {}; }

      if (!createRes.ok) {
        console.error('[Email Test] Campaign creation failed:', createText);
        const omniError = createData?.error?.message || createData?.message || `Status ${createRes.status}`;
        return res.status(502).json({ error: 'Test campaign creation failed: ' + omniError });
      }

      const campaignId = createData.campaignID || createData.id;
      if (!campaignId) {
        return res.status(502).json({ error: 'Omnisend did not return a campaign ID.' });
      }

      console.log(`[Email Test] Campaign created: ${campaignId}`);

      // ── Step 3: Schedule immediate send (60s buffer) ──────────
      const sendAt = new Date(Date.now() + 60000).toISOString();

      const scheduleRes = await fetch(
        `https://api.omnisend.com/v3/campaigns/${campaignId}/actions/start`,
        {
          method: 'POST',
          headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ scheduledFor: sendAt }),
        }
      );

      if (!scheduleRes.ok) {
        const scheduleText = await scheduleRes.text();
        console.error('[Email Test] Schedule failed:', scheduleText);
        return res.status(502).json({
          error: 'Test campaign created but could not be scheduled.',
          campaignId,
          hint: 'You can manually trigger it from your Omnisend dashboard.',
        });
      }

      console.log(`[Email Test] Sent to ${to} via campaign ${campaignId}`);

      // ── Step 4: Clean up temp tag (best-effort, non-fatal) ────
      try {
        const findRes = await fetch(
          `https://api.omnisend.com/v3/contacts?email=${encodeURIComponent(to)}`,
          { headers: { 'X-API-KEY': apiKey } }
        );

        if (findRes.ok) {
          const contactData = await findRes.json();
          const contact = contactData.contacts?.[0];
          if (contact?.contactID) {
            const updatedTags = (contact.tags || []).filter(t => t !== testTag);
            await fetch(`https://api.omnisend.com/v3/contacts/${contact.contactID}`, {
              method: 'PATCH',
              headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
              body: JSON.stringify({ tags: updatedTags }),
            });
            console.log(`[Email Test] Cleaned up temp tag from ${to}`);
          }
        }
      } catch (cleanupErr) {
        console.warn('[Email Test] Tag cleanup failed (non-fatal):', cleanupErr.message);
      }

      return res.json({
        success: true,
        campaignId,
        sentTo: to,
        scheduledFor: sendAt,
      });

    } catch (err) {
      console.error('[Email Test] Unexpected error:', err.message);
      return res.status(500).json({ error: 'Internal server error: ' + err.message });
    }
  }
);

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
  console.log(`Omnisend Configured: ${!!process.env.OMNISEND_API_KEY}`);
  console.log(`Configured vendors: ${Object.keys(VENDOR_MAP).join(', ')}`);
  console.log('');
});
