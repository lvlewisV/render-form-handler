/**
 * HalfCourse Vendor API Server
 * 
 * Complete backend for vendor product editing and store settings management.
 * Deployed on Render, connects to Shopify via OAuth.
 * 
 * Version: 2.1.0 (with Store Settings support)
 * 
 * Endpoints:
 * - GET  /                          → Home page with auth status
 * - GET  /health                    → Health check
 * - GET  /auth                      → Start OAuth flow
 * - GET  /auth/callback             → OAuth callback
 * - POST /api/vendor/login          → Vendor authentication
 * 
 * Product Endpoints:
 * - GET    /api/vendors/:handle/products      → List vendor's products
 * - POST   /api/vendors/:handle/products      → Create product
 * - PUT    /api/vendors/:handle/products/:id  → Update product
 * - DELETE /api/vendors/:handle/products/:id  → Delete product
 * - POST   /api/vendors/:handle/products/:id/images → Upload product image
 * - DELETE /api/vendors/:handle/products/:id/images/:imageId → Delete product image
 * 
 * Store Settings Endpoints:
 * - GET    /api/vendors/:handle/settings              → Get collection settings/metafields
 * - PUT    /api/vendors/:handle/settings              → Update collection metafields
 * - POST   /api/vendors/:handle/settings/images       → Upload setting image
 * - DELETE /api/vendors/:handle/settings/images/:type → Delete setting image
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CONFIGURATION =====

const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE = process.env.SHOPIFY_STORE; // Just 'half-course', not full URL
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL = process.env.APP_URL;
const API_VERSION = '2024-01';

// Vendor handle → Shopify vendor name mapping
const VENDOR_MAP = {
  'liandros': "Liandro's",
  // Add more vendors here:
  // 'marias-kitchen': "Maria's Kitchen",
  // 'bobs-bbq': "Bob's BBQ",
};

// In-memory token storage (use Redis/DB in production)
let shopifyAccessTokens = {};
let vendorSessions = {};

// ===== MIDDLEWARE =====

// CORS configuration
app.use(cors({
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
}));

// Handle preflight requests
app.options('*', cors());

// Parse JSON bodies
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// File upload handling
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 } // 20MB limit
});

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// ===== AUTH MIDDLEWARE =====

/**
 * Ensures Shopify OAuth is connected
 */
function requireShopifyAuth(req, res, next) {
  const shop = SHOPIFY_STORE;
  const token = shopifyAccessTokens[shop];
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Shopify not connected',
      message: 'Please visit the API root to connect Shopify OAuth'
    });
  }
  
  req.shop = shop;
  req.shopifyToken = token;
  next();
}

/**
 * Validates vendor session token
 */
function requireVendorAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }
  
  const token = authHeader.split(' ')[1];
  const session = vendorSessions[token];
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  // Check if token matches the requested vendor handle
  const requestedHandle = req.params.handle;
  if (requestedHandle && session.handle !== requestedHandle) {
    return res.status(403).json({ error: 'Access denied to this vendor' });
  }
  
  // Check token expiry (24 hours)
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    delete vendorSessions[token];
    return res.status(401).json({ error: 'Token expired' });
  }
  
  req.vendorHandle = session.handle;
  req.vendorName = session.vendorName;
  next();
}

/**
 * Validates that a product belongs to the authenticated vendor
 */
async function validateProductOwnership(req, res, next) {
  const { id } = req.params;
  const shop = req.shop;
  const token = req.shopifyToken;
  const vendorName = req.vendorName;
  
  if (!id) {
    return next();
  }
  
  try {
    const response = await fetch(
      `https://${shop}.myshopify.com/admin/api/${API_VERSION}/products/${id}.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    
    if (!response.ok) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    const data = await response.json();
    
    if (data.product.vendor !== vendorName) {
      return res.status(403).json({ error: 'You do not own this product' });
    }
    
    req.product = data.product;
    next();
  } catch (err) {
    console.error('Product ownership check error:', err);
    res.status(500).json({ error: 'Failed to verify product ownership' });
  }
}

// ===== HELPER FUNCTIONS =====

/**
 * Get vendor password from environment variables
 */
function getVendorPassword(handle) {
  const envKey = `VENDOR_${handle.toUpperCase().replace(/-/g, '_')}_PASSWORD`;
  return process.env[envKey] || process.env.DEFAULT_VENDOR_PASSWORD;
}

/**
 * Generate a secure random token
 */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Make a Shopify Admin API request
 */
async function shopifyAPI(shop, token, endpoint, options = {}) {
  const url = `https://${shop}.myshopify.com/admin/api/${API_VERSION}${endpoint}`;
  
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
    console.error(`Shopify API error: ${response.status} - ${errorText}`);
    throw new Error(`Shopify API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Make a Shopify GraphQL request
 */
async function shopifyGraphQL(shop, token, query, variables = {}) {
  const response = await fetch(
    `https://${shop}.myshopify.com/admin/api/${API_VERSION}/graphql.json`,
    {
      method: 'POST',
      headers: {
        'X-Shopify-Access-Token': token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query, variables })
    }
  );
  
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`Shopify GraphQL error: ${response.status} - ${errorText}`);
    throw new Error(`Shopify GraphQL error: ${response.status}`);
  }
  
  return response.json();
}

// ===== ROUTES: OAUTH & GENERAL =====

/**
 * Home page - shows connection status
 */
app.get('/', (req, res) => {
  const shop = SHOPIFY_STORE;
  const isConnected = !!shopifyAccessTokens[shop];
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>HalfCourse Vendor API</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        h1 { color: #ac380b; }
        .status { padding: 20px; border-radius: 8px; margin: 20px 0; }
        .connected { background: #d1fae5; color: #065f46; }
        .disconnected { background: #fee2e2; color: #991b1b; }
        a { color: #ac380b; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
      </style>
    </head>
    <body>
      <h1>🍽️ HalfCourse Vendor API</h1>
      
      <div class="status ${isConnected ? 'connected' : 'disconnected'}">
        ${isConnected 
          ? '✅ Connected to Shopify!' 
          : '❌ Not connected to Shopify'}
      </div>
      
      ${!isConnected ? `
        <p><a href="/auth">→ Click here to connect to Shopify</a></p>
      ` : `
        <p>The API is ready to receive requests from the vendor dashboard.</p>
        <h3>Available Endpoints:</h3>
        <ul>
          <li><code>GET /health</code> - Health check</li>
          <li><code>POST /api/vendor/login</code> - Vendor login</li>
          <li><code>GET /api/vendors/:handle/products</code> - List products</li>
          <li><code>GET /api/vendors/:handle/settings</code> - Get store settings</li>
        </ul>
      `}
      
      <hr>
      <p><small>Store: ${shop} | API Version: ${API_VERSION}</small></p>
    </body>
    </html>
  `);
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  const shop = SHOPIFY_STORE;
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    shopifyConnected: !!shopifyAccessTokens[shop],
    store: shop,
    apiVersion: API_VERSION,
    vendorCount: Object.keys(VENDOR_MAP).length,
    activeVendorSessions: Object.keys(vendorSessions).length
  });
});

/**
 * Start OAuth flow
 */
app.get('/auth', (req, res) => {
  const shop = SHOPIFY_STORE;
  const redirectUri = `${APP_URL}/auth/callback`;
  const nonce = crypto.randomBytes(16).toString('hex');
  
  // Store nonce for validation (in production, use session/redis)
  app.locals.oauthNonce = nonce;
  
  const authUrl = `https://${shop}.myshopify.com/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_CLIENT_ID}&` +
    `scope=${SHOPIFY_SCOPES}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `state=${nonce}`;
  
  console.log('Redirecting to Shopify OAuth:', authUrl);
  res.redirect(authUrl);
});

/**
 * OAuth callback
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, shop: shopParam } = req.query;
  const shop = SHOPIFY_STORE;
  
  // Validate state/nonce
  if (state !== app.locals.oauthNonce) {
    console.error('OAuth state mismatch');
    return res.status(400).send('Invalid state parameter');
  }
  
  try {
    // Exchange code for access token
    const tokenResponse = await fetch(
      `https://${shop}.myshopify.com/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: SHOPIFY_CLIENT_ID,
          client_secret: SHOPIFY_CLIENT_SECRET,
          code
        })
      }
    );
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);
      throw new Error('Failed to exchange code for token');
    }
    
    const tokenData = await tokenResponse.json();
    shopifyAccessTokens[shop] = tokenData.access_token;
    
    console.log('✅ OAuth successful for shop:', shop);
    res.redirect('/');
    
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send(`OAuth error: ${err.message}`);
  }
});

// ===== ROUTES: VENDOR AUTH =====

/**
 * Vendor login
 */
app.post('/api/vendor/login', (req, res) => {
  const { handle, password } = req.body;
  
  if (!handle || !password) {
    return res.status(400).json({ error: 'Handle and password required' });
  }
  
  // Check if vendor exists
  const vendorName = VENDOR_MAP[handle];
  if (!vendorName) {
    return res.status(404).json({ error: 'Vendor not found' });
  }
  
  // Validate password
  const correctPassword = getVendorPassword(handle);
  if (password !== correctPassword) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  // Generate session token
  const token = generateToken();
  vendorSessions[token] = {
    handle,
    vendorName,
    createdAt: Date.now()
  };
  
  console.log(`✅ Vendor logged in: ${handle} (${vendorName})`);
  
  res.json({
    success: true,
    token,
    vendor: {
      handle,
      name: vendorName
    }
  });
});

// ===== ROUTES: PRODUCTS =====

/**
 * List vendor's products
 */
app.get('/api/vendors/:handle/products', 
  requireShopifyAuth, 
  requireVendorAuth, 
  async (req, res) => {
    try {
      const shop = req.shop;
      const token = req.shopifyToken;
      const vendorName = req.vendorName;
      
      // Fetch all products and filter by vendor
      const data = await shopifyAPI(shop, token, '/products.json?limit=250');
      
      const vendorProducts = data.products.filter(p => p.vendor === vendorName);
      
      // Format products for frontend
      const formattedProducts = vendorProducts.map(p => ({
        id: p.id,
        title: p.title,
        body_html: p.body_html,
        vendor: p.vendor,
        status: p.status,
        handle: p.handle,
        images: p.images,
        variants: p.variants.map(v => ({
          id: v.id,
          price: v.price,
          compare_at_price: v.compare_at_price,
          inventory_quantity: v.inventory_quantity
        })),
        metafields: p.metafields || []
      }));
      
      res.json({ products: formattedProducts });
      
    } catch (err) {
      console.error('List products error:', err);
      res.status(500).json({ error: 'Failed to fetch products' });
    }
  }
);

/**
 * Create new product
 */
app.post('/api/vendors/:handle/products',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const shop = req.shop;
      const token = req.shopifyToken;
      const vendorName = req.vendorName;
      const { title, body_html, price, compare_at_price, status, metafields, images } = req.body;
      
      // Create product
      const productData = {
        product: {
          title,
          body_html,
          vendor: vendorName,
          status: status || 'draft',
          variants: [{
            price: price || '0.00',
            compare_at_price: compare_at_price || null
          }]
        }
      };
      
      // Add images if provided
      if (images && images.length > 0) {
        productData.product.images = images.map(img => ({
          attachment: img.attachment,
          alt: img.alt || title
        }));
      }
      
      const data = await shopifyAPI(shop, token, '/products.json', {
        method: 'POST',
        body: JSON.stringify(productData)
      });
      
      const productId = data.product.id;
      
      // Add metafields if provided
      if (metafields && metafields.length > 0) {
        for (const mf of metafields) {
          if (mf.value) {
            await shopifyAPI(shop, token, `/products/${productId}/metafields.json`, {
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
        }
      }
      
      console.log(`✅ Product created: ${title} (ID: ${productId})`);
      res.json({ success: true, product: data.product });
      
    } catch (err) {
      console.error('Create product error:', err);
      res.status(500).json({ error: 'Failed to create product' });
    }
  }
);

/**
 * Update product
 */
app.put('/api/vendors/:handle/products/:id',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const { id } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      const { title, body_html, price, compare_at_price, status, metafields } = req.body;
      
      // Build update payload
      const updateData = {
        product: { id }
      };
      
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
      
      // Update product
      const data = await shopifyAPI(shop, token, `/products/${id}.json`, {
        method: 'PUT',
        body: JSON.stringify(updateData)
      });
      
      // Update metafields if provided
      if (metafields && metafields.length > 0) {
        for (const mf of metafields) {
          if (mf.id) {
            // Update existing metafield
            await shopifyAPI(shop, token, `/metafields/${mf.id}.json`, {
              method: 'PUT',
              body: JSON.stringify({
                metafield: { id: mf.id, value: mf.value || '' }
              })
            });
          } else if (mf.value) {
            // Create new metafield
            await shopifyAPI(shop, token, `/products/${id}/metafields.json`, {
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
        }
      }
      
      console.log(`✅ Product updated: ${id}`);
      res.json({ success: true, product: data.product });
      
    } catch (err) {
      console.error('Update product error:', err);
      res.status(500).json({ error: 'Failed to update product' });
    }
  }
);

/**
 * Delete product
 */
app.delete('/api/vendors/:handle/products/:id',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const { id } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/products/${id}.json`,
        {
          method: 'DELETE',
          headers: { 'X-Shopify-Access-Token': token }
        }
      );
      
      console.log(`✅ Product deleted: ${id}`);
      res.json({ success: true });
      
    } catch (err) {
      console.error('Delete product error:', err);
      res.status(500).json({ error: 'Failed to delete product' });
    }
  }
);

/**
 * Upload product image
 */
app.post('/api/vendors/:handle/products/:id/images',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const { id } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      const { attachment, alt, position } = req.body;
      
      const imageData = {
        image: {
          attachment,
          alt: alt || '',
          position: position || 1
        }
      };
      
      const data = await shopifyAPI(shop, token, `/products/${id}/images.json`, {
        method: 'POST',
        body: JSON.stringify(imageData)
      });
      
      console.log(`✅ Image uploaded to product: ${id}`);
      res.json({ success: true, image: data.image });
      
    } catch (err) {
      console.error('Upload image error:', err);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  }
);

/**
 * Delete product image
 */
app.delete('/api/vendors/:handle/products/:id/images/:imageId',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const { id, imageId } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/products/${id}/images/${imageId}.json`,
        {
          method: 'DELETE',
          headers: { 'X-Shopify-Access-Token': token }
        }
      );
      
      console.log(`✅ Image deleted from product: ${id}, image: ${imageId}`);
      res.json({ success: true });
      
    } catch (err) {
      console.error('Delete image error:', err);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

/**
 * Get product metafields
 */
app.get('/api/vendors/:handle/products/:id/metafields',
  requireShopifyAuth,
  requireVendorAuth,
  validateProductOwnership,
  async (req, res) => {
    try {
      const { id } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      const data = await shopifyAPI(shop, token, `/products/${id}/metafields.json`);
      
      res.json({ metafields: data.metafields });
      
    } catch (err) {
      console.error('Get metafields error:', err);
      res.status(500).json({ error: 'Failed to fetch metafields' });
    }
  }
);

// ===== ROUTES: STORE SETTINGS =====

/**
 * Get vendor collection settings (metafields)
 */
app.get('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { handle } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      // First try custom collections
      let collectionsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/custom_collections.json?handle=${handle}`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      let collectionsData = await collectionsRes.json();
      let collection = collectionsData.custom_collections?.[0];
      
      // If not found, try smart collections
      if (!collection) {
        collectionsRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/smart_collections.json?handle=${handle}`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        
        collectionsData = await collectionsRes.json();
        collection = collectionsData.smart_collections?.[0];
      }
      
      if (!collection) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      // Get metafields for the collection
      const metafieldsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/collections/${collection.id}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      const metafieldsData = await metafieldsRes.json();
      
      // Convert metafields array to object keyed by key name
      const metafields = {};
      (metafieldsData.metafields || []).forEach(mf => {
        metafields[mf.key] = {
          id: mf.id,
          value: mf.value,
          type: mf.type,
          namespace: mf.namespace
        };
      });
      
      console.log(`✅ Settings loaded for collection: ${handle}`);
      
      res.json({
        collection: {
          id: collection.id,
          title: collection.title,
          handle: collection.handle,
          image: collection.image
        },
        metafields
      });
      
    } catch (err) {
      console.error('Get settings error:', err);
      res.status(500).json({ error: 'Failed to load settings' });
    }
  }
);

/**
 * Update vendor collection settings (metafields)
 */
app.put('/api/vendors/:handle/settings',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { handle } = req.params;
      const { metafields } = req.body;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      if (!metafields || !Array.isArray(metafields)) {
        return res.status(400).json({ error: 'Metafields array required' });
      }
      
      // Get the collection by handle (try custom first, then smart)
      let collectionsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/custom_collections.json?handle=${handle}`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      let collectionsData = await collectionsRes.json();
      let collection = collectionsData.custom_collections?.[0];
      
      if (!collection) {
        collectionsRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/smart_collections.json?handle=${handle}`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        
        collectionsData = await collectionsRes.json();
        collection = collectionsData.smart_collections?.[0];
      }
      
      if (!collection) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      // Update each metafield
      const results = [];
      const errors = [];
      
      for (const mf of metafields) {
        try {
          let endpoint, method, body;
          
          if (mf.id) {
            // Update existing metafield
            endpoint = `https://${shop}.myshopify.com/admin/api/${API_VERSION}/metafields/${mf.id}.json`;
            method = 'PUT';
            body = {
              metafield: {
                id: mf.id,
                value: mf.value || ''
              }
            };
          } else {
            // Create new metafield
            endpoint = `https://${shop}.myshopify.com/admin/api/${API_VERSION}/collections/${collection.id}/metafields.json`;
            method = 'POST';
            body = {
              metafield: {
                namespace: mf.namespace || 'custom',
                key: mf.key,
                value: mf.value || '',
                type: mf.type || 'single_line_text_field'
              }
            };
          }
          
          const updateRes = await fetch(endpoint, {
            method,
            headers: {
              'X-Shopify-Access-Token': token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
          });
          
          const result = await updateRes.json();
          
          if (updateRes.ok) {
            results.push(result);
          } else {
            errors.push({ key: mf.key, error: result });
          }
        } catch (mfErr) {
          errors.push({ key: mf.key, error: mfErr.message });
        }
      }
      
      console.log(`✅ Settings updated for collection: ${handle} (${results.length} saved, ${errors.length} errors)`);
      
      res.json({ 
        success: true, 
        results,
        errors: errors.length > 0 ? errors : undefined
      });
      
    } catch (err) {
      console.error('Update settings error:', err);
      res.status(500).json({ error: 'Failed to save settings' });
    }
  }
);

/**
 * Upload image for vendor settings
 */
app.post('/api/vendors/:handle/settings/images',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { handle } = req.params;
      const { imageType, attachment, alt } = req.body;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      if (!imageType || !attachment) {
        return res.status(400).json({ error: 'imageType and attachment required' });
      }
      
      // Get collection
      let collectionsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/custom_collections.json?handle=${handle}`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      let collectionsData = await collectionsRes.json();
      let collection = collectionsData.custom_collections?.[0];
      
      if (!collection) {
        collectionsRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/smart_collections.json?handle=${handle}`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        
        collectionsData = await collectionsRes.json();
        collection = collectionsData.smart_collections?.[0];
      }
      
      if (!collection) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      // Upload to Shopify Files using GraphQL
      const uploadResult = await shopifyGraphQL(shop, token, `
        mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files {
              ... on MediaImage {
                id
                image {
                  url
                }
              }
              ... on GenericFile {
                id
                url
              }
            }
            userErrors {
              field
              message
            }
          }
        }
      `, {
        files: [{
          alt: alt || imageType,
          contentType: 'IMAGE',
          originalSource: `data:image/png;base64,${attachment}`
        }]
      });
      
      if (uploadResult.data?.fileCreate?.userErrors?.length > 0) {
        const error = uploadResult.data.fileCreate.userErrors[0];
        throw new Error(error.message);
      }
      
      // Get the URL - may need to poll for it since file processing is async
      let imageUrl = uploadResult.data?.fileCreate?.files?.[0]?.image?.url;
      const fileId = uploadResult.data?.fileCreate?.files?.[0]?.id;
      
      // If URL not immediately available, poll for it
      if (!imageUrl && fileId) {
        // Wait a bit for file processing
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const fileQueryResult = await shopifyGraphQL(shop, token, `
          query getFile($id: ID!) {
            node(id: $id) {
              ... on MediaImage {
                image {
                  url
                }
              }
            }
          }
        `, { id: fileId });
        
        imageUrl = fileQueryResult.data?.node?.image?.url;
      }
      
      if (!imageUrl) {
        // Fallback: try to get URL from generic file
        imageUrl = uploadResult.data?.fileCreate?.files?.[0]?.url;
      }
      
      if (!imageUrl) {
        throw new Error('Failed to get image URL after upload');
      }
      
      // Save URL as metafield on the collection
      const metafieldKey = `${imageType}_image`;
      
      // Check if metafield already exists
      const existingMetafieldsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/collections/${collection.id}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      const existingMetafieldsData = await existingMetafieldsRes.json();
      const existingMetafield = existingMetafieldsData.metafields?.find(
        mf => mf.key === metafieldKey && mf.namespace === 'custom'
      );
      
      let metafieldRes;
      if (existingMetafield) {
        // Update existing
        metafieldRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/metafields/${existingMetafield.id}.json`,
          {
            method: 'PUT',
            headers: {
              'X-Shopify-Access-Token': token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              metafield: {
                id: existingMetafield.id,
                value: imageUrl
              }
            })
          }
        );
      } else {
        // Create new
        metafieldRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/collections/${collection.id}/metafields.json`,
          {
            method: 'POST',
            headers: {
              'X-Shopify-Access-Token': token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              metafield: {
                namespace: 'custom',
                key: metafieldKey,
                value: imageUrl,
                type: 'single_line_text_field'
              }
            })
          }
        );
      }
      
      console.log(`✅ Image uploaded for ${handle}: ${imageType}`);
      res.json({ success: true, url: imageUrl });
      
    } catch (err) {
      console.error('Upload settings image error:', err);
      res.status(500).json({ error: err.message || 'Failed to upload image' });
    }
  }
);

/**
 * Delete image from vendor settings
 */
app.delete('/api/vendors/:handle/settings/images/:imageType',
  requireShopifyAuth,
  requireVendorAuth,
  async (req, res) => {
    try {
      const { handle, imageType } = req.params;
      const shop = req.shop;
      const token = req.shopifyToken;
      
      // Get collection
      let collectionsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/custom_collections.json?handle=${handle}`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      let collectionsData = await collectionsRes.json();
      let collection = collectionsData.custom_collections?.[0];
      
      if (!collection) {
        collectionsRes = await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/smart_collections.json?handle=${handle}`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        
        collectionsData = await collectionsRes.json();
        collection = collectionsData.smart_collections?.[0];
      }
      
      if (!collection) {
        return res.status(404).json({ error: 'Collection not found' });
      }
      
      // Get the metafield
      const metafieldKey = `${imageType}_image`;
      const metafieldsRes = await fetch(
        `https://${shop}.myshopify.com/admin/api/${API_VERSION}/collections/${collection.id}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      
      const metafieldsData = await metafieldsRes.json();
      const metafield = metafieldsData.metafields?.find(
        mf => mf.key === metafieldKey && mf.namespace === 'custom'
      );
      
      if (metafield) {
        await fetch(
          `https://${shop}.myshopify.com/admin/api/${API_VERSION}/metafields/${metafield.id}.json`,
          {
            method: 'DELETE',
            headers: { 'X-Shopify-Access-Token': token }
          }
        );
        
        console.log(`✅ Image deleted for ${handle}: ${imageType}`);
      }
      
      res.json({ success: true });
      
    } catch (err) {
      console.error('Delete settings image error:', err);
      res.status(500).json({ error: 'Failed to delete image' });
    }
  }
);

// ===== ERROR HANDLING =====

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ===== START SERVER =====

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║           HalfCourse Vendor API Server v2.1.0              ║
╠════════════════════════════════════════════════════════════╣
║  Server running on port ${PORT}                               ║
║  Store: ${SHOPIFY_STORE}                                  ║
║  API Version: ${API_VERSION}                                  ║
║  Vendors configured: ${Object.keys(VENDOR_MAP).length}                                  ║
╚════════════════════════════════════════════════════════════╝
  `);
});
