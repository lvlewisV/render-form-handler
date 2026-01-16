/**
 * HalfCourse Vendor API v2 - OAuth Version
 * 
 * Uses Shopify OAuth to authenticate instead of static access tokens.
 * 
 * Setup:
 * 1. npm install express cors multer dotenv node-fetch
 * 2. Set environment variables (see below)
 * 3. Deploy to Render, Railway, etc.
 * 
 * Environment Variables:
 * - SHOPIFY_CLIENT_ID=your_client_id
 * - SHOPIFY_CLIENT_SECRET=your_client_secret
 * - SHOPIFY_STORE=half-course (just the store name, not full URL)
 * - SHOPIFY_SCOPES=read_products,write_products,read_orders
 * - APP_URL=https://your-app.onrender.com (your deployed URL)
 * - PORT=3000
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Config
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'half-course';
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_products,write_products,read_orders';
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const API_VERSION = '2024-01';

// Store access tokens in memory (use Redis/DB in production)
let accessTokens = {};

// Middleware
app.use(cors({
  origin: [
    'https://halfcourse.com',
    'https://www.halfcourse.com',
    'https://half-course.myshopify.com',
    /\.myshopify\.com$/
  ],
  credentials: true
}));
app.use(express.json());

// ===== VENDOR MAP =====
const VENDOR_MAP = {
  'liandros': "Liandro's",
  // Add more vendors here:
  // 'marias-kitchen': "Maria's Kitchen",
};

function getVendorName(handle) {
  return VENDOR_MAP[handle] || handle;
}

// ===== OAUTH ROUTES =====

// Step 1: Start OAuth flow
app.get('/auth', (req, res) => {
  const shop = process.env.SHOPIFY_STORE;
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/auth/callback`;
  
  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;
  
  res.redirect(authUrl);
});

// Step 2: OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, shop, state } = req.query;
  
  if (!code || !shop) {
    return res.status(400).send('Missing code or shop');
  }
  
  try {
    // Exchange code for access token
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code: code
      })
    });
    
    const data = await response.json();
    
    if (data.access_token) {
      // Store the token
      accessTokens[shop] = data.access_token;
      console.log('Access token obtained for:', shop);
      
      // Redirect to success page or admin
      res.send(`
        <html>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>✅ Connected!</h1>
            <p>HalfCourse Vendor API is now connected to your store.</p>
            <p>You can close this window.</p>
          </body>
        </html>
      `);
    } else {
      throw new Error(data.error || 'Failed to get access token');
    }
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).send('Authentication failed: ' + error.message);
  }
});

// ===== HELPER: Get Access Token =====
function getAccessToken() {
  const shop = `${SHOPIFY_STORE}.myshopify.com`;
  return accessTokens[shop] || process.env.SHOPIFY_ACCESS_TOKEN;
}

function getShopifyHeaders() {
  const token = getAccessToken();
  if (!token) {
    throw new Error('No access token available. Please authenticate first.');
  }
  return {
    'Content-Type': 'application/json',
    'X-Shopify-Access-Token': token
  };
}

function getBaseUrl() {
  return `https://${SHOPIFY_STORE}.myshopify.com/admin/api/${API_VERSION}`;
}

// ===== MIDDLEWARE: Check Auth =====
function requireAuth(req, res, next) {
  try {
    getShopifyHeaders();
    next();
  } catch (error) {
    res.status(401).json({ 
      error: 'Not authenticated', 
      authUrl: `${APP_URL}/auth` 
    });
  }
}

// ===== MIDDLEWARE: Validate Vendor Access =====
async function validateVendorAccess(req, res, next) {
  const { handle } = req.params;
  const productId = req.params.id;
  
  if (productId) {
    try {
      const response = await fetch(`${getBaseUrl()}/products/${productId}.json`, {
        headers: getShopifyHeaders()
      });
      
      if (!response.ok) {
        return res.status(404).json({ error: 'Product not found' });
      }
      
      const data = await response.json();
      const vendorName = getVendorName(handle);
      
      if (data.product.vendor !== vendorName) {
        return res.status(403).json({ error: 'Access denied - product belongs to different vendor' });
      }
      
      req.product = data.product;
    } catch (error) {
      console.error('Validation error:', error);
      return res.status(500).json({ error: 'Validation failed' });
    }
  }
  
  next();
}

// ===== API ROUTES =====

// Check authentication status
app.get('/api/status', (req, res) => {
  const hasToken = !!getAccessToken();
  res.json({ 
    authenticated: hasToken,
    authUrl: hasToken ? null : `${APP_URL}/auth`
  });
});

// Get vendor's products
app.get('/api/vendors/:handle/products', requireAuth, async (req, res) => {
  const { handle } = req.params;
  const vendorName = getVendorName(handle);
  
  try {
    const response = await fetch(
      `${getBaseUrl()}/products.json?vendor=${encodeURIComponent(vendorName)}&limit=250`,
      { headers: getShopifyHeaders() }
    );
    
    if (!response.ok) {
      throw new Error('Failed to fetch products');
    }
    
    const data = await response.json();
    
    // Fetch metafields for each product
    const productsWithMetafields = await Promise.all(
      data.products.map(async (product) => {
        try {
          const metaResponse = await fetch(
            `${getBaseUrl()}/products/${product.id}/metafields.json`,
            { headers: getShopifyHeaders() }
          );
          const metaData = await metaResponse.json();
          
          const metafields = {};
          (metaData.metafields || []).forEach(mf => {
            if (mf.namespace === 'custom') {
              metafields[mf.key] = mf.value;
            }
          });
          
          return { ...product, metafields };
        } catch (e) {
          return { ...product, metafields: {} };
        }
      })
    );
    
    res.json(productsWithMetafields);
    
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Create product
app.post('/api/vendors/:handle/products', requireAuth, upload.any(), async (req, res) => {
  const { handle } = req.params;
  const vendorName = getVendorName(handle);
  
  try {
    const { title, description, price, product_type, tagline, serves, prep_time } = req.body;
    
    const productData = {
      product: {
        title,
        body_html: description || '',
        vendor: vendorName,
        product_type: product_type || '',
        status: 'active',
        variants: [{
          price: parseFloat(price) || 0,
          inventory_management: null,
          inventory_policy: 'continue'
        }]
      }
    };
    
    const createResponse = await fetch(`${getBaseUrl()}/products.json`, {
      method: 'POST',
      headers: getShopifyHeaders(),
      body: JSON.stringify(productData)
    });
    
    if (!createResponse.ok) {
      const errorData = await createResponse.json();
      throw new Error(errorData.errors || 'Failed to create product');
    }
    
    const created = await createResponse.json();
    const productId = created.product.id;
    
    // Add to vendor's collection
    await addProductToVendorCollection(handle, productId);
    
    // Set metafields
    if (tagline || serves || prep_time) {
      await setProductMetafields(productId, { tagline, serves, prep_time });
    }
    
    // Upload images
    const imageFiles = req.files?.filter(f => f.fieldname.startsWith('image_')) || [];
    for (const file of imageFiles) {
      await uploadProductImage(productId, file);
    }
    
    res.json({ success: true, product: created.product });
    
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ error: error.message || 'Failed to create product' });
  }
});

// Update product
app.put('/api/vendors/:handle/products/:id', requireAuth, validateVendorAccess, upload.any(), async (req, res) => {
  const { id } = req.params;
  
  try {
    const { 
      title, 
      description, 
      price, 
      compare_price,
      product_type, 
      available,
      tagline, 
      serves, 
      prep_time,
      images_to_delete 
    } = req.body;
    
    const updateData = {
      product: {
        id,
        title,
        body_html: description || '',
        product_type: product_type || '',
        status: available === 'true' || available === true ? 'active' : 'draft'
      }
    };
    
    const updateResponse = await fetch(`${getBaseUrl()}/products/${id}.json`, {
      method: 'PUT',
      headers: getShopifyHeaders(),
      body: JSON.stringify(updateData)
    });
    
    if (!updateResponse.ok) {
      throw new Error('Failed to update product');
    }
    
    // Update variant price
    const product = req.product;
    const variantId = product.variants[0].id;
    
    const variantData = {
      variant: {
        id: variantId,
        price: parseFloat(price) || 0,
        compare_at_price: compare_price ? parseFloat(compare_price) : null
      }
    };
    
    await fetch(`${getBaseUrl()}/variants/${variantId}.json`, {
      method: 'PUT',
      headers: getShopifyHeaders(),
      body: JSON.stringify(variantData)
    });
    
    // Update metafields
    await setProductMetafields(id, { tagline, serves, prep_time });
    
    // Delete images
    if (images_to_delete) {
      const imagesToDelete = JSON.parse(images_to_delete);
      for (const imageId of imagesToDelete) {
        await fetch(`${getBaseUrl()}/products/${id}/images/${imageId}.json`, {
          method: 'DELETE',
          headers: getShopifyHeaders()
        });
      }
    }
    
    // Upload new images
    const newImages = req.files?.filter(f => f.fieldname.startsWith('new_image_')) || [];
    for (const file of newImages) {
      await uploadProductImage(id, file);
    }
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Delete product
app.delete('/api/vendors/:handle/products/:id', requireAuth, validateVendorAccess, async (req, res) => {
  const { id } = req.params;
  
  try {
    const response = await fetch(`${getBaseUrl()}/products/${id}.json`, {
      method: 'DELETE',
      headers: getShopifyHeaders()
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete product');
    }
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// ===== HELPER FUNCTIONS =====

async function setProductMetafields(productId, fields) {
  const metafields = [];
  
  if (fields.tagline !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'tagline',
      value: fields.tagline || '',
      type: 'single_line_text_field'
    });
  }
  
  if (fields.serves !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'serves',
      value: fields.serves || '',
      type: 'single_line_text_field'
    });
  }
  
  if (fields.prep_time !== undefined) {
    metafields.push({
      namespace: 'custom',
      key: 'prep_time',
      value: fields.prep_time || '',
      type: 'single_line_text_field'
    });
  }
  
  for (const metafield of metafields) {
    try {
      const existingResponse = await fetch(
        `${getBaseUrl()}/products/${productId}/metafields.json?namespace=custom&key=${metafield.key}`,
        { headers: getShopifyHeaders() }
      );
      const existingData = await existingResponse.json();
      
      if (existingData.metafields && existingData.metafields.length > 0) {
        const existingId = existingData.metafields[0].id;
        await fetch(`${getBaseUrl()}/metafields/${existingId}.json`, {
          method: 'PUT',
          headers: getShopifyHeaders(),
          body: JSON.stringify({ metafield: { ...metafield, id: existingId } })
        });
      } else {
        await fetch(`${getBaseUrl()}/products/${productId}/metafields.json`, {
          method: 'POST',
          headers: getShopifyHeaders(),
          body: JSON.stringify({ metafield })
        });
      }
    } catch (e) {
      console.error('Error setting metafield:', e);
    }
  }
}

async function uploadProductImage(productId, file) {
  const base64Image = file.buffer.toString('base64');
  
  const imageData = {
    image: {
      attachment: base64Image,
      filename: file.originalname
    }
  };
  
  await fetch(`${getBaseUrl()}/products/${productId}/images.json`, {
    method: 'POST',
    headers: getShopifyHeaders(),
    body: JSON.stringify(imageData)
  });
}

async function addProductToVendorCollection(vendorHandle, productId) {
  try {
    const collectionsResponse = await fetch(
      `${getBaseUrl()}/custom_collections.json?handle=${vendorHandle}`,
      { headers: getShopifyHeaders() }
    );
    const collectionsData = await collectionsResponse.json();
    
    if (collectionsData.custom_collections && collectionsData.custom_collections.length > 0) {
      const collectionId = collectionsData.custom_collections[0].id;
      
      await fetch(`${getBaseUrl()}/collects.json`, {
        method: 'POST',
        headers: getShopifyHeaders(),
        body: JSON.stringify({
          collect: {
            product_id: productId,
            collection_id: collectionId
          }
        })
      });
    }
  } catch (error) {
    console.error('Error adding product to collection:', error);
  }
}

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    authenticated: !!getAccessToken()
  });
});

// Home page with auth link
app.get('/', (req, res) => {
  const hasToken = !!getAccessToken();
  res.send(`
    <html>
      <head><title>HalfCourse Vendor API</title></head>
      <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>HalfCourse Vendor API</h1>
        ${hasToken ? 
          '<p style="color: green;">✅ Connected to Shopify</p>' : 
          `<p style="color: orange;">⚠️ Not connected</p>
           <a href="/auth" style="display: inline-block; padding: 12px 24px; background: #ac380b; color: white; text-decoration: none; border-radius: 8px;">Connect to Shopify</a>`
        }
      </body>
    </html>
  `);
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`HalfCourse Vendor API running on port ${PORT}`);
  console.log(`Auth URL: ${APP_URL}/auth`);
});

module.exports = app;
