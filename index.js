import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
import { initDB, getShop, saveShop, deleteShop, getAllShops } from "./db.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SCOPES,
  HOST,
  PORT = 3000,
} = process.env;

// Initialize database on startup
await initDB()
  .then(() => console.log("✅ DB initialized"))
  .catch(err => console.error("❌ DB init failed", err));

/* ======================================================
   🔐 HMAC VALIDATION
====================================================== */
function verifyHmac(query) {
  const { hmac, ...rest } = query;
  
  if (!hmac) {
    console.error("❌ No HMAC provided");
    return false;
  }

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  const isValid = digest === hmac;
  console.log(`🔐 HMAC validation: ${isValid ? "✅ PASS" : "❌ FAIL"}`);
  return isValid;
}

/* ======================================================
   🎲 NONCE GENERATION & VALIDATION
====================================================== */
const nonces = new Map();

function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function validateNonce(state) {
  if (!state) return false;
  const isValid = nonces.has(state);
  if (isValid) {
    nonces.delete(state);
  }
  return isValid;
}

setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of nonces.entries()) {
    if (now - timestamp > 600000) {
      nonces.delete(nonce);
    }
  }
}, 600000);

/* ======================================================
   🔒 CSP FOR EMBEDDED APPS
====================================================== */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
  );
  next();
});

/* ======================================================
   📊 LOGGING MIDDLEWARE
====================================================== */
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, req.query);
  next();
});

/* ======================================================
   🏠 ROOT - Health Check
====================================================== */
app.get("/", (req, res) => {
  const { shop, embedded } = req.query;

  if (!shop) {
    return res.status(400).send("Missing shop parameter");
  }

  // ✅ If embedded, break out of iframe BEFORE OAuth
  if (embedded === "1") {
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <script>
            window.top.location.href = "/auth?shop=${shop}";
          </script>
        </head>
        <body></body>
      </html>
    `);
  }

  // Non-embedded fallback
  res.redirect(`/auth?shop=${shop}`);
});


/* ======================================================
   🔑 START OAUTH
====================================================== */
app.get("/auth", (req, res) => {
  const { shop } = req.query;
  
  if (!shop) {
    console.error("❌ Missing shop parameter");
    return res.status(400).send("Missing shop parameter");
  }

  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/;
  if (!shopRegex.test(shop)) {
    console.error("❌ Invalid shop domain:", shop);
    return res.status(400).send("Invalid shop domain");
  }

  const nonce = generateNonce();
  nonces.set(nonce, Date.now());

  const redirectUri = `${HOST}/auth/callback`;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  console.log(`🔑 Redirecting to OAuth: ${shop}`);
  res.redirect(installUrl);
});

/* ======================================================
   🔁 OAUTH CALLBACK
====================================================== */
app.get("/auth/callback", async (req, res) => {
  console.log("🔁 /auth/callback HIT");
  console.log("QUERY PARAMS:", req.query);

  const { shop, code } = req.query;

  if (!shop || !code) {
    console.log("❌ Missing shop or code");
    return res.status(400).send("Missing shop or code");
  }

  if (!verifyHmac(req.query)) {
    console.log("❌ HMAC FAILED");
    return res.status(400).send("HMAC failed");
  }

  try {
    const tokenRes = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code,
      }
    );

    console.log("✅ Access token response:", tokenRes.data);

    const accessToken = tokenRes.data.access_token;

    await saveShop(shop, accessToken, process.env.SCOPES);

    console.log("✅ TOKEN SAVED TO DB FOR:", shop);

    res.redirect(`https://shopify-dummy-frontend.netlify.app/#/screen_initial?shop=${shop}&host=${req.query.host}`);
  } catch (err) {
    console.error("🔥 OAUTH ERROR:", err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});


/* ======================================================
   🪝 WEBHOOK REGISTRATION
====================================================== */
async function registerWebhooks(shop, accessToken) {
  const webhooks = [
    {
      topic: "app/uninstalled",
      address: `${HOST}/webhooks/app_uninstalled`,
      format: "json",
    },
  ];

  for (const webhook of webhooks) {
    try {
      await axios.post(
        `https://${shop}/admin/api/2024-01/webhooks.json`,
        { webhook },
        {
          headers: {
            "X-Shopify-Access-Token": accessToken,
            "Content-Type": "application/json",
          },
        }
      );
      console.log(`✅ Registered webhook: ${webhook.topic}`);
    } catch (err) {
      console.error(`❌ Failed to register webhook ${webhook.topic}:`, err.response?.data || err.message);
    }
  }
}

/* ======================================================
   🪝 WEBHOOK HANDLER - App Uninstalled
====================================================== */
app.post("/webhooks/app_uninstalled", async (req, res) => {
  const hmac = req.get("X-Shopify-Hmac-Sha256");
  const body = JSON.stringify(req.body);
  
  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(body, "utf8")
    .digest("base64");

  if (digest !== hmac) {
    console.error("❌ Webhook HMAC validation failed");
    return res.status(403).send("HMAC validation failed");
  }

  const shop = req.get("X-Shopify-Shop-Domain");
  console.log(`🗑️ App uninstalled from: ${shop}`);

  await deleteShop(shop);

  res.status(200).send("OK");
});

/* ======================================================
   🧪 DEBUG ENDPOINTS
====================================================== */
app.get("/debug/shops", async (req, res) => {
  const shops = await getAllShops();
  res.json(shops);
});

app.get("/debug/config", (req, res) => {
  res.json({
    host: HOST,
    api_key: SHOPIFY_API_KEY ? "✓ Set" : "✗ Missing",
    api_secret: SHOPIFY_API_SECRET ? "✓ Set" : "✗ Missing",
    scopes: SCOPES,
    database: process.env.DATABASE_URL ? "✓ Connected" : "✗ Not configured",
  });
});

/* ======================================================
   ❌ 404 HANDLER
====================================================== */
app.use((req, res) => {
  res.status(404).send("Not Found");
});

/* ======================================================
   🚀 START SERVER
====================================================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Host: ${HOST}`);
  console.log(`🔑 API Key: ${SHOPIFY_API_KEY ? "✓" : "✗"}`);
  console.log(`🔐 API Secret: ${SHOPIFY_API_SECRET ? "✓" : "✗"}`);
});