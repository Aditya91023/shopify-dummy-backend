import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
import cors from "cors";
import { initDB, getShop, saveShop, deleteShop, getAllShops } from "./db.js";

dotenv.config();

const app = express();

/* ======================================================
   🌍 CORS (MANDATORY FOR SHOPIFY IFRAME)
====================================================== */
app.use(
  cors({
    origin: "*", // OK for dummy/testing
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(cors());

/* ======================================================
   🧠 BODY PARSING
====================================================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SCOPES,
  HOST,
  PORT = 3000,
} = process.env;

/* ======================================================
   🗄️ INIT DB
====================================================== */
await initDB()
  .then(() => console.log("✅ DB initialized"))
  .catch((err) => console.error("❌ DB init failed", err));

/* ======================================================
   🔐 HMAC VALIDATION
====================================================== */
function verifyHmac(query) {
  const { hmac, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  return digest === hmac;
}

/* ======================================================
   🎲 NONCE
====================================================== */
const nonces = new Map();

function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

/* ======================================================
   🔒 CSP (EMBEDDED SAFE)
====================================================== */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
  );
  next();
});

/* ======================================================
   📊 LOGGING
====================================================== */
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, req.query);
  next();
});

/* ======================================================
   🏠 ROOT (HEALTH CHECK)
====================================================== */
app.get("/", (req, res) => {
  res.send("Shopify Dummy Backend is running");
});

/* ======================================================
   🔑 START OAUTH
====================================================== */
app.get("/auth", (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send("Missing shop");

  const nonce = generateNonce();
  nonces.set(nonce, Date.now());

  const redirectUri = `${HOST}/auth/callback`;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  res.redirect(installUrl);
});

/* ======================================================
   🔁 OAUTH CALLBACK
====================================================== */
app.get("/auth/callback", async (req, res) => {
  const { shop, code, host } = req.query;
  if (!shop || !code) return res.status(400).send("Missing params");

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC failed");
  }

  try {
    const tokenRes = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }
    );

    const accessToken = tokenRes.data.access_token;
    await saveShop(shop, accessToken, SCOPES);

    // 🔴 REDIRECT BACK TO FLUTTER UI
    res.redirect(
      `https://shopify-dummy-frontend.netlify.app/?shop=${shop}&host=${host}`
    );
  } catch (err) {
    console.error("OAuth error:", err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

/* ======================================================
   💳 DUMMY PAYMENT ENDPOINT (THIS WAS MISSING)
====================================================== */
app.post("/payment/dummy", async (req, res) => {
  const { shop, amount } = req.body;

  if (!shop || !amount) {
    return res.status(400).json({
      success: false,
      message: "Missing shop or amount",
    });
  }

  console.log(`💰 Dummy payment | Shop: ${shop} | Amount: ${amount}`);

  return res.status(200).json({
    success: true,
    message: "Dummy transaction successful",
  });
});

/* ======================================================
   🪝 WEBHOOK — APP UNINSTALLED
====================================================== */
app.post("/webhooks/app_uninstalled", async (req, res) => {
  const hmac = req.get("X-Shopify-Hmac-Sha256");
  const body = JSON.stringify(req.body);

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(body, "utf8")
    .digest("base64");

  if (digest !== hmac) {
    return res.status(403).send("HMAC validation failed");
  }

  const shop = req.get("X-Shopify-Shop-Domain");
  await deleteShop(shop);

  res.status(200).send("OK");
});

/* ======================================================
   🧪 DEBUG
====================================================== */
app.get("/debug/shops", async (req, res) => {
  res.json(await getAllShops());
});

/* ======================================================
   ❌ 404
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
});
