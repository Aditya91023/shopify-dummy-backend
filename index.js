import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
import { readDB, writeDB } from "./store.js";

dotenv.config();

const app = express();
app.use(express.json());

/* ======================================================
   🔐 REQUIRED CSP FOR SHOPIFY EMBEDDED APPS
====================================================== */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com"
  );
  next();
});

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SCOPES,
  HOST,
  PORT = 3000,
} = process.env;

/* ======================================================
   🔐 HMAC VERIFICATION
====================================================== */
function verifyHmac(query) {
  const { hmac, ...rest } = query;

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join("&");

  const generatedHmac = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  return generatedHmac === hmac;
}

/* ======================================================
   🏠 ROOT (EMBEDDED APP ENTRY POINT)
   ✔ Uses Shopify App Bridge
   ✔ Breaks out of iframe safely
====================================================== */
app.get("/", (req, res) => {
  const { shop, host } = req.query;

  if (!shop || !host) {
    return res.status(400).send("Missing shop or host parameter");
  }

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8" />
        <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
        <script>
          const AppBridge = window['app-bridge'];
          const createApp = AppBridge.createApp;
          const Redirect = AppBridge.actions.Redirect;

          const app = createApp({
            apiKey: "${SHOPIFY_API_KEY}",
            host: "${host}",
            forceRedirect: true,
          });

          Redirect.create(app).dispatch(
            Redirect.Action.REMOTE,
            "/auth?shop=${shop}"
          );
        </script>
      </head>
      <body></body>
    </html>
  `);
});

/* ======================================================
   🔑 START OAUTH
====================================================== */
app.get("/auth", (req, res) => {
  const { shop } = req.query;

  if (!shop) {
    return res.status(400).send("Missing shop parameter");
  }

  const redirectUri = `${HOST}/auth/callback`;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${redirectUri}`;

  res.redirect(installUrl);
});

/* ======================================================
   🔁 OAUTH CALLBACK
====================================================== */
app.get("/auth/callback", async (req, res) => {
  console.log("🔁 OAuth callback HIT");
  console.log("QUERY:", req.query);

  const { shop, code } = req.query;

  if (!verifyHmac(req.query)) {
    console.log("❌ HMAC validation failed");
    return res.status(400).send("HMAC validation failed");
  }

  try {
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const db = readDB();
    db[shop] = {
      access_token: accessToken,
      scope: SCOPES,
      installed_at: new Date().toISOString(),
    };
    writeDB(db);

    console.log("✅ Token stored for:", shop);

    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
  } catch (err) {
    console.error("🔥 OAuth error:", err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

/* ======================================================
   🧪 DEBUG ROUTE
====================================================== */
app.get("/debug/shops", (req, res) => {
  res.json(readDB());
});

/* ======================================================
   🚀 START SERVER
====================================================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
