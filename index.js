import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
app.use(express.json());

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SCOPES,
  HOST,
  PORT = 3000,
} = process.env;

/* ======================================================
   📦 SIMPLE FILE DB
====================================================== */
const DB_PATH = path.join(process.cwd(), "db.json");

function readDB() {
  if (!fs.existsSync(DB_PATH)) return {};
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

/* ======================================================
   🔐 HMAC VALIDATION
====================================================== */
function verifyHmac(query) {
  const { hmac, ...rest } = query;

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
   🔒 CSP FOR EMBEDDED APPS
====================================================== */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com"
  );
  next();
});

/* ======================================================
   🏠 ROOT (APP BRIDGE BOOTSTRAP)
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
        <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
        <script>
          var AppBridge = window['app-bridge'];
          var createApp = AppBridge.createApp;
          var Redirect = AppBridge.actions.Redirect;

          var app = createApp({
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
  if (!shop) return res.status(400).send("Missing shop");

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
  const { shop, code } = req.query;

  if (!verifyHmac(req.query)) {
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

    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

/* ======================================================
   🧪 DEBUG (OPTIONAL)
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
