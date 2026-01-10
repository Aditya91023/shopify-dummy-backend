import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";
import { readDB, writeDB } from "./store.js";

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
   🏠 ROOT
====================================================== */
app.get("/", (req, res) => {
  const { shop } = req.query;

  if (!shop) {
    return res.send("Missing shop parameter");
  }

  // 🚀 START OAUTH
  res.redirect(`/auth?shop=${shop}`);
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
   🔁 OAUTH CALLBACK (ONLY ONE!)
====================================================== */
app.get("/auth/callback", async (req, res) => {
  console.log("🔁 OAuth callback HIT");
  console.log("QUERY:", req.query);

  const { shop, code } = req.query;

  if (!verifyHmac(req.query)) {
    console.log("❌ HMAC FAILED");
    return res.status(400).send("HMAC validation failed ❌");
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
    console.log("✅ Access token received");

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
   🧪 DEBUG ROUTE (THIS WAS MISSING)
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
