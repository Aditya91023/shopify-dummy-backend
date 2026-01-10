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
   🔐 HMAC VERIFICATION (MANDATORY)
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
   🏠 APP ENTRY
====================================================== */
app.get("/", (req, res) => {
  res.send("Shopify Dummy App Backend is running ✅");
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
  const { shop, code } = req.query;

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC validation failed ❌");
  }

  try {
    // Exchange code for access token
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }
    );

    const accessToken = tokenResponse.data.access_token;

    // Store token in file DB
    const db = readDB();

    db[shop] = {
      access_token: accessToken,
      scope: SCOPES,
      installed_at: new Date().toISOString(),
    };

    writeDB(db);

    // Redirect back to Shopify Admin (embedded app)
    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
  } catch (error) {
    console.error("OAuth Error:", error.response?.data || error.message);
    res.status(500).send("OAuth failed");
  }
});

/* ======================================================
   🧪 DEBUG ROUTE (TEMPORARY – REMOVE BEFORE PUBLISH)
====================================================== */
app.get("/auth/callback", async (req, res) => {
  console.log("🔁 OAuth callback HIT");
  console.log("QUERY PARAMS:", req.query);

  const { shop, code } = req.query;

  // TEMP: bypass HMAC just to confirm flow
  // if (!verifyHmac(req.query)) {
  //   console.log("❌ HMAC FAILED");
  //   return res.status(400).send("HMAC validation failed");
  // }

  try {
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }
    );

    console.log("✅ Access token response:", tokenResponse.data);

    const accessToken = tokenResponse.data.access_token;

    const db = readDB();
    db[shop] = {
      access_token: accessToken,
      scope: SCOPES,
      installed_at: new Date().toISOString(),
    };
    writeDB(db);

    console.log("✅ TOKEN STORED FOR:", shop);

    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
  } catch (err) {
    console.error("🔥 OAuth ERROR:", err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

/* ======================================================
   🚀 START SERVER
====================================================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
