import express from "express";
import axios from "axios";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SCOPES,
  HOST,
  PORT
} = process.env;

// 1️⃣ App entry
app.get("/", (req, res) => {
  res.send("Shopify Dummy App Backend is running ✅");
});

// 2️⃣ Start OAuth
app.get("/auth", (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop parameter");

  const redirectUri = `${HOST}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${redirectUri}`;

  res.redirect(installUrl);
});

// 3️⃣ OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { shop, code } = req.query;

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

    // 🔹 Dummy storage (for now)
    console.log("Store:", shop);
    console.log("Access Token:", accessToken);

    res.send("✅ App installed successfully. You can close this window.");
  } catch (error) {
    console.error(error);
    res.status(500).send("OAuth failed");
  }
});

// 4️⃣ Dummy API call (REAL Shopify API usage)
app.get("/api/store-info", async (req, res) => {
  res.json({
    message: "This endpoint will fetch store info later",
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
