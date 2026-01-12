import pg from "pg";
const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// Initialize database table
export async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS shops (
        shop VARCHAR(255) PRIMARY KEY,
        access_token TEXT NOT NULL,
        scope TEXT NOT NULL,
        installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("✅ Database initialized");
  } catch (err) {
    console.error("❌ Database initialization error:", err);
  } finally {
    client.release();
  }
}

// Get shop data
export async function getShop(shop) {
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM shops WHERE shop = $1",
      [shop]
    );
    return result.rows[0] || null;
  } catch (err) {
    console.error("❌ Error fetching shop:", err);
    return null;
  } finally {
    client.release();
  }
}

// Save or update shop data
export async function saveShop(shop, accessToken, scope) {
  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO shops (shop, access_token, scope, installed_at, updated_at)
       VALUES ($1, $2, $3, NOW(), NOW())
       ON CONFLICT (shop)
       DO UPDATE SET 
         access_token = $2,
         scope = $3,
         updated_at = NOW()`,
      [shop, accessToken, scope]
    );
    console.log(`✅ Shop saved: ${shop}`);
    return true;
  } catch (err) {
    console.error("❌ Error saving shop:", err);
    return false;
  } finally {
    client.release();
  }
}

// Delete shop data
export async function deleteShop(shop) {
  const client = await pool.connect();
  try {
    await client.query("DELETE FROM shops WHERE shop = $1", [shop]);
    console.log(`✅ Shop deleted: ${shop}`);
    return true;
  } catch (err) {
    console.error("❌ Error deleting shop:", err);
    return false;
  } finally {
    client.release();
  }
}

// Get all shops (for debug)
export async function getAllShops() {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT shop, scope, installed_at FROM shops");
    return result.rows;
  } catch (err) {
    console.error("❌ Error fetching all shops:", err);
    return [];
  } finally {
    client.release();
  }
}


