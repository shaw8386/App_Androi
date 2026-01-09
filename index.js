const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const cloudinary = require("cloudinary").v2;

require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ===== ENV REQUIRED =====
// DATABASE_URL
// CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
// JWT_SECRET
// PORT (Railway sets)
// Optional seeding env:
// SEED_ADMIN=true/false (default true)
// ADMIN_USERNAME (default admin)
// ADMIN_PASSWORD (default 123456)

const PORT = process.env.PORT || 8080;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway") ? { rejectUnauthorized: false } : undefined,
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer memory storage (upload thẳng Cloudinary)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 },
});

// ===== DB INIT (AUTO CREATE TABLES) =====
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // cần cho gen_random_uuid()
    await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id TEXT UNIQUE NOT NULL,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        status TEXT NOT NULL DEFAULT 'PENDING',
        shot_count INT NOT NULL DEFAULT 0,
        uploaded_count INT NOT NULL DEFAULT 0,
        note TEXT
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS session_files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_db_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        file_index INT NOT NULL,
        cloudinary_url TEXT NOT NULL,
        cloudinary_public_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE(session_db_id, file_index)
      );
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);`);

    await client.query("COMMIT");
    console.log("✅ DB init ok");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("❌ DB init failed:", e);
    throw e;
  } finally {
    client.release();
  }
}

// ===== SEED ADMIN =====
async function seedAdminIfNeeded() {
  const seed = (process.env.SEED_ADMIN ?? "true").toLowerCase() === "true";
  if (!seed) {
    console.log("ℹ️ SEED_ADMIN=false -> skip seeding admin");
    return;
  }

  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "123456";

  // Nếu bạn muốn cố định đúng hash (admin/123456) như yêu cầu:
  // bcrypt hash (cost=10) của "123456":
  // $2b$10$B5Jlq0TZKSZT3T.xnSTHn.ZRQW68ey8kZJvuSiD6HGnTXcqyFQrUO
  //
  // Tuy nhiên để linh hoạt (đổi pass bằng ENV), ta hash runtime:
  const hash = await bcrypt.hash(adminPass, 10);

  try {
    const exist = await pool.query("SELECT id FROM users WHERE username=$1", [adminUser]);
    if (exist.rowCount > 0) {
      console.log(`ℹ️ Admin user '${adminUser}' already exists -> skip`);
      return;
    }

    await pool.query(
      "INSERT INTO users(username, password_hash) VALUES($1,$2)",
      [adminUser, hash]
    );

    console.log(`✅ Seeded admin account: ${adminUser} / ${adminPass}`);
  } catch (e) {
    console.error("❌ Seed admin failed:", e);
  }
}

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "NO_TOKEN" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { userId, username }
    next();
  } catch (e) {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
}

// ===== HELPERS =====
function makeSessionId(deviceId) {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const ts =
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    "_" +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds());
  return `${deviceId}_${ts}`;
}

// ===== AUTH ROUTES =====

// Register (optional: bạn có thể disable endpoint này khi production)
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "MISSING_FIELDS" });
  if (String(password).length < 6) return res.status(400).json({ error: "WEAK_PASSWORD" });

  const hash = await bcrypt.hash(password, 10);

  try {
    const r = await pool.query(
      "INSERT INTO users(username, password_hash) VALUES($1,$2) RETURNING id, username, created_at",
      [username, hash]
    );
    return res.json({ ok: true, user: r.rows[0] });
  } catch (e) {
    if (String(e.message).toLowerCase().includes("duplicate"))
      return res.status(409).json({ error: "USERNAME_TAKEN" });
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "MISSING_FIELDS" });

  const r = await pool.query("SELECT id, username, password_hash FROM users WHERE username=$1", [username]);
  if (r.rowCount === 0) return res.status(401).json({ error: "INVALID_CREDENTIALS" });

  const u = r.rows[0];
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "INVALID_CREDENTIALS" });

  const token = jwt.sign({ userId: u.id, username: u.username }, process.env.JWT_SECRET, { expiresIn: "30d" });
  return res.json({ ok: true, token, username: u.username });
});

app.get("/api/me", auth, async (req, res) => {
  return res.json({ ok: true, user: { id: req.user.userId, username: req.user.username } });
});

// ===== SESSION ROUTES =====

app.post("/api/session/start", auth, async (req, res) => {
  const { device_id } = req.body || {};
  if (!device_id) return res.status(400).json({ error: "MISSING_DEVICE_ID" });

  const sessionId = makeSessionId(device_id);

  try {
    await pool.query(
      `INSERT INTO sessions(session_id, user_id, device_id, status, shot_count, uploaded_count)
       VALUES($1,$2,$3,'PENDING',0,0)`,
      [sessionId, req.user.userId, device_id]
    );

    return res.json({ ok: true, session_id: sessionId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/session/:sessionId/upload", auth, upload.single("file"), async (req, res) => {
  const sessionId = req.params.sessionId;
  const deviceId = req.body.device_id;
  const index = parseInt(req.body.index, 10);

  if (!deviceId || !index || !req.file) return res.status(400).json({ error: "MISSING_FIELDS" });
  if (index < 1 || index > 6) return res.status(400).json({ error: "INVALID_INDEX" });

  const s = await pool.query("SELECT id, user_id, device_id FROM sessions WHERE session_id=$1", [sessionId]);
  if (s.rowCount === 0) return res.status(404).json({ error: "SESSION_NOT_FOUND" });

  const sessionRow = s.rows[0];
  if (sessionRow.user_id !== req.user.userId) return res.status(403).json({ error: "FORBIDDEN" });
  if (sessionRow.device_id !== deviceId) return res.status(400).json({ error: "DEVICE_MISMATCH" });

  const folder = `sessions/${req.user.username}/${deviceId}/${sessionId}`;
  const publicId = `${sessionId}_${String(index).padStart(2, "0")}`;

  try {
    const uploadRes = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder, public_id: publicId, resource_type: "image", overwrite: true },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(req.file.buffer);
    });

    await pool.query("BEGIN");

    await pool.query(
      `INSERT INTO session_files(session_db_id, file_index, cloudinary_url, cloudinary_public_id)
       VALUES($1,$2,$3,$4)
       ON CONFLICT (session_db_id, file_index)
       DO UPDATE SET cloudinary_url=EXCLUDED.cloudinary_url, cloudinary_public_id=EXCLUDED.cloudinary_public_id`,
      [sessionRow.id, index, uploadRes.secure_url, uploadRes.public_id]
    );

    const c = await pool.query(
      "SELECT COUNT(*)::int AS cnt FROM session_files WHERE session_db_id=$1",
      [sessionRow.id]
    );
    const uploadedCount = c.rows[0].cnt;

    await pool.query("UPDATE sessions SET uploaded_count=$1 WHERE id=$2", [uploadedCount, sessionRow.id]);
    await pool.query("COMMIT");

    return res.json({
      ok: true,
      index,
      file_url: uploadRes.secure_url,
      public_id: uploadRes.public_id,
      uploaded_count: uploadedCount,
    });
  } catch (e) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error(e);
    return res.status(500).json({ error: "UPLOAD_FAILED" });
  }
});

app.post("/api/session/:sessionId/end", auth, async (req, res) => {
  const sessionId = req.params.sessionId;
  const { device_id, shot_count } = req.body || {};
  const sc = parseInt(shot_count, 10);

  if (!device_id || !sc) return res.status(400).json({ error: "MISSING_FIELDS" });
  if (sc < 5 || sc > 6) return res.status(400).json({ error: "INVALID_SHOT_COUNT" });

  const s = await pool.query("SELECT id, user_id, device_id FROM sessions WHERE session_id=$1", [sessionId]);
  if (s.rowCount === 0) return res.status(404).json({ error: "SESSION_NOT_FOUND" });

  const sessionRow = s.rows[0];
  if (sessionRow.user_id !== req.user.userId) return res.status(403).json({ error: "FORBIDDEN" });
  if (sessionRow.device_id !== device_id) return res.status(400).json({ error: "DEVICE_MISMATCH" });

  const c = await pool.query(
    "SELECT COUNT(*)::int AS cnt FROM session_files WHERE session_db_id=$1",
    [sessionRow.id]
  );
  const uploadedCount = c.rows[0].cnt;

  let status = "PENDING";
  let note = null;

  if (uploadedCount >= sc) status = "SUCCESS";
  else note = `Uploaded ${uploadedCount}/${sc}`;

  await pool.query(
    "UPDATE sessions SET status=$1, shot_count=$2, uploaded_count=$3, note=$4 WHERE id=$5",
    [status, sc, uploadedCount, note, sessionRow.id]
  );

  return res.json({ ok: true, status, shot_count: sc, uploaded_count: uploadedCount });
});

// Health
app.get("/", (req, res) => res.send("OK"));

(async () => {
  try {
    await initDb();
    await seedAdminIfNeeded();
    app.listen(PORT, () => console.log(`✅ Server running on :${PORT}`));
  } catch (e) {
    console.error("Fatal:", e);
    process.exit(1);
  }
})();
