// const express = require("express");
// const cors = require("cors");
// const multer = require("multer");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcryptjs");
// const { Pool } = require("pg");
// const cloudinary = require("cloudinary").v2;

// require("dotenv").config();

// const app = express();
// app.use(cors());
// app.use(express.json({ limit: "2mb" }));

// const PORT = process.env.PORT || 8080;

// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   ssl: process.env.DATABASE_URL?.includes("railway") ? { rejectUnauthorized: false } : undefined,
// });

// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET,
// });

// // Multer memory storage (upload thẳng Cloudinary)
// const upload = multer({
//   storage: multer.memoryStorage(),
//   limits: { fileSize: 12 * 1024 * 1024 },
// });

// // ===================== DB INIT =====================
// async function initDb() {
//   const client = await pool.connect();
//   try {
//     await client.query("BEGIN");

//     await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

//     await client.query(`
//       CREATE TABLE IF NOT EXISTS users (
//         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//         username TEXT UNIQUE NOT NULL,
//         password_hash TEXT NOT NULL,
//         created_at TIMESTAMPTZ NOT NULL DEFAULT now()
//       );
//     `);

//     await client.query(`
//       CREATE TABLE IF NOT EXISTS sessions (
//         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//         session_id TEXT UNIQUE NOT NULL,
//         user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//         device_id TEXT NOT NULL,
//         created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
//         status TEXT NOT NULL DEFAULT 'PENDING',
//         shot_count INT NOT NULL DEFAULT 0,
//         uploaded_count INT NOT NULL DEFAULT 0,
//         note TEXT
//       );
//     `);

//     // Optional debug column
//     await client.query(`
//       ALTER TABLE sessions
//       ADD COLUMN IF NOT EXISTS client_time_vn TEXT;
//     `);

//     // Add is_approved column for admin approval (gold coin icon)
//     await client.query(`
//       ALTER TABLE sessions
//       ADD COLUMN IF NOT EXISTS is_approved BOOLEAN NOT NULL DEFAULT false;
//     `);

//     await client.query(`
//       CREATE TABLE IF NOT EXISTS session_files (
//         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//         session_db_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
//         file_index INT NOT NULL,
//         cloudinary_url TEXT NOT NULL,
//         cloudinary_public_id TEXT NOT NULL,
//         created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
//         UNIQUE(session_db_id, file_index)
//       );
//     `);

//     await client.query(`
//       CREATE TABLE IF NOT EXISTS account_info (
//         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//         user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//         bank_account_number TEXT NOT NULL,
//         bank_account_name TEXT NOT NULL,
//         is_approved BOOLEAN NOT NULL DEFAULT false,
//         created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
//         updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
//       );
//     `);

//     await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`);
//     await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);`);
//     await client.query(`CREATE INDEX IF NOT EXISTS idx_account_info_user_id ON account_info(user_id);`);

//     await client.query("COMMIT");
//     console.log("✅ DB init ok");
//   } catch (e) {
//     await client.query("ROLLBACK");
//     console.error("❌ DB init failed:", e);
//     throw e;
//   } finally {
//     client.release();
//   }
// }

// // ===================== SEED ADMIN =====================
// async function seedAdminIfNeeded() {
//   const seed = (process.env.SEED_ADMIN ?? "true").toLowerCase() === "true";
//   if (!seed) {
//     console.log("ℹ️ SEED_ADMIN=false -> skip seeding admin");
//     return;
//   }

//   const adminUser = process.env.ADMIN_USERNAME || "admin";
//   const adminPass = process.env.ADMIN_PASSWORD || "123456";
//   const hash = await bcrypt.hash(adminPass, 10);

//   try {
//     const exist = await pool.query("SELECT id FROM users WHERE username=$1", [adminUser]);
//     if (exist.rowCount > 0) {
//       console.log(`ℹ️ Admin user '${adminUser}' already exists -> skip`);
//       return;
//     }

//     await pool.query("INSERT INTO users(username, password_hash) VALUES($1,$2)", [adminUser, hash]);
//     console.log(`✅ Seeded admin account: ${adminUser} / ${adminPass}`);
//   } catch (e) {
//     console.error("❌ Seed admin failed:", e);
//   }
// }

// // ===================== AUTH MIDDLEWARE =====================
// function auth(req, res, next) {
//   const h = req.headers.authorization || "";
//   const token = h.startsWith("Bearer ") ? h.slice(7) : null;
//   if (!token) return res.status(401).json({ error: "NO_TOKEN" });

//   try {
//     const payload = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = payload; // { userId, username }
//     next();
//   } catch (e) {
//     return res.status(401).json({ error: "INVALID_TOKEN" });
//   }
// }

// // ===================== HELPERS =====================
// function vnNowStringFull() {
//   // "YYYY-MM-DD HH:mm:ss" (sv-SE)
//   return new Date().toLocaleString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
// }

// function makeSessionId(deviceId) {
//   const s = vnNowStringFull(); // "2026-01-10 12:30:05"
//   const ts = s.replaceAll("-", "").replace(" ", "_").replaceAll(":", ""); // "20260110_123005"
//   return `${deviceId}_${ts}`;
// }

// // Parse client_time_vn ("YYYY-MM-DD HH:mm:ss") -> TIMESTAMPTZ using VN timezone
// function isValidClientTimeVn(s) {
//   return typeof s === "string" && /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s.trim());
// }

// // ===================== AUTH ROUTES =====================
// app.post("/api/auth/register", async (req, res) => {
//   const { username, password } = req.body || {};
//   if (!username || !password) return res.status(400).json({ error: "MISSING_FIELDS" });
//   if (String(password).length < 6) return res.status(400).json({ error: "WEAK_PASSWORD" });

//   const hash = await bcrypt.hash(password, 10);

//   try {
//     const r = await pool.query(
//       "INSERT INTO users(username, password_hash) VALUES($1,$2) RETURNING id, username, created_at",
//       [username, hash]
//     );
//     return res.json({ ok: true, user: r.rows[0] });
//   } catch (e) {
//     if (String(e.message).toLowerCase().includes("duplicate"))
//       return res.status(409).json({ error: "USERNAME_TAKEN" });
//     return res.status(500).json({ error: "SERVER_ERROR" });
//   }
// });

// app.post("/api/auth/login", async (req, res) => {
//   const { username, password } = req.body || {};
//   if (!username || !password) return res.status(400).json({ error: "MISSING_FIELDS" });

//   const r = await pool.query("SELECT id, username, password_hash FROM users WHERE username=$1", [username]);
//   if (r.rowCount === 0) return res.status(401).json({ error: "INVALID_CREDENTIALS" });

//   const u = r.rows[0];
//   const ok = await bcrypt.compare(password, u.password_hash);
//   if (!ok) return res.status(401).json({ error: "INVALID_CREDENTIALS" });

//   const token = jwt.sign({ userId: u.id, username: u.username }, process.env.JWT_SECRET, { expiresIn: "30d" });
//   return res.json({ ok: true, token, username: u.username });
// });

// app.get("/api/me", auth, async (req, res) => {
//   return res.json({ ok: true, user: { id: req.user.userId, username: req.user.username } });
// });

// // ===================== SESSION ROUTES =====================
// app.post("/api/session/start", auth, async (req, res) => {
//   const { device_id, client_time_vn } = req.body || {};
//   if (!device_id) return res.status(400).json({ error: "MISSING_DEVICE_ID" });

//   const sessionId = makeSessionId(device_id);

//   try {
//     if (isValidClientTimeVn(client_time_vn)) {
//       // created_at = client_time_vn interpreted as VN local time
//       await pool.query(
//         `
//         INSERT INTO sessions(session_id, user_id, device_id, created_at, client_time_vn, status, shot_count, uploaded_count)
//         VALUES(
//           $1, $2, $3,
//           ($4)::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh',
//           $4,
//           'PENDING', 0, 0
//         )
//         `,
//         [sessionId, req.user.userId, device_id, client_time_vn.trim()]
//       );
//     } else {
//       // fallback server now()
//       await pool.query(
//         `
//         INSERT INTO sessions(session_id, user_id, device_id, status, shot_count, uploaded_count)
//         VALUES($1,$2,$3,'PENDING',0,0)
//         `,
//         [sessionId, req.user.userId, device_id]
//       );
//     }

//     // Trả luôn created_at_vn để app có thể show ngay
//     const q = await pool.query(
//       `
//       SELECT
//         session_id,
//         to_char(created_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'FMYYYY-FMMM-FMDD HH24:MI:SS') AS created_at_vn
//       FROM sessions
//       WHERE session_id = $1
//       `,
//       [sessionId]
//     );

//     return res.json({
//       ok: true,
//       session_id: sessionId,
//       created_at_vn: q.rows?.[0]?.created_at_vn || null,
//     });
//   } catch (e) {
//     console.error(e);
//     return res.status(500).json({ error: "SERVER_ERROR" });
//   }
// });

// app.post("/api/session/:sessionId/upload", auth, upload.single("file"), async (req, res) => {
//   const sessionId = req.params.sessionId;
//   const deviceId = req.body.device_id;
//   const index = parseInt(req.body.index, 10);

//   if (!deviceId || !index || !req.file) return res.status(400).json({ error: "MISSING_FIELDS" });
//   if (index < 1 || index > 6) return res.status(400).json({ error: "INVALID_INDEX" });

//   const s = await pool.query("SELECT id, user_id, device_id FROM sessions WHERE session_id=$1", [sessionId]);
//   if (s.rowCount === 0) return res.status(404).json({ error: "SESSION_NOT_FOUND" });

//   const sessionRow = s.rows[0];
//   if (sessionRow.user_id !== req.user.userId) return res.status(403).json({ error: "FORBIDDEN" });
//   if (sessionRow.device_id !== deviceId) return res.status(400).json({ error: "DEVICE_MISMATCH" });

//   const folder = `sessions/${req.user.username}/${deviceId}/${sessionId}`;
//   const publicId = `${sessionId}_${String(index).padStart(2, "0")}`;

//   try {
//     const uploadRes = await new Promise((resolve, reject) => {
//       const stream = cloudinary.uploader.upload_stream(
//         { folder, public_id: publicId, resource_type: "image", overwrite: true },
//         (err, result) => (err ? reject(err) : resolve(result))
//       );
//       stream.end(req.file.buffer);
//     });

//     await pool.query("BEGIN");

//     await pool.query(
//       `INSERT INTO session_files(session_db_id, file_index, cloudinary_url, cloudinary_public_id)
//        VALUES($1,$2,$3,$4)
//        ON CONFLICT (session_db_id, file_index)
//        DO UPDATE SET cloudinary_url=EXCLUDED.cloudinary_url, cloudinary_public_id=EXCLUDED.cloudinary_public_id`,
//       [sessionRow.id, index, uploadRes.secure_url, uploadRes.public_id]
//     );

//     const c = await pool.query(
//       "SELECT COUNT(*)::int AS cnt FROM session_files WHERE session_db_id=$1",
//       [sessionRow.id]
//     );
//     const uploadedCount = c.rows[0].cnt;

//     await pool.query("UPDATE sessions SET uploaded_count=$1 WHERE id=$2", [uploadedCount, sessionRow.id]);
//     await pool.query("COMMIT");

//     return res.json({
//       ok: true,
//       index,
//       file_url: uploadRes.secure_url,
//       public_id: uploadRes.public_id,
//       uploaded_count: uploadedCount,
//     });
//   } catch (e) {
//     await pool.query("ROLLBACK").catch(() => {});
//     console.error(e);
//     return res.status(500).json({ error: "UPLOAD_FAILED" });
//   }
// });

// app.post("/api/session/:sessionId/end", auth, async (req, res) => {
//   const sessionId = req.params.sessionId;
//   const { device_id, shot_count } = req.body || {};
//   const sc = parseInt(shot_count, 10);

//   if (!device_id || !sc) return res.status(400).json({ error: "MISSING_FIELDS" });
//   if (sc < 5 || sc > 6) return res.status(400).json({ error: "INVALID_SHOT_COUNT" });

//   const s = await pool.query("SELECT id, user_id, device_id FROM sessions WHERE session_id=$1", [sessionId]);
//   if (s.rowCount === 0) return res.status(404).json({ error: "SESSION_NOT_FOUND" });

//   const sessionRow = s.rows[0];
//   if (sessionRow.user_id !== req.user.userId) return res.status(403).json({ error: "FORBIDDEN" });
//   if (sessionRow.device_id !== device_id) return res.status(400).json({ error: "DEVICE_MISMATCH" });

//   const c = await pool.query(
//     "SELECT COUNT(*)::int AS cnt FROM session_files WHERE session_db_id=$1",
//     [sessionRow.id]
//   );
//   const uploadedCount = c.rows[0].cnt;

//   let status = "PENDING";
//   let note = null;

//   if (uploadedCount >= sc) status = "SUCCESS";
//   else note = `Uploaded ${uploadedCount}/${sc}`;

//   await pool.query(
//     "UPDATE sessions SET status=$1, shot_count=$2, uploaded_count=$3, note=$4 WHERE id=$5",
//     [status, sc, uploadedCount, note, sessionRow.id]
//   );

//   return res.json({ ok: true, status, shot_count: sc, uploaded_count: uploadedCount });
// });

// // ===================== LIST SESSIONS FOR DASHBOARD =====================
// // ✅ Ẩn created_at cũ, chỉ trả created_at_vn
// // ✅ Sort chuẩn theo created_at DESC (mới nhất lên đầu)
// app.get("/api/sessions", auth, async (req, res) => {
//   const limit = Math.min(parseInt(req.query.limit || "50", 10), 200);

//   try {
//     const r = await pool.query(
//       `
//       SELECT
//         s.session_id,
//         to_char((s.created_at AT TIME ZONE 'Asia/Ho_Chi_Minh'), 'YYYY-FMMM-FMDD HH24:MI:SS') AS created_at_vn,
//         s.status,
//         s.shot_count,
//         s.uploaded_count,
//         s.is_approved
//       FROM sessions s
//       WHERE s.user_id = $1
//       ORDER BY s.created_at DESC
//       LIMIT $2
//       `,
//       [req.user.userId, limit]
//     );

//     return res.json({
//       ok: true,
//       sessions: r.rows.map((row) => ({
//         session_id: row.session_id,
//         created_at_vn: row.created_at_vn,
//         shot_count: row.shot_count,
//         uploaded_count: row.uploaded_count,
//         status: row.status,
//         // is_approved: boolean from database (true/false)
//         // When admin sets is_approved=true in DB, this will be true
//         // App will show 🪙 icon when is_approved=true
//         is_approved: Boolean(row.is_approved), // Explicit boolean conversion
//       })),
//     });
//   } catch (e) {
//     console.error(e);
//     return res.status(500).json({ error: "SERVER_ERROR" });
//   }
// });

// // ===================== ACCOUNT INFO ROUTES =====================
// // GET account info - returns 404 if not found
// app.get("/api/account/info", auth, async (req, res) => {
//   try {
//     const r = await pool.query(
//       "SELECT bank_account_number, bank_account_name, is_approved FROM account_info WHERE user_id = $1",
//       [req.user.userId]
//     );

//     if (r.rowCount === 0) {
//       return res.status(404).json({ error: "ACCOUNT_INFO_NOT_FOUND" });
//     }

//     const info = r.rows[0];
//     return res.json({
//       ok: true,
//       bank_account_number: info.bank_account_number,
//       bank_account_name: info.bank_account_name,
//       is_approved: info.is_approved,
//     });
//   } catch (e) {
//     console.error(e);
//     return res.status(500).json({ error: "SERVER_ERROR" });
//   }
// });

// // POST account info - creates or updates (UPSERT)
// app.post("/api/account/info", auth, async (req, res) => {
//   const { bank_account_number, bank_account_name } = req.body || {};

//   if (!bank_account_number || !bank_account_name) {
//     return res.status(400).json({ error: "MISSING_FIELDS" });
//   }

//   // Validate: account number should be numeric
//   if (!/^\d+$/.test(String(bank_account_number).trim())) {
//     return res.status(400).json({ error: "INVALID_ACCOUNT_NUMBER" });
//   }

//   // Validate: account name should not be empty
//   if (String(bank_account_name).trim().length === 0) {
//     return res.status(400).json({ error: "INVALID_ACCOUNT_NAME" });
//   }

//   try {
//     // UPSERT: Insert or update
//     const r = await pool.query(
//       `
//       INSERT INTO account_info(user_id, bank_account_number, bank_account_name, updated_at)
//       VALUES($1, $2, $3, now())
//       ON CONFLICT (user_id)
//       DO UPDATE SET
//         bank_account_number = EXCLUDED.bank_account_number,
//         bank_account_name = EXCLUDED.bank_account_name,
//         updated_at = now()
//       RETURNING bank_account_number, bank_account_name, is_approved
//       `,
//       [req.user.userId, String(bank_account_number).trim(), String(bank_account_name).trim()]
//     );

//     const info = r.rows[0];
//     return res.json({
//       ok: true,
//       bank_account_number: info.bank_account_number,
//       bank_account_name: info.bank_account_name,
//       is_approved: info.is_approved,
//     });
//   } catch (e) {
//     console.error(e);
//     return res.status(500).json({ error: "SERVER_ERROR" });
//   }
// });

// // Health
// app.get("/", (req, res) => res.send("OK"));

// (async () => {
//   try {
//     await initDb();
//     await seedAdminIfNeeded();
//     app.listen(PORT, () => console.log(`✅ Server running on :${PORT}`));
//   } catch (e) {
//     console.error("Fatal:", e);
//     process.exit(1);
//   }
// })();

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

// ===================== DB INIT (CLEAN ADMIN-FRIENDLY) =====================
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    // users table (giữ nguyên)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // reset schema (CHỈ khi bạn chủ động bật)
    const reset = String(process.env.RESET_DB || "false").toLowerCase() === "true";
    if (reset) {
      console.log("⚠️ RESET_DB=true -> drop & rebuild sessions/session_files/account_info...");
      await client.query(`DROP VIEW IF EXISTS admin_sessions_overview;`);
      await client.query(`DROP TRIGGER IF EXISTS trg_sync_uploaded_count ON session_files;`).catch(() => {});
      await client.query(`DROP FUNCTION IF EXISTS sync_uploaded_count;`).catch(() => {});
      await client.query(`DROP TABLE IF EXISTS session_files;`);
      await client.query(`DROP TABLE IF EXISTS sessions;`);
      await client.query(`DROP TABLE IF EXISTS account_info;`);
      await client.query(`DROP TYPE IF EXISTS session_status;`);
    }

    // status enum cho sessions (admin nhìn rõ ràng)
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_status') THEN
          CREATE TYPE session_status AS ENUM ('PENDING', 'SUCCESS', 'FAILED');
        END IF;
      END$$;
    `);

    // sessions: gọn gàng, đủ cho admin
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id TEXT UNIQUE NOT NULL,

        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,

        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- vẫn giữ tên created_at để không sửa API nhiều
        client_time_vn TEXT, -- optional debug: "YYYY-MM-DD HH:mm:ss"

        status session_status NOT NULL DEFAULT 'PENDING',
        shot_count INT NOT NULL DEFAULT 0 CHECK (shot_count BETWEEN 0 AND 6),
        uploaded_count INT NOT NULL DEFAULT 0 CHECK (uploaded_count >= 0),

        note TEXT,

        is_approved BOOLEAN NOT NULL DEFAULT false,
        approved_at TIMESTAMPTZ
      );
    `);

    // đảm bảo các cột cần thiết tồn tại (nếu DB đã có bảng cũ)
    await client.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_time_vn TEXT;`);
    await client.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_approved BOOLEAN NOT NULL DEFAULT false;`);
    await client.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;`);

    // ép kiểu status về enum nếu bảng cũ đang TEXT (an toàn)
    // nếu đã enum thì không làm gì
    await client.query(`
      DO $$
      BEGIN
        -- Nếu status đang là TEXT (thường gặp bản cũ)
        IF EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_name='sessions'
            AND column_name='status'
            AND data_type='text'
        ) THEN
          ALTER TABLE sessions
          ALTER COLUMN status TYPE session_status
          USING (CASE
            WHEN upper(status) LIKE '%SUCCESS%' THEN 'SUCCESS'::session_status
            WHEN upper(status) LIKE '%FAIL%' THEN 'FAILED'::session_status
            ELSE 'PENDING'::session_status
          END);
        END IF;
      END$$;
    `);

    // session_files: rõ ràng hơn (uploaded_at)
    await client.query(`
      CREATE TABLE IF NOT EXISTS session_files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_db_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,

        file_index INT NOT NULL CHECK (file_index BETWEEN 1 AND 6),

        cloudinary_url TEXT NOT NULL,
        cloudinary_public_id TEXT NOT NULL,

        uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),

        UNIQUE(session_db_id, file_index)
      );
    `);

    // nếu bảng cũ có created_at, giữ lại nhưng thêm uploaded_at để chuẩn hoá
    await client.query(`ALTER TABLE session_files ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now();`);

    // account_info: thêm approved_at
    await client.query(`
      CREATE TABLE IF NOT EXISTS account_info (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,

        bank_account_number TEXT NOT NULL,
        bank_account_name TEXT NOT NULL,

        is_approved BOOLEAN NOT NULL DEFAULT false,
        approved_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await client.query(`ALTER TABLE account_info ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;`);

    // indexes
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_session_files_session_db_id ON session_files(session_db_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_account_info_user_id ON account_info(user_id);`);

    // Trigger sync uploaded_count (đỡ rối admin, luôn đúng)
    await client.query(`
      CREATE OR REPLACE FUNCTION sync_uploaded_count() RETURNS trigger AS $$
      DECLARE sid UUID;
      BEGIN
        sid := COALESCE(NEW.session_db_id, OLD.session_db_id);

        UPDATE sessions s
        SET uploaded_count = (
          SELECT COUNT(*) FROM session_files f WHERE f.session_db_id = sid
        )
        WHERE s.id = sid;

        RETURN NULL;
      END;
      $$ LANGUAGE plpgsql;
    `);

    await client.query(`DROP TRIGGER IF EXISTS trg_sync_uploaded_count ON session_files;`);
    await client.query(`
      CREATE TRIGGER trg_sync_uploaded_count
      AFTER INSERT OR UPDATE OR DELETE ON session_files
      FOR EACH ROW EXECUTE FUNCTION sync_uploaded_count();
    `);

    // View admin nhìn 1 phát hiểu ngay
    await client.query(`
      CREATE OR REPLACE VIEW admin_sessions_overview AS
      SELECT
        u.username,
        s.session_id,
        s.device_id,

        to_char((s.created_at AT TIME ZONE 'Asia/Ho_Chi_Minh'), 'YYYY-MM-DD HH24:MI:SS') AS created_at_vn,
        s.client_time_vn,

        s.shot_count,
        s.uploaded_count,
        (s.shot_count - s.uploaded_count) AS missing_count,

        s.status,
        s.is_approved,
        CASE WHEN s.approved_at IS NULL THEN NULL
             ELSE to_char((s.approved_at AT TIME ZONE 'Asia/Ho_Chi_Minh'), 'YYYY-MM-DD HH24:MI:SS')
        END AS approved_at_vn,

        s.note
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      ORDER BY s.created_at DESC;
    `);

    await client.query("COMMIT");
    console.log("✅ DB init ok (clean admin-friendly)");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("❌ DB init failed:", e);
    throw e;
  } finally {
    client.release();
  }
}

// ===================== SEED ADMIN =====================
async function seedAdminIfNeeded() {
  const seed = (process.env.SEED_ADMIN ?? "true").toLowerCase() === "true";
  if (!seed) {
    console.log("ℹ️ SEED_ADMIN=false -> skip seeding admin");
    return;
  }

  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "123456";
  const hash = await bcrypt.hash(adminPass, 10);

  try {
    const exist = await pool.query("SELECT id FROM users WHERE username=$1", [adminUser]);
    if (exist.rowCount > 0) {
      console.log(`ℹ️ Admin user '${adminUser}' already exists -> skip`);
      return;
    }

    await pool.query("INSERT INTO users(username, password_hash) VALUES($1,$2)", [adminUser, hash]);
    console.log(`✅ Seeded admin account: ${adminUser} / ${adminPass}`);
  } catch (e) {
    console.error("❌ Seed admin failed:", e);
  }
}

// ===================== AUTH MIDDLEWARE =====================
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

// ===================== HELPERS =====================
function vnNowStringFull() {
  return new Date().toLocaleString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
}

function makeSessionId(deviceId) {
  const s = vnNowStringFull(); // "2026-01-10 12:30:05"
  const ts = s.replaceAll("-", "").replace(" ", "_").replaceAll(":", "");
  return `${deviceId}_${ts}`;
}

function isValidClientTimeVn(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s.trim());
}

// ===================== AUTH ROUTES =====================
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

// ===================== SESSION ROUTES =====================
app.post("/api/session/start", auth, async (req, res) => {
  const { device_id, client_time_vn } = req.body || {};
  if (!device_id) return res.status(400).json({ error: "MISSING_DEVICE_ID" });

  const sessionId = makeSessionId(device_id);

  try {
    if (isValidClientTimeVn(client_time_vn)) {
      await pool.query(
        `
        INSERT INTO sessions(session_id, user_id, device_id, created_at, client_time_vn, status, shot_count, uploaded_count)
        VALUES(
          $1, $2, $3,
          ($4)::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh',
          $4,
          'PENDING', 0, 0
        )
        `,
        [sessionId, req.user.userId, device_id, client_time_vn.trim()]
      );
    } else {
      await pool.query(
        `
        INSERT INTO sessions(session_id, user_id, device_id, status, shot_count, uploaded_count)
        VALUES($1,$2,$3,'PENDING',0,0)
        `,
        [sessionId, req.user.userId, device_id]
      );
    }

    const q = await pool.query(
      `
      SELECT
        session_id,
        to_char(created_at AT TIME ZONE 'Asia/Ho_Chi_Minh', 'FMYYYY-FMMM-FMDD HH24:MI:SS') AS created_at_vn
      FROM sessions
      WHERE session_id = $1
      `,
      [sessionId]
    );

    return res.json({
      ok: true,
      session_id: sessionId,
      created_at_vn: q.rows?.[0]?.created_at_vn || null,
    });
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

    // uploaded_count sẽ được trigger tự sync, nhưng mình vẫn trả count cho client
    const c = await pool.query(
      "SELECT COUNT(*)::int AS cnt FROM session_files WHERE session_db_id=$1",
      [sessionRow.id]
    );
    const uploadedCount = c.rows[0].cnt;

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
    "UPDATE sessions SET status=$1, shot_count=$2, note=$3 WHERE id=$4",
    [status, sc, note, sessionRow.id]
  );

  return res.json({ ok: true, status, shot_count: sc, uploaded_count: uploadedCount });
});

// ===================== LIST SESSIONS FOR DASHBOARD =====================
app.get("/api/sessions", auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "50", 10), 200);

  try {
    const r = await pool.query(
      `
      SELECT
        s.session_id,
        to_char((s.created_at AT TIME ZONE 'Asia/Ho_Chi_Minh'), 'YYYY-FMMM-FMDD HH24:MI:SS') AS created_at_vn,
        s.status,
        s.shot_count,
        s.uploaded_count,
        s.is_approved
      FROM sessions s
      WHERE s.user_id = $1
      ORDER BY s.created_at DESC
      LIMIT $2
      `,
      [req.user.userId, limit]
    );

    return res.json({
      ok: true,
      sessions: r.rows.map((row) => ({
        session_id: row.session_id,
        created_at_vn: row.created_at_vn,
        shot_count: row.shot_count,
        uploaded_count: row.uploaded_count,
        status: row.status,
        is_approved: Boolean(row.is_approved),
      })),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===================== ACCOUNT INFO ROUTES =====================
app.get("/api/account/info", auth, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT bank_account_number, bank_account_name, is_approved FROM account_info WHERE user_id = $1",
      [req.user.userId]
    );

    if (r.rowCount === 0) {
      return res.status(404).json({ error: "ACCOUNT_INFO_NOT_FOUND" });
    }

    const info = r.rows[0];
    return res.json({
      ok: true,
      bank_account_number: info.bank_account_number,
      bank_account_name: info.bank_account_name,
      is_approved: info.is_approved,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/account/info", auth, async (req, res) => {
  const { bank_account_number, bank_account_name } = req.body || {};

  if (!bank_account_number || !bank_account_name) {
    return res.status(400).json({ error: "MISSING_FIELDS" });
  }

  if (!/^\d+$/.test(String(bank_account_number).trim())) {
    return res.status(400).json({ error: "INVALID_ACCOUNT_NUMBER" });
  }

  if (String(bank_account_name).trim().length === 0) {
    return res.status(400).json({ error: "INVALID_ACCOUNT_NAME" });
  }

  try {
    const r = await pool.query(
      `
      INSERT INTO account_info(user_id, bank_account_number, bank_account_name, updated_at)
      VALUES($1, $2, $3, now())
      ON CONFLICT (user_id)
      DO UPDATE SET
        bank_account_number = EXCLUDED.bank_account_number,
        bank_account_name = EXCLUDED.bank_account_name,
        updated_at = now()
      RETURNING bank_account_number, bank_account_name, is_approved
      `,
      [req.user.userId, String(bank_account_number).trim(), String(bank_account_name).trim()]
    );

    const info = r.rows[0];
    return res.json({
      ok: true,
      bank_account_number: info.bank_account_number,
      bank_account_name: info.bank_account_name,
      is_approved: info.is_approved,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
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


