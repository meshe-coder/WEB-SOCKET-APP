import pg from "pg";
import dotenv from "dotenv";
dotenv.config();
const pool = new pg.Pool({
    user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
async function requireAuth(req, res, next) {
  const sessionToken = req.cookies.session;

  if (!sessionToken) {
    return res.status(401).json({
      message: "Not authenticated"
    });
  }

  const result = await pool.query(
    "SELECT * FROM sessions WHERE session_token = $1",
    [sessionToken]
  );

  const session = result.rows[0];

  if (!session) {
    return res.status(401).json({
      message: "Invalid session"
    });
  }

  if (new Date(session.expires_at) < new Date()) {
    return res.status(401).json({
      message: "Session expired"
    });
  }

  const userResult = await pool.query(
    "SELECT id, name, email FROM users WHERE id = $1",
    [session.user_id]
  );

  const user = userResult.rows[0];

  if (!user) {
    return res.status(401).json({
      message: "User not found"
    });
  }

  req.user = user;

  next();
}
