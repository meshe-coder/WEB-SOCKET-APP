import express from "express";
import pg from "pg";
import dotenv from "dotenv";
import argon2 from "argon2";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { requireAuth } from "./auth.mjs";

dotenv.config();

const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const app = express();
const PORT = 3001;

app.use(express.json());
app.use(cookieParser());


// LOGIN
app.post("/api/auth/login", async (req, res) => {
  console.log("You are talking with the server");

  const { email, password } = req.body;

  const tableObject = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  const user = tableObject.rows[0];

  if (!user) {
    return res.status(401).json({
      message: "invalid credentials"
    });
  }

  const isValid = await argon2.verify(
    user.password_hash,
    password
  );

  if (!isValid) {
    return res.status(401).json({
      message: "invalid credentials"
    });
  }

  const sessionToken = crypto.randomBytes(32).toString("hex");

  await pool.query(
    "INSERT INTO sessions (session_token, user_id, expires_at) VALUES ($1, $2, $3)",
    [
      sessionToken,
      user.id,
      new Date(Date.now() + 24 * 60 * 60 * 1000)
    ]
  );

  res.cookie("session", sessionToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  });

  res.json({
    message: "login successful"
  });
});


// PROTECTED ROUTE
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: req.user
  });
});


// LOGOUT
app.post("/api/auth/logout", async (req, res) => {
  const sessionToken = req.cookies.session;

  if (sessionToken) {
    await pool.query(
      "DELETE FROM sessions WHERE session_token = $1",
      [sessionToken]
    );
  }

  res.clearCookie("session");

  res.json({
    message: "logout successful"
  });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
