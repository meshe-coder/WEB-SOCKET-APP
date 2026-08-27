import pg from "pg";
import argon2 from "argon2";
import dotenv from "dotenv";
dotenv.config();
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
const hash = await argon2.hash("meshack");
console.log(hash);
pool.query("UPDATE users SET password_hash = $1 WHERE id = 5", [hash])
