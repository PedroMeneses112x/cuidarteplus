const { Pool } = require("pg");
require("dotenv").config();

if (!process.env.DATABASE_URL) {
  throw new Error("FATAL: La variable de entorno DATABASE_URL no está definida.");
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

module.exports = { pool };