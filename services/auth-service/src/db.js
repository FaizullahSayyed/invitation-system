// services/auth-service/src/db.js
const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({
  host: config.DB.host,
  port: config.DB.port,
  user: config.DB.user,
  password: config.DB.password,
  database: config.DB.database,
  ssl: config.DB.ssl ? { rejectUnauthorized: false } : false,
  max: config.DB.max,
  idleTimeoutMillis: config.DB.idleTimeoutMillis,
  connectionTimeoutMillis: config.DB.connectionTimeoutMillis,
});

// Prevent leaking password in error logs
pool.on('error', (err) => {
  // Log error WITHOUT password details
  console.error(`[DB ERROR] Connection error: ${err.code || 'UNKNOWN'}`);
});

// Sanitize — remove password from config stringification
pool._getConfigSafe = () => ({
  host: config.DB.host,
  port: config.DB.port,
  user: config.DB.user,
  database: config.DB.database,
  max: config.DB.max,
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};