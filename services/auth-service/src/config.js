// services/auth-service/src/config.js
const dotenv = require('dotenv');
dotenv.config();

module.exports = {
  PORT: process.env.AUTH_PORT || 3001,
  DB: {
    host: process.env.AUTH_DB_HOST || 'auth-db',
    port: parseInt(process.env.AUTH_DB_PORT, 10) || 5432,
    user: process.env.AUTH_DB_USER,
    password: process.env.AUTH_DB_PASSWORD,
    database: process.env.AUTH_DB_NAME || 'auth_db',
    ssl: process.env.DB_SSL === 'true',
    // Connection pool — prevents connection exhaustion
    max: parseInt(process.env.DB_POOL_MAX, 10) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  },
  JWT: {
    accessSecret: process.env.JWT_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  },
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
};