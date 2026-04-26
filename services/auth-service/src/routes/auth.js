// services/auth-service/src/routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { query } = require('../db');
const config = require('../config');
const { authenticate } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// ── REGISTER ──
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if email exists
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const hash = await bcrypt.hash(password, config.BCRYPT_ROUNDS);
    const id = crypto.randomUUID();

    await query(
      `INSERT INTO users (id, name, email, password_hash, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())`,
      [id, name.trim(), email.toLowerCase().trim(), hash]
    );

    // Generate tokens
    const accessToken = jwt.sign(
      { sub: id, email: email.toLowerCase(), role: 'user' },
      config.JWT.accessSecret,
      { expiresIn: config.JWT.accessTokenExpiry }
    );
    const refreshToken = jwt.sign(
      { sub: id, type: 'refresh' },
      config.JWT.refreshSecret,
      { expiresIn: config.JWT.refreshTokenExpiry }
    );

    res.status(201).json({
      user: { id, name, email: email.toLowerCase() },
      tokens: { accessToken, refreshToken },
    });
  } catch (err) {
    console.error(`[AUTH] Register error: ${err.code}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── LOGIN ──
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await query(
      'SELECT id, name, email, password_hash FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign(
      { sub: user.id, email: user.email, role: 'user' },
      config.JWT.accessSecret,
      { expiresIn: config.JWT.accessTokenExpiry }
    );
    const refreshToken = jwt.sign(
      { sub: user.id, type: 'refresh' },
      config.JWT.refreshSecret,
      { expiresIn: config.JWT.refreshTokenExpiry }
    );

    res.json({
      user: { id: user.id, name: user.name, email: user.email },
      tokens: { accessToken, refreshToken },
    });
  } catch (err) {
    console.error(`[AUTH] Login error: ${err.code}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── REFRESH TOKEN ──
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    const decoded = jwt.verify(refreshToken, config.JWT.refreshSecret);
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid token type' });
    }

    const result = await query('SELECT id, email FROM users WHERE id = $1', [decoded.sub]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    const newAccessToken = jwt.sign(
      { sub: user.id, email: user.email, role: 'user' },
      config.JWT.accessSecret,
      { expiresIn: config.JWT.accessTokenExpiry }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// ── GET PROFILE ──
router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, name, email, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;