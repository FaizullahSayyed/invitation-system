// services/auth-service/src/index.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const config = require('./config');
const { generalLimiter } = require('./middleware/rateLimiter');
const authRoutes = require('./routes/auth');

const app = express();

// ── Security Middleware ──
app.use(helmet({
  contentSecurityPolicy: false, // API-only, no HTML
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '10kb' })); // Prevent large payloads
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(generalLimiter);

// ── Routes ──
app.use('/api/auth', authRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth-service', version: '0.2.0' });
});

// ── Global Error Handler ──
app.use((err, req, res, _next) => {
  // Never leak error details in production
  if (process.env.NODE_ENV === 'production') {
    console.error(`[ERROR] ${err.message}`);
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

app.listen(config.PORT, '0.0.0.0', () => {
  console.log(`[AUTH] Running on port ${config.PORT}`);
});