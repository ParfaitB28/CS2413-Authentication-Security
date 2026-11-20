
const { rateLimit } = require('express-rate-limit');

// Limit each IP address to 10 login attempts per minute.
const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts. Please try again later.'
  }
});

module.exports = { loginRateLimiter };
