// LexCommons — SSO Routes (Google + Microsoft)
const express    = require('express');
const passport   = require('passport');
const session    = require('express-session');
const { Pool }   = require('pg');
const jwt        = require('jsonwebtoken');
const GoogleStrategy   = require('passport-google-oauth20').Strategy;
const { OIDCStrategy } = require('passport-azure-ad');

const router = express.Router();
const pool   = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

const ALLOWED_ORIGINS = [
  'https://ops.lexcommons.org',
  'https://lawschoolcommons.com',
  'https://admin.lexcommons.org',
];

function safeRedirect(origin) {
  return ALLOWED_ORIGINS.includes(origin) ? origin : process.env.APP_URL;
}

router.use(session({
  secret: process.env.SESSION_SECRET || 'lc-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 10 * 60 * 1000 },
}));

router.use(passport.initialize());
router.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || false);
  } catch (e) { done(e); }
});

async function findOrCreateSsoUser(email, name, provider) {
  const parts = (name || '').split(' ');
  const first = parts[0] || '';
  const last = parts.slice(1).join(' ') || '';
  const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (existing.rows.length) {
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [existing.rows[0].id]);
    const u = existing.rows[0];
    return { ...u, name: [u.first_name, u.last_name].filter(Boolean).join(' ') };
  }
  const { rows } = await pool.query(
    `INSERT INTO users (first_name, last_name, email, role, active, password_hash, created_at)
     VALUES ($1, $2, $3, 1, 1, 'sso', NOW())
     RETURNING *`,
    [first, last, email]
  );
  const u = rows[0];
  return { ...u, name: [u.first_name, u.last_name].filter(Boolean).join(' ') };
}

// ── Google OAuth 2.0 ──────────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use('google', new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${process.env.APP_URL?.replace('ops.','api.')}/auth/google/callback`,
    passReqToCallback: true,
  }, async (req, accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      const name  = profile.displayName;
      if (!email) return done(new Error('No email from Google'));
      const user = await findOrCreateSsoUser(email, name, 'google');
      done(null, { ...user, _origin: req.session._sso_origin });
    } catch (e) { done(e); }
  }));

  router.get('/google', (req, res, next) => {
    const origin = req.query.origin || process.env.APP_URL;
    passport.authenticate('google', { scope: ['profile', 'email'], state: Buffer.from(origin).toString('base64') })(req, res, next);
  });

  router.get('/google/callback', passport.authenticate('google', { failureRedirect: `${process.env.APP_URL}?sso_error=google` }), (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, email: req.user.email, role: req.user.role, name: req.user.name || [req.user.first_name, req.user.last_name].filter(Boolean).join(' ') },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const origin = safeRedirect(req.query.state ? Buffer.from(req.query.state, 'base64').toString() : process.env.APP_URL);
    res.redirect(`${origin}?sso_token=${token}`);
  });
}

// ── Microsoft Azure AD / Entra ID ─────────────────────────────────────────────
if (process.env.MS_CLIENT_ID) {
  passport.use('azuread-openidconnect', new OIDCStrategy({
    identityMetadata: `https://login.microsoftonline.com/${process.env.MS_TENANT_ID || 'common'}/v2.0/.well-known/openid-configuration`,
    clientID:         process.env.MS_CLIENT_ID,
    clientSecret:     process.env.MS_CLIENT_SECRET,
    responseType:     'code',
    responseMode:     'query',
    redirectUrl:      `${process.env.APP_URL?.replace('ops.','api.')}/auth/microsoft/callback`,
    allowHttpForRedirectUrl: process.env.NODE_ENV !== 'production',
    scope:            ['profile', 'email', 'openid'],
    passReqToCallback: true,
  }, async (req, iss, sub, profile, accessToken, refreshToken, done) => {
    try {
      const email = profile._json?.email || profile._json?.preferred_username;
      const name  = profile.displayName || profile._json?.name;
      if (!email) return done(new Error('No email from Microsoft'));
      const user = await findOrCreateSsoUser(email, name, 'microsoft');
      done(null, { ...user, _origin: req.session._sso_origin });
    } catch (e) { done(e); }
  }));

  router.get('/microsoft', (req, res, next) => {
    req.session._sso_origin = req.query.origin || process.env.APP_URL;
    passport.authenticate('azuread-openidconnect', { failureRedirect: `${process.env.APP_URL}?sso_error=microsoft` })(req, res, next);
  });

  router.get('/microsoft/callback', passport.authenticate('azuread-openidconnect', { failureRedirect: `${process.env.APP_URL}?sso_error=microsoft` }), (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, email: req.user.email, role: req.user.role, name: req.user.name || [req.user.first_name, req.user.last_name].filter(Boolean).join(' ') },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const origin = safeRedirect(req.user._origin || req.session._sso_origin);
    res.redirect(`${origin}?sso_token=${token}`);
  });
}

// ── SSO status endpoint ───────────────────────────────────────────────────────
router.get('/status', (req, res) => {
  res.json({
    google:    !!process.env.GOOGLE_CLIENT_ID,
    microsoft: !!process.env.MS_CLIENT_ID,
  });
});

module.exports = router;
