/**
 * BrainSpark AI — Backend Server v5.0
 * Node.js + Express + Claude AI + OpenAI + Groq (fallback chain)
 *
 * INSTALL:
 *   npm install express cors bcryptjs jsonwebtoken express-rate-limit
 *              helmet morgan @supabase/supabase-js @anthropic-ai/sdk
 *              google-auth-library razorpay nodemailer crypto dotenv
 *              openai groq-sdk multer csv-parser
 *
 * NEW ENV VARS (add to .env):
 *   OPENAI_API_KEY=sk-...
 *   GROQ_API_KEY=gsk_...
 *   SUPABASE_STORAGE_BUCKET=brainspark-media
 */

const express          = require('express');
const cors             = require('cors');
const bcrypt           = require('bcryptjs');
const jwt              = require('jsonwebtoken');
const rateLimit        = require('express-rate-limit');
const helmet           = require('helmet');
const morgan           = require('morgan');
const { createClient } = require('@supabase/supabase-js');
const Anthropic        = require('@anthropic-ai/sdk');
const OpenAI           = require('openai');
const Groq             = require('groq-sdk');
const { OAuth2Client } = require('google-auth-library');
const Razorpay         = require('razorpay');
const nodemailer       = require('nodemailer');
const crypto           = require('crypto');
const multer           = require('multer');
const csv              = require('csv-parser');
const stream           = require('stream');
let YoutubeTranscript;
try {
  ({ YoutubeTranscript } = require('youtube-transcript'));
} catch (e) {
  console.warn('[youtube-transcript] package not found — transcript features disabled');
  YoutubeTranscript = null;
}
require('dotenv').config();

// ════════════════════════════════════════════════════════════════
//  App & Middleware
// ════════════════════════════════════════════════════════════════
const app  = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(morgan('dev'));
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    const allowed = [process.env.FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5173'];
    const ok = allowed.includes(origin) || origin.includes('vercel.app') || origin.includes('netlify.app');
    cb(ok ? null : new Error('CORS blocked'), ok);
  },
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 400 });
const aiLimiter     = rateLimit({ windowMs: 15 * 60 * 1000, max: 80, message: { error: 'AI rate limit reached. Please wait.' } });
app.use(globalLimiter);

// ════════════════════════════════════════════════════════════════
//  Service Clients
// ════════════════════════════════════════════════════════════════
const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

const groq = process.env.GROQ_API_KEY
  ? new Groq({ apiKey: process.env.GROQ_API_KEY }) : null;

const googleAuth = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const razorpay = process.env.RAZORPAY_KEY_ID
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const mailer = process.env.EMAIL_USER
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } })
  : null;

// Multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
    cb(null, allowed.includes(file.mimetype));
  },
});
const uploadCSV = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// ════════════════════════════════════════════════════════════════
//  AI — Anthropic → OpenAI → Groq (fallback chain)
// ════════════════════════════════════════════════════════════════
const MODEL_TIER = {
  doubt:      'claude-haiku-4-5-20251001',
  flashcards: 'claude-haiku-4-5-20251001',
  buddy:      'claude-haiku-4-5-20251001',
  quiz:       'claude-sonnet-4-6',
  notes:      'claude-sonnet-4-6',
  paper:      'claude-sonnet-4-6',
  cheatsheet: 'claude-sonnet-4-6',
  lessonplan: 'claude-sonnet-4-6',
};

async function callAI(messages, system = '', maxTokens = 2000, tool = 'default') {
  const claudeModel = MODEL_TIER[tool] || 'claude-sonnet-4-6';

  // 1. Try Anthropic (Claude) — primary
  try {
    const response = await anthropic.messages.create({
      model:      claudeModel,
      max_tokens: Math.min(maxTokens, 8096),
      system:     system || undefined,
      messages:   messages.map(m => ({
        role:    m.role === 'assistant' ? 'assistant' : 'user',
        content: m.content,
      })),
    });
    const text = response.content[0].text;
    return { text: text.replace(/```[\w]*\n?/gi, '').trim(), provider: 'claude' };
  } catch (e) {
    console.warn('[Claude failed, trying OpenAI]', e.message?.slice(0, 80));
  }

  // 2. Try OpenAI — fallback 1
  if (openai) {
    try {
      const msgs = [];
      if (system) msgs.push({ role: 'system', content: system });
      msgs.push(...messages.map(m => ({
        role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content,
      })));
      const r = await openai.chat.completions.create({
        model: 'gpt-4o-mini', max_tokens: Math.min(maxTokens, 4096), messages: msgs,
      });
      return { text: r.choices[0].message.content.trim(), provider: 'openai' };
    } catch (e) {
      console.warn('[OpenAI failed, trying Groq]', e.message?.slice(0, 80));
    }
  }

  // 3. Try Groq — fallback 2
  if (groq) {
    const msgs = [];
    if (system) msgs.push({ role: 'system', content: system });
    msgs.push(...messages.map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content,
    })));
    const r = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile', max_tokens: Math.min(maxTokens, 4096), messages: msgs,
    });
    return { text: r.choices[0].message.content.trim(), provider: 'groq' };
  }

  throw new Error('All AI providers failed. Please try again.');
}

// ════════════════════════════════════════════════════════════════
//  Auth Helpers
// ════════════════════════════════════════════════════════════════
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });
}

async function createSession(userId, deviceInfo = {}) {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  await db.from('user_sessions').update({ is_active: false }).eq('user_id', userId);
  await db.from('user_sessions').insert({
    user_id: userId, session_token: sessionToken,
    device_info: deviceInfo, ip_address: deviceInfo.ip || null,
    user_agent: deviceInfo.userAgent || null, is_active: true,
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  });
  return sessionToken;
}

async function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  const stok = req.headers['x-session-token'];
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
  if (stok) {
    const { data: sess } = await db.from('user_sessions')
      .select('id').eq('user_id', req.user.id).eq('session_token', stok).eq('is_active', true).maybeSingle();
    if (!sess) return res.status(401).json({ error: 'Signed in on another device.', code: 'SESSION_REPLACED' });
    await db.from('user_sessions').update({ last_seen_at: new Date().toISOString() })
      .eq('user_id', req.user.id).eq('session_token', stok);
  }
  next();
}

function verifyAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_SECRET_KEY) return res.status(403).json({ error: 'Admin required' });
  next();
}

// ════════════════════════════════════════════════════════════════
//  FREE TIER — Wall-clock 10 minutes from first AI call
// ════════════════════════════════════════════════════════════════
const FREE_WINDOW_SECONDS = 600; // 10 minutes

async function checkAccess(req, res, next) {
  // ── FREE ACCESS MODE — all users pass through ──
  // Uncomment the block below to re-enable the free trial wall:
  /*
  if (req.user.type === 'school') return next();

  const { data: u } = await db.from('users')
    .select('subscription_status, subscription_expires_at, free_tier_started_at')
    .eq('id', req.user.id).single();

  if (u?.subscription_status === 'active' && u.subscription_expires_at && new Date(u.subscription_expires_at) > new Date()) {
    return next();
  }

  if (!u?.free_tier_started_at) {
    await db.from('users')
      .update({ free_tier_started_at: new Date().toISOString() })
      .eq('id', req.user.id);
    req.freeSecondsRemaining = FREE_WINDOW_SECONDS;
    return next();
  }

  const elapsed   = Math.floor((Date.now() - new Date(u.free_tier_started_at)) / 1000);
  const remaining = FREE_WINDOW_SECONDS - elapsed;

  if (remaining <= 0) {
    return res.status(402).json({
      error:            'Your 10-minute free trial has ended.',
      code:             'SUBSCRIPTION_REQUIRED',
      secondsRemaining: 0,
    });
  }

  req.freeSecondsRemaining = remaining;
  */
  return next();
}

// ════════════════════════════════════════════════════════════════
//  DB Helpers
// ════════════════════════════════════════════════════════════════
async function ensureXPRecord(userId) {
  await db.from('user_xp').upsert({ user_id: userId }, { onConflict: 'user_id', ignoreDuplicates: true });
}

async function logActivity(userId, tool, opts = {}) {
  const { subject = '', chapter = '', chapters = [], xpEarned = 0, meta = {}, provider = '' } = opts;
  try {
    await db.from('activity_log').insert({
      user_id: userId, tool, subject, chapter, chapters,
      xp_earned: xpEarned, ai_provider: provider, metadata: meta,
    });
    await db.rpc('increment_xp',  { p_user_id: userId, p_amount: xpEarned });
    await db.rpc('update_streak', { p_user_id: userId });
    const counters = {
      doubt: 'doubts_solved', quiz: 'quizzes_done', notes: 'notes_made',
      paper: 'papers_made',   flashcards: 'flashcards_made',
      cheatsheet: 'cheat_sheets_made', lessonplan: 'lesson_plans_made',
    };
    if (counters[tool]) await db.rpc('increment_counter', { p_user_id: userId, p_field: counters[tool] });
    const hour = new Date().getHours();
    if (hour >= 22) await db.from('user_xp').update({ night_owl_unlocked: true }).eq('user_id', userId).eq('night_owl_unlocked', false);
    if (hour < 7)   await db.from('user_xp').update({ early_bird_unlocked: true }).eq('user_id', userId).eq('early_bird_unlocked', false);
    const today = new Date().toISOString().split('T')[0];
    const { data: xpRow } = await db.from('user_xp').select('tools_used_today, tools_used_today_date, subjects_used').eq('user_id', userId).single();
    if (xpRow) {
      const sameDay  = xpRow.tools_used_today_date === today;
      const tools    = [...new Set([...(sameDay ? xpRow.tools_used_today || [] : []), tool])];
      const subjects = [...new Set([...(xpRow.subjects_used || []), ...(subject ? [subject] : [])])];
      await db.from('user_xp').update({ tools_used_today: tools, tools_used_today_date: today, subjects_used: subjects }).eq('user_id', userId);
    }
    checkAchievements(userId).catch(() => {});
  } catch (e) { console.error('[logActivity]', e.message); }
}

async function checkAchievements(userId) {
  const [{ data: stats }, { data: user }, { data: all }, { data: unlocked }] = await Promise.all([
    db.from('user_xp').select('*').eq('user_id', userId).single(),
    db.from('users').select('login_count').eq('id', userId).single(),
    db.from('achievements').select('*'),
    db.from('user_achievements').select('achievement_id').eq('user_id', userId),
  ]);
  if (!stats || !all) return;
  const done = new Set((unlocked || []).map(a => a.achievement_id));
  const toUnlock = [];
  for (const ach of all) {
    if (done.has(ach.id)) continue;
    let ok = false;
    const v = ach.condition_value;
    switch (ach.condition_type) {
      case 'xp':              ok = stats.total_xp          >= v; break;
      case 'streak':          ok = stats.current_streak    >= v; break;
      case 'doubts':          ok = stats.doubts_solved     >= v; break;
      case 'quizzes':         ok = stats.quizzes_done      >= v; break;
      case 'quizzes_perfect': ok = stats.quizzes_perfect   >= v; break;
      case 'notes':           ok = stats.notes_made        >= v; break;
      case 'papers':          ok = stats.papers_made       >= v; break;
      case 'flashcards':      ok = stats.flashcards_made   >= v; break;
      case 'cheat_sheets':    ok = stats.cheat_sheets_made >= v; break;
      case 'lesson_plans':    ok = stats.lesson_plans_made >= v; break;
      case 'login_count':     ok = (user?.login_count || 0) >= v; break;
      case 'night_owl':       ok = stats.night_owl_unlocked === true; break;
      case 'early_bird':      ok = stats.early_bird_unlocked === true; break;
      case 'subjects':        ok = (stats.subjects_used || []).length >= v; break;
      case 'all_tools':       ok = (stats.tools_used_today || []).length >= v; break;
    }
    if (ok) toUnlock.push(ach);
  }
  if (toUnlock.length > 0) {
    await db.from('user_achievements').insert(
      toUnlock.map(a => ({ user_id: userId, achievement_id: a.id })),
      { onConflict: 'user_id,achievement_id', ignoreDuplicates: true }
    );
    const bonus = toUnlock.reduce((s, a) => s + (a.xp_reward || 0), 0);
    if (bonus > 0) await db.rpc('increment_xp', { p_user_id: userId, p_amount: bonus });
  }
}

function safeUser(u) {
  if (!u) return null;
  const { password_hash, ...safe } = u;
  return safe;
}

async function buildLoginResponse(user, deviceInfo = {}) {
  const sessionToken = await createSession(user.id, deviceInfo);
  await db.from('users').update({ last_login_at: new Date().toISOString(), login_count: (user.login_count || 0) + 1 }).eq('id', user.id);
  await ensureXPRecord(user.id);
  return {
    token:        signToken({ id: user.id, email: user.email, type: user.type, role: user.role }),
    sessionToken,
    user:         safeUser(user),
  };
}

// ════════════════════════════════════════════════════════════════
//  ROUTES: AUTH
// ════════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role = 'student' } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be >= 8 characters' });
    if (!['student', 'teacher'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const { data: ex } = await db.from('users').select('id').eq('email', email.toLowerCase()).maybeSingle();
    if (ex) return res.status(409).json({ error: 'Email already registered.' });
    const { data: user, error } = await db.from('users').insert({
      name: name.trim(), email: email.toLowerCase().trim(),
      password_hash: await bcrypt.hash(password, 12),
      type: 'personal', role, provider: 'email',
    }).select().single();
    if (error) throw error;
    res.status(201).json(await buildLoginResponse(user, { ip: req.ip, userAgent: req.headers['user-agent'] }));
  } catch (e) { console.error('[register]', e); res.status(500).json({ error: 'Registration failed.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const { data: user } = await db.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid email or password' });
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.is_active) return res.status(403).json({ error: 'Account is deactivated.' });
    res.json(await buildLoginResponse(user, { ip: req.ip, userAgent: req.headers['user-agent'] }));
  } catch (e) { console.error('[login]', e); res.status(500).json({ error: 'Login failed.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'Google token required' });
    const ticket  = await googleAuth.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;
    let { data: user } = await db.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({
        name, email: email.toLowerCase(), provider: 'google', type: 'personal', role: 'student',
        avatar_url: picture, google_id: googleId, email_verified: true,
      }).select().single();
      if (error) throw error;
      user = newUser;
    } else {
      await db.from('users').update({ avatar_url: picture, google_id: googleId }).eq('id', user.id);
      user = { ...user, avatar_url: picture, google_id: googleId };
    }
    res.json(await buildLoginResponse(user, { ip: req.ip, userAgent: req.headers['user-agent'] }));
  } catch (e) { console.error('[google]', e); res.status(401).json({ error: 'Google sign-in failed: ' + e.message }); }
});

app.post('/api/auth/microsoft', async (req, res) => {
  try {
    const { accessToken } = req.body;
    if (!accessToken) return res.status(400).json({ error: 'Microsoft token required' });
    const graphRes = await fetch('https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!graphRes.ok) return res.status(401).json({ error: 'Invalid Microsoft token' });
    const profile = await graphRes.json();
    const email   = (profile.mail || profile.userPrincipalName).toLowerCase();
    const name    = profile.displayName;
    const msId    = profile.id;
    let { data: user } = await db.from('users').select('*').eq('email', email).maybeSingle();
    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({
        name, email, provider: 'microsoft', type: 'personal', role: 'student',
        microsoft_id: msId, email_verified: true,
      }).select().single();
      if (error) throw error;
      user = newUser;
    } else {
      await db.from('users').update({ microsoft_id: msId }).eq('id', user.id);
    }
    res.json(await buildLoginResponse(user, { ip: req.ip, userAgent: req.headers['user-agent'] }));
  } catch (e) { console.error('[microsoft]', e); res.status(500).json({ error: 'Microsoft sign-in failed.' }); }
});

app.post('/api/auth/school', async (req, res) => {
  try {
    const { schoolCode, identifier, password, role = 'student' } = req.body;
    if (!schoolCode || !identifier || !password) return res.status(400).json({ error: 'School code, ID and password required' });
    const { data: school } = await db.from('schools').select('*').eq('school_code', schoolCode.toUpperCase()).maybeSingle();
    if (!school)             return res.status(404).json({ error: 'School code not found.' });
    if (!school.is_active)   return res.status(403).json({ error: 'School account is inactive.' });
    if (school.subscription_status === 'expired') return res.status(403).json({ error: 'School subscription has expired.' });
    const table   = role === 'teacher' ? 'school_teachers' : 'school_students';
    const idField = role === 'teacher' ? 'employee_id'      : 'roll_number';
    const { data: member } = await db.from(table).select('*').eq('school_id', school.id).eq(idField, identifier.trim()).maybeSingle();
    if (!member)           return res.status(401).json({ error: `${role === 'teacher' ? 'Employee ID' : 'Roll number'} not found.` });
    if (!member.is_active) return res.status(403).json({ error: 'This account has been deactivated.' });
    if (!await bcrypt.compare(password, member.password_hash)) return res.status(401).json({ error: 'Incorrect password.' });
    const syntheticEmail = `${identifier.toLowerCase().replace(/[^a-z0-9]/g, '')}@${schoolCode.toLowerCase()}.school`;
    let { data: user } = await db.from('users').select('*').eq('email', syntheticEmail).maybeSingle();
    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({
        name: member.name, email: syntheticEmail, type: 'school', role, provider: 'school',
        school_id: school.id, class_level: member.class_level || null,
        section: member.section || null, roll_number: role === 'student' ? identifier.trim() : null,
        employee_id: role === 'teacher' ? identifier.trim() : null,
        subject_specialization: role === 'teacher' ? (member.subjects || []).join(', ') : null,
      }).select().single();
      if (error) throw error;
      user = newUser;
    }
    const resp = await buildLoginResponse(user, { ip: req.ip, userAgent: req.headers['user-agent'] });
    resp.schoolName = school.name;
    resp.schoolCode = school.school_code;
    resp.schoolLogo = school.logo_url;
    res.json(resp);
  } catch (e) { console.error('[school login]', e); res.status(500).json({ error: 'School login failed.' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const { data: user } = await db.from('users').select('id, name').eq('email', email.toLowerCase()).maybeSingle();
    if (!user || !mailer) return res.json({ success: true, message: 'If that email exists, a reset link was sent.' });
    const token = crypto.randomBytes(32).toString('hex');
    await db.from('password_reset_tokens').insert({
      email: email.toLowerCase(), token,
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await mailer.sendMail({
      from: `"BrainSpark AI" <${process.env.EMAIL_USER}>`, to: email,
      subject: 'Reset your BrainSpark AI password',
      html: `<div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px"><h2 style="color:#6366F1">Password Reset</h2><p>Hi ${user.name},</p><p>Click below to reset your password. This link expires in 1 hour.</p><a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:12px 24px;background:#6366F1;color:#fff;text-decoration:none;border-radius:8px;font-weight:700">Reset Password</a><p style="color:#888;font-size:12px">If you didn't request this, ignore this email.</p></div>`,
    });
    res.json({ success: true, message: 'If that email exists, a reset link was sent.' });
  } catch (e) { console.error('[forgot-password]', e); res.status(500).json({ error: 'Failed to send reset email.' }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be >= 8 characters' });
    const { data: rec } = await db.from('password_reset_tokens')
      .select('*').eq('token', token).eq('used', false).maybeSingle();
    if (!rec || new Date(rec.expires_at) < new Date()) return res.status(400).json({ error: 'Invalid or expired reset link.' });
    await db.from('users').update({ password_hash: await bcrypt.hash(newPassword, 12), updated_at: new Date().toISOString() }).eq('email', rec.email);
    await db.from('password_reset_tokens').update({ used: true }).eq('id', rec.id);
    res.json({ success: true });
  } catch (e) { console.error('[reset-password]', e); res.status(500).json({ error: 'Reset failed.' }); }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const { data: user } = await db.from('users')
      .select('*, schools(name, school_code, logo_url)')
      .eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', verifyToken, async (req, res) => {
  const stok = req.headers['x-session-token'];
  if (stok) await db.from('user_sessions').update({ is_active: false }).eq('user_id', req.user.id).eq('session_token', stok);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: USER PROFILE & STATS
// ════════════════════════════════════════════════════════════════
app.get('/api/user/profile', verifyToken, async (req, res) => {
  const { data: user } = await db.from('users').select('*, schools(name, school_code, logo_url)').eq('id', req.user.id).maybeSingle();
  res.json(safeUser(user));
});

app.put('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const { name, bio, phone, classLevel, section, subjectSpecialization, preferredSubjects } = req.body;
    const { data: user, error } = await db.from('users').update({
      ...(name                              && { name: name.trim() }),
      ...(bio               !== undefined   && { bio }),
      ...(phone             !== undefined   && { phone }),
      ...(classLevel        !== undefined   && { class_level: classLevel }),
      ...(section           !== undefined   && { section }),
      ...(subjectSpecialization !== undefined && { subject_specialization: subjectSpecialization }),
      ...(preferredSubjects !== undefined   && { preferred_subjects: preferredSubjects }),
      updated_at: new Date().toISOString(),
    }).eq('id', req.user.id).select().single();
    if (error) throw error;
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be >= 8 characters' });
    const { data: user } = await db.from('users').select('password_hash').eq('id', req.user.id).single();
    if (user.password_hash && !await bcrypt.compare(currentPassword, user.password_hash))
      return res.status(401).json({ error: 'Current password is incorrect' });
    await db.from('users').update({ password_hash: await bcrypt.hash(newPassword, 12), updated_at: new Date().toISOString() }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/stats', verifyToken, async (req, res) => {
  try {
    const { data: stats  } = await db.rpc('get_user_stats', { p_user_id: req.user.id });
    const { data: recent } = await db.from('activity_log').select('tool,subject,chapter,xp_earned,created_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
    const sevenAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data: weekly } = await db.from('activity_log').select('tool,xp_earned,created_at')
      .eq('user_id', req.user.id).gte('created_at', sevenAgo);
    res.json({ stats: stats?.[0] || {}, recentActivity: recent || [], weeklyActivity: weekly || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/history', verifyToken, async (req, res) => {
  const page  = parseInt(req.query.page) || 1;
  const limit = 50;
  const { data } = await db.from('activity_log')
    .select('id, tool, subject, chapter, chapters, xp_earned, ai_provider, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .range((page - 1) * limit, page * limit - 1);
  res.json(data || []);
});

app.get('/api/user/achievements', verifyToken, async (req, res) => {
  const { data: all } = await db.from('achievements').select('*').order('sort_order');
  const { data: unlocked } = await db.from('user_achievements').select('achievement_id, unlocked_at').eq('user_id', req.user.id);
  const unlockedMap = Object.fromEntries((unlocked || []).map(u => [u.achievement_id, u.unlocked_at]));
  res.json((all || []).map(a => ({ ...a, unlocked: !!unlockedMap[a.id], unlocked_at: unlockedMap[a.id] || null })));
});

app.get('/api/user/subscription', verifyToken, async (req, res) => {
  const { data: user } = await db.from('users')
    .select('subscription_status, subscription_plan, subscription_expires_at, free_tier_started_at, type, role')
    .eq('id', req.user.id).single();
  // Calculate seconds remaining for frontend
  let freeSecondsRemaining = null;
  if (user?.type === 'personal' && user.subscription_status !== 'active') {
    if (!user.free_tier_started_at) {
      freeSecondsRemaining = FREE_WINDOW_SECONDS; // not started yet
    } else {
      const elapsed = Math.floor((Date.now() - new Date(user.free_tier_started_at)) / 1000);
      freeSecondsRemaining = Math.max(0, FREE_WINDOW_SECONDS - elapsed);
    }
  }
  res.json({ ...user, freeSecondsRemaining });
});

// Saved Notes
app.get('/api/user/notes', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_notes').select('id,title,subject,class_level,chapter,style,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.get('/api/user/notes/:id', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_notes').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data);
});
app.post('/api/user/notes', verifyToken, async (req, res) => {
  const { subject, classLevel, chapter, style, content } = req.body;
  const { data, error } = await db.from('saved_notes').insert({ user_id: req.user.id, title: `${chapter} — ${subject}`, subject, class_level: classLevel, chapter, style, content, word_count: content?.split(/\s+/).length || 0 }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/notes/:id', verifyToken, async (req, res) => {
  await db.from('saved_notes').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// Saved Papers
app.get('/api/user/papers', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_papers').select('id,title,subject,class_level,chapters,marks,duration,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.post('/api/user/papers', verifyToken, async (req, res) => {
  const { subject, classLevel, chapters, marks, duration, description, content } = req.body;
  const { data, error } = await db.from('saved_papers').insert({ user_id: req.user.id, title: `${subject} — ${classLevel} — ${marks}M`, subject, class_level: classLevel, chapters: chapters || [], marks, duration, description, content }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/papers/:id', verifyToken, async (req, res) => {
  await db.from('saved_papers').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// Cheat Sheets
app.get('/api/user/cheatsheets', verifyToken, async (req, res) => {
  const { data } = await db.from('cheat_sheets').select('id,title,subject,class_level,chapters,exam_date,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.post('/api/user/cheatsheets', verifyToken, async (req, res) => {
  const { subject, classLevel, chapters, examDate, content } = req.body;
  const { data, error } = await db.from('cheat_sheets').insert({ user_id: req.user.id, title: `${subject} — ${(chapters || []).join(', ')}`, subject, class_level: classLevel, chapters: chapters || [], exam_date: examDate || null, content, word_count: content?.split(/\s+/).length || 0 }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/cheatsheets/:id', verifyToken, async (req, res) => {
  await db.from('cheat_sheets').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// Lesson Plans
app.get('/api/user/lessonplans', verifyToken, async (req, res) => {
  const { data } = await db.from('lesson_plans').select('id,title,subject,topic,class_level,duration_minutes,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.post('/api/user/lessonplans', verifyToken, async (req, res) => {
  const { subject, topic, classLevel, durationMinutes, customPrompt, content } = req.body;
  const { data, error } = await db.from('lesson_plans').insert({ user_id: req.user.id, title: `${topic} — ${subject}`, subject, topic, class_level: classLevel, duration_minutes: durationMinutes, custom_prompt: customPrompt, content }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/lessonplans/:id', verifyToken, async (req, res) => {
  await db.from('lesson_plans').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// Quiz History
app.get('/api/user/quiz-history', verifyToken, async (req, res) => {
  const { data } = await db.from('quiz_history').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
  res.json(data || []);
});
app.post('/api/user/quiz-history', verifyToken, async (req, res) => {
  const { subject, topic, difficulty, totalQuestions, correctAnswers, xpEarned, isPerfect } = req.body;
  const { data, error } = await db.from('quiz_history').insert({
    user_id: req.user.id, subject, topic, difficulty,
    total_questions: totalQuestions, correct_answers: correctAnswers,
    score_percent: Math.round((correctAnswers / totalQuestions) * 100),
    xp_earned: xpEarned, is_perfect: isPerfect || false,
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  if (isPerfect) await db.rpc('increment_counter', { p_user_id: req.user.id, p_field: 'quizzes_perfect' });
  res.status(201).json(data);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: MEDIA UPLOAD
// ════════════════════════════════════════════════════════════════
app.post('/api/upload/media', verifyToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    const ext  = req.file.originalname.split('.').pop().toLowerCase();
    const name = `${req.user.id}/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${ext}`;
    const { error } = await db.storage
      .from(process.env.SUPABASE_STORAGE_BUCKET || 'brainspark-media')
      .upload(name, req.file.buffer, { contentType: req.file.mimetype });
    if (error) throw error;
    const { data: urlData } = db.storage
      .from(process.env.SUPABASE_STORAGE_BUCKET || 'brainspark-media')
      .getPublicUrl(name);
    res.json({
      url:  urlData.publicUrl,
      type: req.file.mimetype.startsWith('image/') ? 'image' : 'pdf',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SOCIAL FEED (with media + rich comments)
// ════════════════════════════════════════════════════════════════
app.get('/api/posts', verifyToken, async (req, res) => {
  try {
    let query = db.from('posts').select('*').order('created_at', { ascending: false }).limit(100);
    // School users only see posts from their school
    if (req.user.type === 'school') {
      const { data: u } = await db.from('users').select('school_id').eq('id', req.user.id).single();
      query = query.eq('school_id', u.school_id);
    } else {
      query = query.is('school_id', null);
    }
    const { data } = await query;
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts', verifyToken, async (req, res) => {
  try {
    const { body, subj, tags, anon, grad, media_url, media_type } = req.body;
    if (!body?.trim() && !media_url) return res.status(400).json({ error: 'Post cannot be empty' });
    const { data: user } = await db.from('users').select('name, class_level, school_id').eq('id', req.user.id).single();
    const { data, error } = await db.from('posts').insert({
      uid:           anon ? null : req.user.id,
      uname:         anon ? 'Anonymous Student' : user.name,
      ucls:          user.class_level || 'Student',
      subj:          subj || 'General',
      body:          body?.trim() || '',
      tags:          tags || [],
      likes:         0,
      rich_comments: [],
      anon:          !!anon,
      grad:          grad || '135deg,#6366F1,#8B5CF6',
      media_url:     media_url || null,
      media_type:    media_type || null,
      school_id:     req.user.type === 'school' ? user.school_id : null,
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) { console.error('[post]', e); res.status(500).json({ error: e.message }); }
});

app.patch('/api/posts/:id/like', verifyToken, async (req, res) => {
  try {
    await db.rpc('increment_post_like', { p_post_id: req.params.id });
    res.json({ success: true });
  } catch {
    const { data: post } = await db.from('posts').select('likes').eq('id', req.params.id).single();
    await db.from('posts').update({ likes: (post?.likes || 0) + 1 }).eq('id', req.params.id);
    res.json({ success: true });
  }
});

app.post('/api/posts/:id/comment', verifyToken, async (req, res) => {
  try {
    const { text, media_url, media_type } = req.body;
    if (!text?.trim() && !media_url) return res.status(400).json({ error: 'Comment cannot be empty' });

    const { data: post } = await db.from('posts').select('rich_comments, school_id').eq('id', req.params.id).single();

    // School isolation
    if (post?.school_id && req.user.type === 'school') {
      const { data: u } = await db.from('users').select('school_id').eq('id', req.user.id).single();
      if (u.school_id !== post.school_id) return res.status(403).json({ error: 'Access denied' });
    }

    const comment = {
      id:          crypto.randomUUID(),
      author_id:   req.user.id,
      author_name: req.user.name || 'User',
      text:        text?.trim() || '',
      media_url:   media_url || null,
      media_type:  media_type || null,
      created_at:  new Date().toISOString(),
    };
    const updated = [...(post?.rich_comments || []), comment];
    await db.from('posts').update({ rich_comments: updated }).eq('id', req.params.id);
    res.json(comment);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: CHAPTER COURSE CACHE
// ════════════════════════════════════════════════════════════════
app.get('/api/courses/:key', async (req, res) => {
  const { data } = await db.from('chapter_cache').select('*').eq('cache_key', req.params.key).maybeSingle();
  res.json(data || null);
});

app.post('/api/courses', verifyToken, async (req, res) => {
  try {
    const { cacheKey, notes, qa, quiz, subject, cls, chapter } = req.body;
    if (!cacheKey) return res.status(400).json({ error: 'cacheKey required' });
    const { data, error } = await db.from('chapter_cache').upsert({
      cache_key: cacheKey, notes, qa, quiz, subject, class_level: cls, chapter,
      generated_by: req.user.id, updated_at: new Date().toISOString(),
    }, { onConflict: 'cache_key' }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { console.error('[courses]', e); res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SEARCH
// ════════════════════════════════════════════════════════════════
app.get('/api/search', verifyToken, async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) return res.json([]);
  try {
    if (req.user.type === 'school') {
      const { data: me } = await db.from('users').select('school_id').eq('id', req.user.id).single();
      const { data } = await db.from('users')
        .select('id, name, role, class_level, section, avatar_url, subject_specialization')
        .eq('school_id', me.school_id).ilike('name', `%${q}%`).limit(20);
      return res.json(data || []);
    }
    const { data } = await db.from('users')
      .select('id, name, role, class_level, bio, avatar_url')
      .eq('type', 'personal').ilike('name', `%${q}%`).limit(20);
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: PROFILES (LinkedIn-style)
// ════════════════════════════════════════════════════════════════
app.get('/api/profiles/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    // School isolation check
    if (req.user.type === 'school') {
      const [{ data: me }, { data: them }] = await Promise.all([
        db.from('users').select('school_id').eq('id', req.user.id).single(),
        db.from('users').select('school_id').eq('id', userId).single(),
      ]);
      if (!them || me.school_id !== them.school_id)
        return res.status(403).json({ error: 'Cannot view profiles from other schools' });
    }
    const [userRes, profileRes, xpRes] = await Promise.all([
      db.from('users').select('id, name, role, class_level, section, subject_specialization, school_id, created_at, type, bio, avatar_url').eq('id', userId).single(),
      db.from('user_profiles').select('*').eq('user_id', userId).maybeSingle(),
      db.from('user_xp').select('total_xp, current_streak, doubts_solved, quizzes_done, notes_made, papers_made, cheat_sheets_made, lesson_plans_made').eq('user_id', userId).single(),
    ]);
    // XP rank
    const { data: rankData } = await db.rpc('get_xp_ranking', { p_user_id: userId }).catch(() => ({ data: null }));
    res.json({
      user:    userRes.data,
      profile: profileRes.data || {},
      stats:   xpRes.data || {},
      rank:    rankData?.[0] || {},
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profiles/me', verifyToken, async (req, res) => {
  try {
    const { headline, about, location, website_url, skills, languages, hobbies,
            certifications, experience, education, visibility, banner_url } = req.body;
    const { data, error } = await db.from('user_profiles').upsert({
      user_id: req.user.id, headline, about, location, website_url, skills, languages,
      hobbies, certifications, experience, education, visibility, banner_url,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: MESSAGING
// ════════════════════════════════════════════════════════════════
async function canMessage(senderId, receiverId) {
  const [{ data: sender }, { data: receiver }] = await Promise.all([
    db.from('users').select('role, school_id, type').eq('id', senderId).single(),
    db.from('users').select('role, school_id, type').eq('id', receiverId).single(),
  ]);
  if (!sender || !receiver) return false;
  // School users: must be same school + no student↔student
  if (sender.type === 'school' || receiver.type === 'school') {
    if (sender.school_id !== receiver.school_id) return false;
    if (sender.role === 'student' && receiver.role === 'student') return false;
  }
  return true;
}

app.get('/api/conversations', verifyToken, async (req, res) => {
  try {
    const { data } = await db.from('conversations')
      .select('id, participant_ids, last_message, last_message_at, created_at')
      .contains('participant_ids', [req.user.id])
      .order('last_message_at', { ascending: false });
    // Fetch other participant info
    const enriched = await Promise.all((data || []).map(async c => {
      const otherId = c.participant_ids.find(id => id !== req.user.id);
      const { data: other } = await db.from('users').select('id, name, role, class_level, avatar_url').eq('id', otherId).single();
      return { ...c, other };
    }));
    res.json(enriched);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/conversations', verifyToken, async (req, res) => {
  try {
    const { receiverId } = req.body;
    if (!await canMessage(req.user.id, receiverId))
      return res.status(403).json({ error: 'Messaging not allowed between these users' });
    const participants = [req.user.id, receiverId].sort();
    const { data: existing } = await db.from('conversations')
      .select('id').contains('participant_ids', participants).maybeSingle();
    if (existing) return res.json(existing);
    const { data: u } = await db.from('users').select('school_id').eq('id', req.user.id).single();
    const { data, error } = await db.from('conversations').insert({
      participant_ids: participants, school_id: u.school_id || null,
    }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/conversations/:id/messages', verifyToken, async (req, res) => {
  try {
    const { data: conv } = await db.from('conversations').select('participant_ids').eq('id', req.params.id).single();
    if (!conv?.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'Forbidden' });
    const { data } = await db.from('messages')
      .select('id, sender_id, content, media_url, media_type, created_at')
      .eq('conversation_id', req.params.id)
      .order('created_at', { ascending: true }).limit(100);
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/conversations/:id/messages', verifyToken, async (req, res) => {
  try {
    const { content, media_url, media_type } = req.body;
    if (!content?.trim() && !media_url) return res.status(400).json({ error: 'Empty message' });
    const { data: conv } = await db.from('conversations').select('participant_ids').eq('id', req.params.id).single();
    if (!conv?.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await db.from('messages').insert({
      conversation_id: req.params.id, sender_id: req.user.id,
      content: content?.trim() || null, media_url: media_url || null, media_type: media_type || null,
    }).select().single();
    if (error) throw error;
    await db.from('conversations').update({
      last_message_at: new Date().toISOString(),
      last_message:    content?.slice(0, 80) || '📷 Media',
    }).eq('id', req.params.id);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL — NOTICES
// ════════════════════════════════════════════════════════════════
app.get('/api/school/notices', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id').eq('id', req.user.id).single();
  if (!u?.school_id) return res.json([]);
  const { data } = await db.from('school_notices').select('*')
    .eq('school_id', u.school_id)
    .order('is_pinned', { ascending: false })
    .order('created_at',  { ascending: false }).limit(50);
  res.json(data || []);
});

app.post('/api/school/notices', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, role').eq('id', req.user.id).single();
  if (!['admin', 'principal', 'teacher'].includes(u?.role))
    return res.status(403).json({ error: 'Only admin/teachers can post notices' });
  // Only admin can post school-wide notices
  const { title, content, notice_type, target_audience, media_url, is_pinned, expires_at } = req.body;
  if (target_audience === 'all' && u.role === 'teacher')
    return res.status(403).json({ error: 'Only admin can post school-wide notices' });
  const { data, error } = await db.from('school_notices').insert({
    school_id: u.school_id, title, content, notice_type: notice_type || 'general',
    target_audience: target_audience || 'all', media_url: media_url || null,
    is_pinned: is_pinned || false, expires_at: expires_at || null, posted_by: req.user.id,
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL — TIMETABLE
// ════════════════════════════════════════════════════════════════
app.get('/api/school/timetable', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, class_level, section').eq('id', req.user.id).single();
  if (!u?.school_id) return res.json(null);
  const { data } = await db.from('timetables').select('*')
    .eq('school_id', u.school_id)
    .eq('class_level', u.class_level || '').maybeSingle();
  res.json(data || null);
});

app.post('/api/school/timetable', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, role').eq('id', req.user.id).single();
  if (!['teacher', 'admin'].includes(u?.role)) return res.status(403).json({ error: 'Teachers only' });
  const { class_level, section, schedule, academic_year } = req.body;
  const { data, error } = await db.from('timetables').upsert({
    school_id: u.school_id, class_level, section, schedule,
    academic_year: academic_year || '2024-25', uploaded_by: req.user.id,
    updated_at: new Date().toISOString(),
  }, { onConflict: 'school_id,class_level,section' }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: ASSIGNMENTS
// ════════════════════════════════════════════════════════════════
app.get('/api/assignments', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, role, class_level, section').eq('id', req.user.id).single();
  if (!u?.school_id) return res.json([]);
  let query = db.from('assignments').select('*, users!teacher_id(name)').eq('school_id', u.school_id);
  if (u.role === 'teacher') {
    query = query.eq('teacher_id', req.user.id);
  } else {
    query = query.eq('class_level', u.class_level);
  }
  const { data } = await query.order('deadline', { ascending: true });
  res.json(data || []);
});

app.post('/api/assignments', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, role').eq('id', req.user.id).single();
  if (u?.role !== 'teacher') return res.status(403).json({ error: 'Teachers only' });
  const { title, description, subject, class_level, section, chapters, total_marks,
          deadline, answer_type, grading_notes, question_paper_url, question_paper_text, questions_json } = req.body;
  if (!title || !deadline) return res.status(400).json({ error: 'Title and deadline are required' });
  const { data, error } = await db.from('assignments').insert({
    school_id: u.school_id, teacher_id: req.user.id, title, description, subject,
    class_level, section: section || null, chapters: chapters || [], total_marks: total_marks || 0,
    deadline, answer_type: answer_type || 'both', grading_notes: grading_notes || '',
    question_paper_url: question_paper_url || null,
    question_paper_text: question_paper_text || null,
    questions_json: questions_json || null,
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.post('/api/assignments/generate-paper', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('role').eq('id', req.user.id).single();
  if (u?.role !== 'teacher') return res.status(403).json({ error: 'Teachers only' });
  const { subject, class_level, chapters, marks, answer_type, teacher_notes, question_types } = req.body;
  const prompt = `Create a formal CBSE ${marks}-mark assignment question paper.
Subject: ${subject} | Class: ${class_level}
Chapters covered: ${(chapters || []).join(', ')}
Expected answer format: ${answer_type || 'both'} (text or PDF upload)
Teacher's grading priorities: ${teacher_notes || 'Standard CBSE grading'}
Preferred question types: ${question_types || 'Mix of MCQ, Short Answer, Long Answer'}

IMPORTANT: Number every question clearly as Q1., Q2., etc. with marks in brackets like [2 marks].
Write a clean, professional question paper. After the paper, write exactly: ===JSON===
Then return ONLY this JSON (no markdown, no explanation):
{"questions":[{"q_num":1,"question":"full question text","type":"mcq","max_marks":2},{"q_num":2,"question":"...","type":"short","max_marks":5}]}`;
  try {
    const r = await callAI([{ role: 'user', content: prompt }], '', 4000, 'paper');
    const sepIdx = r.text.indexOf('===JSON===');
    let paperText = r.text, questionsJson = null;
    if (sepIdx > -1) {
      paperText = r.text.slice(0, sepIdx).trim();
      try { questionsJson = JSON.parse(r.text.slice(sepIdx + 10).trim()); } catch {}
    }
    res.json({ paper_text: paperText, questions_json: questionsJson, provider: r.provider });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/assignments/:id/submit', verifyToken, upload.single('pdf'), async (req, res) => {
  try {
    const { data: assignment } = await db.from('assignments').select('*').eq('id', req.params.id).single();
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });
    const isLate = new Date() > new Date(assignment.deadline);
    let pdf_url = null, answers_text = null, submission_type = 'text';
    if (req.file) {
      const name = `assignments/${req.user.id}/${req.params.id}-${Date.now()}.pdf`;
      const { error: uploadErr } = await db.storage
        .from(process.env.SUPABASE_STORAGE_BUCKET || 'brainspark-media')
        .upload(name, req.file.buffer, { contentType: 'application/pdf' });
      if (uploadErr) throw uploadErr;
      const { data: urlData } = db.storage
        .from(process.env.SUPABASE_STORAGE_BUCKET || 'brainspark-media')
        .getPublicUrl(name);
      pdf_url = urlData.publicUrl;
      submission_type = 'pdf';
    } else {
      const raw = req.body.answers;
      answers_text = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : [];
      submission_type = 'text';
    }
    const { data, error } = await db.from('assignment_submissions').upsert({
      assignment_id: req.params.id, student_id: req.user.id,
      school_id: assignment.school_id, submission_type,
      answers_text, pdf_url, is_late: isLate,
      submitted_at: new Date().toISOString(),
    }, { onConflict: 'assignment_id,student_id' }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/assignments/:id/analysis/me', verifyToken, async (req, res) => {
  const { data } = await db.from('assignment_analysis')
    .select('*').eq('assignment_id', req.params.id).eq('student_id', req.user.id).maybeSingle();
  res.json(data || null);
});

app.get('/api/assignments/:id/analysis/all', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('role').eq('id', req.user.id).single();
  if (u?.role !== 'teacher') return res.status(403).json({ error: 'Teachers only' });
  const { data } = await db.from('assignment_analysis')
    .select('*, users!student_id(name, class_level, section, roll_number)')
    .eq('assignment_id', req.params.id);
  res.json(data || []);
});

// ════════════════════════════════════════════════════════════════
//  ASSIGNMENT AUTO-ANALYSIS ENGINE (runs every 15 min)
// ════════════════════════════════════════════════════════════════
async function analyzeTextSubmission(assignment, submission) {
  const prompt = `You are an expert CBSE teacher grading an assignment.

ASSIGNMENT: "${assignment.title}"
SUBJECT: ${assignment.subject} | TOTAL MARKS: ${assignment.total_marks}
QUESTIONS: ${JSON.stringify(assignment.questions_json?.questions || [])}
TEACHER GRADING PREFERENCES: ${assignment.grading_notes || 'Standard CBSE grading. Award marks for correct method.'}

STUDENT ANSWERS: ${JSON.stringify(submission.answers_text)}

CRITICAL: Match answers to questions by question NUMBER only (Q1 answer → Q1 question, Q2 → Q2, etc.)
Give detailed, constructive feedback for each answer.

Return ONLY this JSON (no markdown):
{
  "questions_analysis": [
    {"q_num": 1, "marks_awarded": 3, "marks_max": 5, "feedback": "Good explanation but missed the formula derivation.", "improvement_tip": "Always show the derivation step in your working.", "correctness_pct": 70}
  ],
  "total_marks_awarded": 18,
  "total_marks_max": 25,
  "overall_feedback": "Well-structured answers. Focus on showing working steps.",
  "strengths": ["Good conceptual understanding", "Neat presentation"],
  "improvements": ["Show derivations", "Elaborate on definitions"]
}`;
  const r = await callAI([{ role: 'user', content: prompt }], '', 3000, 'notes');
  const parsed = JSON.parse(r.text.replace(/```[\w]*\n?/g, '').trim());
  return { ...parsed, ai_provider: r.provider };
}

async function analyzePDFSubmission(assignment, submission) {
  const prompt = `You are an expert CBSE teacher grading a handwritten assignment.

ASSIGNMENT: "${assignment.title}"
SUBJECT: ${assignment.subject} | TOTAL MARKS: ${assignment.total_marks}
QUESTIONS: ${JSON.stringify(assignment.questions_json?.questions || [])}
GRADING PREFERENCES: ${assignment.grading_notes || 'Standard CBSE'}

CRITICAL: Match student answers to questions by question number (Q1., Q2., etc.) ONLY.

Analyze the handwritten answers and return ONLY this JSON:
{
  "questions_analysis": [{"q_num": 1, "marks_awarded": 3, "marks_max": 5, "feedback": "...", "improvement_tip": "..."}],
  "total_marks_awarded": 18, "total_marks_max": 25,
  "overall_feedback": "...",
  "strengths": ["..."], "improvements": ["..."],
  "handwriting_quality": "good",
  "handwriting_tips": "Your handwriting is clear. Try to maintain consistent letter size."
}`;
  const r = await anthropic.messages.create({
    model: 'claude-sonnet-4-6', max_tokens: 3000,
    messages: [{
      role: 'user',
      content: [
        { type: 'document', source: { type: 'url', url: submission.pdf_url } },
        { type: 'text', text: prompt },
      ],
    }],
  });
  const text = r.content[0].text.replace(/```[\w]*\n?/g, '').trim();
  const parsed = JSON.parse(text);
  return { ...parsed, ai_provider: 'claude' };
}

async function runAssignmentAnalysis() {
  try {
    const { data: pending } = await db.from('assignments')
      .select('id').eq('status', 'active').lt('deadline', new Date().toISOString());
    for (const a of pending || []) {
      await db.from('assignments').update({ status: 'closed' }).eq('id', a.id);
      const { data: submissions } = await db.from('assignment_submissions')
        .select('*').eq('assignment_id', a.id);
      const { data: assignment } = await db.from('assignments').select('*').eq('id', a.id).single();
      for (const sub of submissions || []) {
        const { data: existing } = await db.from('assignment_analysis')
          .select('id').eq('submission_id', sub.id).maybeSingle();
        if (existing) continue;
        try {
          let result;
          if (sub.submission_type === 'pdf' && sub.pdf_url) {
            result = await analyzePDFSubmission(assignment, sub);
          } else {
            result = await analyzeTextSubmission(assignment, sub);
          }
          await db.from('assignment_analysis').insert({
            submission_id: sub.id, assignment_id: a.id,
            student_id: sub.student_id, school_id: sub.school_id,
            ...result, analyzed_at: new Date().toISOString(),
          });
        } catch (e) { console.error('[analysis error]', e.message); }
      }
    }
  } catch (e) { console.error('[runAssignmentAnalysis]', e.message); }
}

setInterval(runAssignmentAnalysis, 15 * 60 * 1000);

// ════════════════════════════════════════════════════════════════
//  ROUTES: AI BUDDY
// ════════════════════════════════════════════════════════════════
async function getBuddyContext(userId) {
  const sevenDaysAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  const { data: u } = await db.from('users').select('school_id, role, name, class_level').eq('id', userId).single();
  const [activity, xpData, memories] = await Promise.all([
    db.from('activity_log').select('tool, subject, chapter, created_at').eq('user_id', userId).gte('created_at', sevenDaysAgo).limit(20),
    db.from('user_xp').select('total_xp, current_streak, doubts_solved, quizzes_done, notes_made').eq('user_id', userId).single(),
    db.from('ai_buddy_memories').select('memory, importance').eq('user_id', userId).order('importance', { ascending: false }).limit(15),
  ]);
  let schoolContext = '';
  if (u?.school_id) {
    const [notices, assignments] = await Promise.all([
      db.from('school_notices').select('title, notice_type').eq('school_id', u.school_id).gte('created_at', sevenDaysAgo).limit(5),
      db.from('assignments').select('title, subject, deadline').eq('school_id', u.school_id).gt('deadline', new Date().toISOString()).limit(5),
    ]);
    schoolContext = `
Recent school notices: ${(notices.data || []).map(n => `[${n.notice_type}] ${n.title}`).join(' | ')}
Upcoming assignments: ${(assignments.data || []).map(a => `${a.subject}: "${a.title}" due ${new Date(a.deadline).toLocaleDateString('en-IN')}`).join(' | ')}`;
  }
  return `You are ${u?.name || 'a student'}'s AI Study Buddy — warm, encouraging, and genuinely helpful like a caring friend who truly knows them.

WHO THEY ARE:
- Name: ${u?.name} | Role: ${u?.role} | Class: ${u?.class_level || 'N/A'}
- XP: ${xpData.data?.total_xp || 0} | Streak: ${xpData.data?.current_streak || 0} days
- Doubts: ${xpData.data?.doubts_solved || 0} | Quizzes: ${xpData.data?.quizzes_done || 0}

RECENT ACTIVITY (7 days): ${(activity.data || []).slice(0, 10).map(a => `${a.tool}(${a.subject})`).join(', ') || 'None yet'}
${schoolContext}
WHAT I REMEMBER ABOUT THEM: ${(memories.data || []).map(m => m.memory).join('; ') || 'This is our first conversation!'}

Guidelines: Be like a real friend — concise (2-4 sentences), warm, specific to their context. Use their name. Reference their actual data. Ask good questions. Give actionable suggestions. Use emojis sparingly. When they're stressed, acknowledge it first before helping.`;
}

async function extractBuddyMemories(userId, conversation) {
  if (conversation.length < 4) return;
  try {
    const r = await callAI([{
      role: 'user',
      content: `From this conversation, identify 0-3 IMPORTANT long-term facts about this person to remember (goals, struggles, key events, preferences, milestones). Be specific and concise.
Return ONLY valid JSON array (empty [] if nothing worth remembering):
[{"memory": "Student is preparing for IIT JEE and finds organic chemistry very hard", "importance": 5, "category": "goal"}]
Conversation: ${JSON.stringify(conversation.slice(-6))}`,
    }], '', 400, 'buddy');
    const memories = JSON.parse(r.text.replace(/```[\w]*\n?/g, '').trim());
    if (Array.isArray(memories) && memories.length > 0) {
      await db.from('ai_buddy_memories').insert(memories.map(m => ({ user_id: userId, ...m })));
    }
  } catch {}
}

app.post('/api/buddy/chat', verifyToken, async (req, res) => {
  try {
    const { message, sessionMessages = [] } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
    const systemPrompt = await getBuddyContext(req.user.id);
    const messages = [
      ...sessionMessages.slice(-10),
      { role: 'user', content: message },
    ];
    const r = await callAI(messages, systemPrompt, 600, 'buddy');
    extractBuddyMemories(req.user.id, [...messages, { role: 'assistant', content: r.text }]).catch(() => {});
    const today = new Date().toISOString().split('T')[0];
    const { data: existing } = await db.from('ai_buddy_conversations')
      .select('id, messages').eq('user_id', req.user.id).eq('session_date', today).maybeSingle();
    const newMessages = [
      ...(existing?.messages || []),
      { role: 'user', content: message, ts: new Date().toISOString() },
      { role: 'assistant', content: r.text, ts: new Date().toISOString() },
    ];
    await db.from('ai_buddy_conversations').upsert(
      { user_id: req.user.id, session_date: today, messages: newMessages, updated_at: new Date().toISOString() },
      { onConflict: 'user_id,session_date' }
    );
    res.json({ content: r.text, provider: r.provider });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL ADMIN ANALYTICS
// ════════════════════════════════════════════════════════════════
app.get('/api/school/analytics', verifyToken, async (req, res) => {
  const { data: u } = await db.from('users').select('school_id, role').eq('id', req.user.id).single();
  if (!['admin', 'teacher'].includes(u?.role)) return res.status(403).json({ error: 'Admin/Teacher only' });
  const { data } = await db.from('school_analytics').select('*').eq('school_id', u.school_id);
  res.json(data || []);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL DATA UPLOAD (CSV)
// ════════════════════════════════════════════════════════════════
app.post('/api/admin/schools/:code/upload/students-csv', verifyAdmin, uploadCSV.single('file'), async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).single();
    if (!school) return res.status(404).json({ error: 'School not found' });
    const rows = [];
    const readable = stream.Readable.from(req.file.buffer.toString());
    await new Promise((resolve, reject) => {
      readable.pipe(csv()).on('data', row => rows.push(row)).on('end', resolve).on('error', reject);
    });
    const students = await Promise.all(rows.filter(r => r.roll_number && r.name).map(async r => ({
      school_id: school.id, roll_number: r.roll_number?.trim(), name: r.name?.trim(),
      class_level: r.class_level?.trim() || '', section: r.section?.trim() || '',
      email: r.email || null, phone: r.phone || null,
      parent_name: r.parent_name || null, parent_phone: r.parent_phone || null,
      password_hash: await bcrypt.hash(r.password || r.roll_number?.trim(), 12),
    })));
    const { data, error } = await db.from('school_students')
      .upsert(students, { onConflict: 'school_id,roll_number' }).select();
    if (error) throw error;
    res.json({ success: true, imported: data.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/schools/:code/upload/teachers-csv', verifyAdmin, uploadCSV.single('file'), async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).single();
    if (!school) return res.status(404).json({ error: 'School not found' });
    const rows = [];
    const readable = stream.Readable.from(req.file.buffer.toString());
    await new Promise((resolve, reject) => {
      readable.pipe(csv()).on('data', row => rows.push(row)).on('end', resolve).on('error', reject);
    });
    const teachers = await Promise.all(rows.filter(r => r.employee_id && r.name).map(async r => ({
      school_id: school.id, employee_id: r.employee_id?.trim(), name: r.name?.trim(),
      subjects: r.subjects ? r.subjects.split('|').map(s => s.trim()) : [],
      email: r.email || null, phone: r.phone || null, qualification: r.qualification || null,
      password_hash: await bcrypt.hash(r.password || r.employee_id?.trim(), 12),
    })));
    const { data, error } = await db.from('school_teachers')
      .upsert(teachers, { onConflict: 'school_id,employee_id' }).select();
    if (error) throw error;
    res.json({ success: true, imported: data.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/schools', verifyAdmin, async (req, res) => {
  try {
    const { name, schoolCode, address, city, state, contactEmail, contactPhone, maxStudents = 500, maxTeachers = 50 } = req.body;
    if (!name || !schoolCode) return res.status(400).json({ error: 'Name and code required' });
    const { data, error } = await db.from('schools').insert({
      name: name.trim(), school_code: schoolCode.toUpperCase().trim(), address, city, state,
      contact_email: contactEmail, contact_phone: contactPhone, max_students: maxStudents, max_teachers: maxTeachers,
    }).select().single();
    if (error?.code === '23505') return res.status(409).json({ error: 'School code already exists' });
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/schools', verifyAdmin, async (req, res) => {
  const { data } = await db.from('schools').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: AI TOOLS
// ════════════════════════════════════════════════════════════════
const AI_CONFIGS = {
  doubt:      { xp: 15, maxTokens: 800,  label: 'doubt'      },
  quiz:       { xp: 5,  maxTokens: 7500, label: 'quiz'       },
  notes:      { xp: 20, maxTokens: 8096, label: 'notes'      },
  paper:      { xp: 25, maxTokens: 8000, label: 'paper'      },
  flashcards: { xp: 15, maxTokens: 2000, label: 'flashcards' },
  cheatsheet: { xp: 30, maxTokens: 8096, label: 'cheatsheet' },
  lessonplan: { xp: 30, maxTokens: 4000, label: 'lessonplan' },
};

app.post('/api/ai/:tool', verifyToken, checkAccess, aiLimiter, async (req, res) => {
  const cfg = AI_CONFIGS[req.params.tool];
  if (!cfg) return res.status(400).json({ error: `Unknown tool: ${req.params.tool}` });
  try {
    const { messages, system = '', subject = '', chapter = '', chapters = [] } = req.body;
    if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'Messages array required' });
    const { text, provider } = await callAI(messages, system, cfg.maxTokens, cfg.label);
    logActivity(req.user.id, cfg.label, { subject, chapter, chapters, xpEarned: cfg.xp, provider, meta: { subject, chapter } }).catch(console.error);
    const resp = { content: text, xpEarned: cfg.xp, provider };
    if (req.freeSecondsRemaining !== undefined) resp.secondsRemaining = req.freeSecondsRemaining;
    res.json(resp);
  } catch (e) {
    console.error(`[AI /${req.params.tool}]`, e.message);
    if (e.message?.includes('429') || e.message?.includes('rate_limit')) return res.status(429).json({ error: 'AI is busy. Try again in a moment.' });
    res.status(500).json({ error: 'AI service error.' });
  }
});



app.get('/debug/profile/:userId', verifyToken, async (req, res) => {
  const results = {}
 
  // Test 1: basic user select
  try {
    const { data, error } = await db.from('users')
      .select('id, name, role, type, school_id')
      .eq('id', req.params.userId)
      .maybeSingle()
    results.user = error ? { ERROR: error.message, code: error.code } : { OK: true, name: data?.name }
  } catch(e) { results.user = { EXCEPTION: e.message } }
 
  // Test 2: user_profiles table
  try {
    const { data, error } = await db.from('user_profiles').select('user_id').limit(1)
    results.user_profiles_table = error ? { ERROR: error.message } : { OK: true }
  } catch(e) { results.user_profiles_table = { EXCEPTION: e.message } }
 
  // Test 3: user_xp table
  try {
    const { data, error } = await db.from('user_xp')
      .select('user_id, total_xp')
      .eq('user_id', req.params.userId)
      .maybeSingle()
    results.user_xp = error ? { ERROR: error.message } : { OK: true, total_xp: data?.total_xp ?? 'no record' }
  } catch(e) { results.user_xp = { EXCEPTION: e.message } }
 
  // Test 4: get_xp_ranking RPC
  try {
    const { data, error } = await db.rpc('get_xp_ranking', { p_user_id: req.params.userId })
    results.get_xp_ranking_rpc = error ? { ERROR: error.message } : { OK: true, data }
  } catch(e) { results.get_xp_ranking_rpc = { EXCEPTION: e.message } }
 
  // Test 5: schools join
  try {
    const { data, error } = await db.from('users')
      .select('id, schools(name, school_code)')
      .eq('id', req.params.userId)
      .maybeSingle()
    results.schools_join = error ? { ERROR: error.message } : { OK: true }
  } catch(e) { results.schools_join = { EXCEPTION: e.message } }
 
  res.json(results)
})

// ════════════════════════════════════════════════════════════════
//  ROUTES: SUBSCRIPTION
// ════════════════════════════════════════════════════════════════
const PLANS = {
  student_monthly:  { amount: 15000,  label: 'Student Monthly',  months: 1  },
  student_yearly:   { amount: 150000, label: 'Student Yearly',   months: 12 },
  teacher_monthly:  { amount: 18000,  label: 'Teacher Monthly',  months: 1  },
  teacher_yearly:   { amount: 180000, label: 'Teacher Yearly',   months: 12 },
};

app.post('/api/subscription/create-order', verifyToken, async (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error: 'Payment not configured' });
    const { planType } = req.body;
    const plan = PLANS[planType];
    if (!plan) return res.status(400).json({ error: 'Invalid plan' });
    const order = await razorpay.orders.create({
      amount: plan.amount, currency: 'INR',
      receipt: `bs_${req.user.id.slice(0, 8)}_${Date.now()}`,
      notes: { userId: req.user.id, planType },
    });
    await db.from('subscriptions').insert({
      user_id: req.user.id, plan_type: planType,
      amount_paise: plan.amount, razorpay_order_id: order.id, status: 'pending',
    });
    res.json({ orderId: order.id, amount: plan.amount, currency: 'INR', planLabel: plan.label });
  } catch (e) { console.error('[create-order]', e); res.status(500).json({ error: 'Could not create payment order.' }); }
});

app.post('/api/subscription/verify', verifyToken, async (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error: 'Payment not configured' });
    const { orderId, paymentId, signature, planType } = req.body;
    const expectedSig = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`).digest('hex');
    if (expectedSig !== signature) return res.status(400).json({ error: 'Payment verification failed.' });
    const plan = PLANS[planType];
    const exp  = new Date(Date.now() + plan.months * 30 * 24 * 60 * 60 * 1000);
    await db.from('subscriptions').update({
      razorpay_payment_id: paymentId, razorpay_signature: signature,
      status: 'active', starts_at: new Date().toISOString(), expires_at: exp.toISOString(),
    }).eq('razorpay_order_id', orderId);
    await db.from('users').update({
      subscription_status: 'active', subscription_plan: planType, subscription_expires_at: exp.toISOString(),
    }).eq('id', req.user.id);
    res.json({ success: true, expiresAt: exp.toISOString() });
  } catch (e) { console.error('[verify]', e); res.status(500).json({ error: 'Verification error.' }); }
});



async function ytSearch(query, n = 5) {
  if (!process.env.YOUTUBE_API_KEY) return [];
  try {
    const url = new URL('https://www.googleapis.com/youtube/v3/search');
    url.searchParams.set('part',            'snippet');
    url.searchParams.set('q',               query);
    url.searchParams.set('maxResults',      String(n));
    url.searchParams.set('type',            'video');
    url.searchParams.set('videoEmbeddable', 'true');
    url.searchParams.set('relevanceLanguage', 'en');
    url.searchParams.set('key',             process.env.YOUTUBE_API_KEY);

    const r    = await fetch(url.toString(), { signal: AbortSignal.timeout(8000) });
    const data = await r.json();
    if (!r.ok) { console.warn('[ytSearch]', data?.error?.message); return []; }

    return (data.items || []).map(item => ({
      videoId:   item.id.videoId,
      title:     item.snippet.title,
      channel:   item.snippet.channelTitle,
      thumbnail: item.snippet.thumbnails?.medium?.url
                 || `https://img.youtube.com/vi/${item.id.videoId}/mqdefault.jpg`,
      description: (item.snippet.description || '').slice(0, 160),
    }));
  } catch (e) {
    console.warn('[ytSearch error]', e.message?.slice(0, 80));
    return [];
  }
}

/**
 * Fetch transcript for a single video. Returns plain-text string or null.
 * Trims to maxChars to stay within Claude context limits.
 */
async function ytTranscript(videoId, maxChars = 8000) {
  if (!videoId || !YoutubeTranscript) return null;
  try {
    let segs;
    try { segs = await YoutubeTranscript.fetchTranscript(videoId, { lang: 'en' }); }
    catch { segs = await YoutubeTranscript.fetchTranscript(videoId); }
    if (!segs?.length) return null;
    const text = segs.map(s => s.text).join(' ').replace(/\s+/g, ' ').trim();
    return text.length > 200 ? text.slice(0, maxChars) : null;
  } catch {
    return null;
  }
}

/**
 * Try to get a good transcript from a list of videos.
 * Tries each video in order and returns the first one with ≥500 chars.
 */
async function getBestTranscript(videos) {
  for (const v of (videos || []).slice(0, 5)) {
    if (!v?.videoId) continue;
    const t = await ytTranscript(v.videoId);
    if (t && t.length >= 500) return { transcript: t, videoId: v.videoId };
  }
  return { transcript: null, videoId: videos?.[0]?.videoId || null };
}

// ════════════════════════════════════════════════════════════════
//  AI HELPERS — module-specific prompts
// ════════════════════════════════════════════════════════════════

/** Generate the list of 8-15 modules for a chapter using Claude */
async function aiGenerateModuleList(subject, cls, chapter, moduleCount = 10) {
  const prompt = `You are an expert CBSE curriculum designer.
Break down the CBSE chapter "${chapter}" (${subject}, ${cls}) into exactly ${moduleCount} focused learning modules.
Each module should cover a distinct sub-topic that can be taught via a single YouTube video (10-20 min).
Module ${moduleCount} should be a "Practice & Exam Tips" or "Solved Examples" module.

Return ONLY valid JSON (no markdown):
{
  "modules": [
    {
      "id": 1,
      "title": "Introduction to ${chapter}",
      "description": "Brief description under 40 words",
      "emoji": "🔢",
      "estimatedMinutes": 15,
      "keyTopics": ["topic1", "topic2", "topic3"],
      "searchQuery": "specific YouTube search query for this sub-topic CBSE"
    }
  ]
}`;
  const r = await callAI([{ role: 'user', content: prompt }], '', 2000, 'notes');
  try {
    const parsed = JSON.parse(r.text.replace(/```[\w]*\n?/g, '').trim());
    return parsed?.modules || null;
  } catch { return null; }
}

/** Generate notes + Q&A + quiz for one module using transcript (or fallback to topic knowledge) */
async function aiGenerateModuleContent(moduleTitle, chapter, subject, cls, transcript) {
  const transcriptSection = transcript
    ? `Use this YouTube video transcript as your PRIMARY source. Base notes, Q&A and quiz STRICTLY on what the transcript teaches:\n\n"${transcript.slice(0, 7000)}"\n\nSupplement with CBSE knowledge only where the transcript is insufficient.`
    : `No transcript available. Use your expert CBSE knowledge of "${moduleTitle}" in ${subject} ${cls}.`;

  const prompt = `You are an expert CBSE teacher creating learning content.
Module: "${moduleTitle}"
Chapter: "${chapter}" | Subject: ${subject} | Class: ${cls} | Board: CBSE

${transcriptSection}

Return ONLY valid JSON (no markdown, no preamble):
{
  "notes": {
    "summary": "3-4 substantial paragraphs covering the module content",
    "keyConcepts": [{"term": "string", "definition": "1-2 sentences"}],
    "keyPoints": ["10 key points as complete sentences with explanation"],
    "formulas": ["formulas with units and when to use them — empty array if not applicable"],
    "solvedExample": "One worked example relevant to this module (null if not applicable)",
    "commonMistakes": ["3 common mistakes students make"],
    "examTips": ["3 specific exam tips for this sub-topic"]
  },
  "qa": [
    {"q": "question", "a": "3-4 sentence answer", "difficulty": "Easy|Medium|Hard"}
  ],
  "quiz": [
    {"q": "question text", "opts": ["A", "B", "C", "D"], "ans": 0, "exp": "explanation why correct"}
  ]
}
Include exactly 6 Q&A items and 8 quiz questions. "ans" is 0-indexed.`;

  const r = await callAI([{ role: 'user', content: prompt }], '', 5000, 'notes');
  try {
    const parsed = JSON.parse(r.text.replace(/```[\w]*\n?/g, '').trim());
    if (!parsed?.notes) throw new Error('No notes');
    return { notes: parsed.notes, qa: parsed.qa || [], quiz: parsed.quiz || [] };
  } catch {
    return {
      notes: {
        summary: `Content for "${moduleTitle}" is being prepared. Please retry in a moment.`,
        keyConcepts: [], keyPoints: [], formulas: [], solvedExample: null, commonMistakes: [], examTips: [],
      },
      qa: [], quiz: [],
    };
  }
}

// ════════════════════════════════════════════════════════════════
//  SSE EVENT BUS (in-memory, for real-time progress streaming)
// ════════════════════════════════════════════════════════════════
const { EventEmitter } = require('events');
const moduleEventBus = new Map(); // courseKey → EventEmitter

function emitModuleEvent(courseKey, data) {
  moduleEventBus.get(courseKey)?.emit('update', data);
}

// ════════════════════════════════════════════════════════════════
//  CACHE HELPERS (Supabase chapter_cache table)
// ════════════════════════════════════════════════════════════════

function moduleListKey(subject, cls, chapter) {
  const safe = s => s.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 20);
  return `bscm-list-${safe(subject)}-${safe(cls)}-${safe(chapter)}`;
}

function moduleContentKey(subject, cls, chapter, moduleId) {
  const safe = s => s.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 16);
  return `bscm-mod-${safe(subject)}-${safe(cls)}-${safe(chapter)}-${moduleId}`;
}

async function getCacheEntry(key) {
  try {
    const { data } = await db.from('chapter_cache').select('*').eq('cache_key', key).maybeSingle();
    return data || null;
  } catch { return null; }
}

async function setCacheEntry(key, payload, meta = {}) {
  try {
    await db.from('chapter_cache').upsert({
      cache_key: key,
      notes:     JSON.stringify(payload), // reuse notes column for JSON blobs
      subject:   meta.subject || '',
      class_level: meta.cls || '',
      chapter:   meta.chapter || '',
      updated_at: new Date().toISOString(),
    }, { onConflict: 'cache_key' });
  } catch (e) { console.error('[setCacheEntry]', e.message); }
}

// ════════════════════════════════════════════════════════════════
//  MODULE COUNT based on role
// ════════════════════════════════════════════════════════════════
function getModuleCount(user) {
  // Teachers / pro: 12 modules; Students: 10
  if (user.role === 'teacher') return 12;
  if (user.subscription_status === 'active') return 12;
  return 10;
}

// ════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/chapter-courses/list/:key
 * Returns the cached module list for a chapter (or null if not generated yet).
 */
app.get('/api/chapter-courses/list/:key', async (req, res) => {
  const entry = await getCacheEntry(req.params.key);
  if (!entry) return res.json(null);
  try {
    const parsed = JSON.parse(entry.notes);
    
    // Check if any modules need reprocessing
    const modules = parsed?.modules || [];
    const hasProblems = modules.some(m => 
      m.status === 'error' || 
      m.status === 'pending' ||
      (m.status === 'done' && (!m.videoId || !m.transcriptStatus))
    );
    
    // If more than 30% modules are broken, invalidate entire cache
    const brokenCount = modules.filter(m => 
      m.status === 'error' || m.status === 'pending'
    ).length;
    
    if (brokenCount > modules.length * 0.3) {
      await db.from('chapter_cache').delete().eq('cache_key', req.params.key);
      return res.json(null); // Forces full regeneration
    }
    
    res.json(parsed);
  } catch { res.json(null); }
});

app.post('/api/chapter-courses/module/retry', verifyToken, checkAccess, async (req, res) => {
  const { subject, cls, chapter, moduleId, moduleTitle, searchQuery } = req.body;
  if (!subject || !cls || !chapter || moduleId === undefined)
    return res.status(400).json({ error: 'Missing fields' });

  const modKey = moduleContentKey(subject, cls, chapter, moduleId);
  const listKey = moduleListKey(subject, cls, chapter);

  res.json({ ok: true }); // respond immediately

  (async () => {
    try {
      // Search YouTube
      const searchQ = `${searchQuery || moduleTitle} ${subject} ${cls} CBSE explained`;
      const videos  = await ytSearch(searchQ, 5);
      const { transcript, videoId: bestVidId } = await getBestTranscript(videos);
      const topVideo = videos.find(v => v.videoId === bestVidId) || videos[0] || null;

      // Regenerate content
      const content = await aiGenerateModuleContent(
        moduleTitle, chapter, subject, cls, transcript
      );

      // Save module content
      await setCacheEntry(modKey, {
        moduleId, title: moduleTitle,
        videoId:         bestVidId || null,
        videoTitle:      topVideo?.title || null,
        videoChannel:    topVideo?.channel || null,
        videoThumbnail:  topVideo?.thumbnail || null,
        searchResults:   videos,
        transcript:      transcript || null,
        transcriptStatus: transcript ? 'success' : bestVidId ? 'unavailable' : 'none',
        notes:    content.notes,
        qa:       content.qa,
        quiz:     content.quiz,
        generatedAt: new Date().toISOString(),
      }, { subject, cls, chapter });

      // Update module status in list cache to 'done'
      const listEntry = await getCacheEntry(listKey);
      if (listEntry) {
        const parsed = JSON.parse(listEntry.notes);
        const idx = parsed.modules.findIndex(m => m.id === moduleId);
        if (idx > -1) {
          parsed.modules[idx] = {
            ...parsed.modules[idx],
            status:          'done',
            videoId:         bestVidId || null,
            videoTitle:      topVideo?.title || null,
            transcriptStatus: transcript ? 'success' : 'unavailable',
          };
          await setCacheEntry(listKey, parsed, { subject, cls, chapter });
        }
      }
    } catch (e) {
      console.error('[module retry]', e.message);
    }
  })();
});

/**
 * GET /api/chapter-courses/module/:key
 * Returns cached content for a single module (or null).
 */
app.get('/api/chapter-courses/module/:key', async (req, res) => {
  const entry = await getCacheEntry(req.params.key);
  if (!entry) return res.json(null);
  try { res.json(JSON.parse(entry.notes)); }
  catch { res.json(null); }
});

/**
 * POST /api/chapter-courses/generate
 * Starts background generation of ALL modules for a chapter.
 * Returns immediately with { courseKey, existing: bool }
 * Frontend should then connect to SSE stream.
 */
app.post('/api/chapter-courses/generate', verifyToken, checkAccess, async (req, res) => {
  const { subject, cls, chapter } = req.body;
  if (!subject || !cls || !chapter)
    return res.status(400).json({ error: 'subject, cls, chapter required' });

  const listKey = moduleListKey(subject, cls, chapter);

  // Return existing if already generated
  const existing = await getCacheEntry(listKey);
  if (existing) {
    try {
      const parsed = JSON.parse(existing.notes);
      if (parsed?.modules?.length) return res.json({ courseKey: listKey, existing: true });
    } catch {}
  }

  // Start generation in background
  res.json({ courseKey: listKey, existing: false });

  const moduleCount = getModuleCount(req.user);
  generateChapterCourse(listKey, subject, cls, chapter, moduleCount, req.user.id).catch(e =>
    console.error('[generateChapterCourse]', e.message)
  );
});

/**
 * GET /api/chapter-courses/stream/:key
 * SSE endpoint for real-time generation progress.
 * Query param: token=<jwt>  (for SSE which can't set Authorization header)
 */
app.get('/api/chapter-courses/stream/:key', async (req, res) => {
  // Auth via query param for SSE
  const token = req.headers.authorization?.slice(7) || req.query.token;
  if (!token) return res.status(401).json({ error: 'token required' });
  try { jwt.verify(token, process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'invalid token' }); }

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const courseKey = req.params.key;
  const send      = data => res.write(`data: ${JSON.stringify(data)}\n\n`);
  const keepAlive = setInterval(() => res.write(': ping\n\n'), 20000);
  const emitter   = moduleEventBus.get(courseKey);

  send({ type: 'connected' });

  if (!emitter) {
    // Check if already done
    const cached = await getCacheEntry(courseKey);
    if (cached) {
      try { send({ type: 'already_done', data: JSON.parse(cached.notes) }); }
      catch {}
    } else {
      send({ type: 'no_stream' });
    }
    clearInterval(keepAlive);
    return res.end();
  }

  emitter.on('update', send);
  req.on('close', () => {
    clearInterval(keepAlive);
    emitter.off('update', send);
  });
});

/**
 * POST /api/chapter-courses/module/regenerate
 * Regenerates content for a single module (e.g. after swapping video).
 */
app.post('/api/chapter-courses/module/regenerate', verifyToken, checkAccess, async (req, res) => {
  const { subject, cls, chapter, moduleId, videoId, moduleTitle, searchQuery } = req.body;
  if (!subject || !cls || !chapter || moduleId === undefined)
    return res.status(400).json({ error: 'subject, cls, chapter, moduleId required' });

  const modKey = moduleContentKey(subject, cls, chapter, moduleId);
  res.json({ ok: true, modKey });

  // Background: fetch transcript for new video, regenerate content
  (async () => {
    try {
      let transcript = null;
      if (videoId) {
        transcript = await ytTranscript(videoId);
      } else if (searchQuery) {
        const videos = await ytSearch(`${searchQuery} ${subject} ${cls} CBSE`, 5);
        const best   = await getBestTranscript(videos);
        transcript = best.transcript;
      }

      const content = await aiGenerateModuleContent(
        moduleTitle || `Module ${moduleId}`, chapter, subject, cls, transcript
      );

      // Get existing module data and merge
      const existing = await getCacheEntry(modKey);
      let modData = {};
      try { modData = JSON.parse(existing?.notes || '{}'); } catch {}

      await setCacheEntry(modKey, {
        ...modData,
        notes:      content.notes,
        qa:         content.qa,
        quiz:       content.quiz,
        transcript: transcript || null,
        transcriptStatus: transcript ? 'success' : 'unavailable',
        videoId:    videoId || modData.videoId,
      }, { subject, cls, chapter });
    } catch (e) {
      console.error('[module regenerate]', e.message);
    }
  })();
});

/**
 * PATCH /api/chapter-courses/module/video
 * Swap to a different video for a module — triggers transcript fetch + content regen.
 * Returns new search results for the module.
 */
app.patch('/api/chapter-courses/module/video', verifyToken, async (req, res) => {
  const { subject, cls, chapter, moduleId, newVideoId, moduleTitle } = req.body;
  if (!subject || !cls || !chapter || moduleId === undefined || !newVideoId)
    return res.status(400).json({ error: 'Missing required fields' });

  const modKey = moduleContentKey(subject, cls, chapter, moduleId);

  // Update videoId immediately for UX
  const existing = await getCacheEntry(modKey);
  let modData = {};
  try { modData = JSON.parse(existing?.notes || '{}'); } catch {}

  await setCacheEntry(modKey, {
    ...modData,
    videoId: newVideoId,
    transcriptStatus: 'pending',
  }, { subject, cls, chapter });

  res.json({ ok: true, videoId: newVideoId });

  // Background: fetch transcript + regenerate
  (async () => {
    try {
      const transcript = await ytTranscript(newVideoId);
      const content    = await aiGenerateModuleContent(
        moduleTitle || `Module ${moduleId}`, chapter, subject, cls, transcript
      );
      await setCacheEntry(modKey, {
        ...modData,
        videoId:          newVideoId,
        notes:            content.notes,
        qa:               content.qa,
        quiz:             content.quiz,
        transcript:       transcript || null,
        transcriptStatus: transcript ? 'success' : 'unavailable',
      }, { subject, cls, chapter });
    } catch (e) {
      console.error('[swap video regen]', e.message);
    }
  })();
});

// ════════════════════════════════════════════════════════════════
//  BACKGROUND GENERATION ENGINE
// ════════════════════════════════════════════════════════════════
async function generateChapterCourse(listKey, subject, cls, chapter, moduleCount, userId) {
  const emitter = new EventEmitter();
  emitter.setMaxListeners(100);
  moduleEventBus.set(listKey, emitter);

  const emit = data => emitter.emit('update', data);

  try {
    // ── Step 1: Generate module structure ────────────────────
    emit({ type: 'status', message: `Designing ${moduleCount} modules for "${chapter}"…` });

    const modules = await aiGenerateModuleList(subject, cls, chapter, moduleCount);
    if (!modules?.length) throw new Error('Module generation failed');

    // Save module list skeleton immediately (no content yet)
    const skeleton = modules.map(m => ({
      ...m,
      status: 'pending',  // pending | building | done | error
      videoId: null,
      videoTitle: null,
      videoChannel: null,
      videoThumbnail: null,
      searchResults: [],
    }));

    await setCacheEntry(listKey, { modules: skeleton, generatedAt: new Date().toISOString() }, { subject, cls, chapter });
    emit({ type: 'modules_listed', modules: skeleton });

    // ── Step 2: Process each module sequentially ──────────────
    // Sequential gives better quality (no rate-limit collisions)
    for (const mod of modules) {
      const modKey = moduleContentKey(subject, cls, chapter, mod.id);
      emit({ type: 'module_building', moduleId: mod.id, title: mod.title });

      try {
        // Search YouTube
        const searchQ = `${mod.searchQuery || mod.title} ${subject} ${cls} CBSE explained`;
        const videos  = await ytSearch(searchQ, 5);

        // Get best transcript
        const { transcript, videoId: bestVidId } = await getBestTranscript(videos);
        const topVideo = videos.find(v => v.videoId === bestVidId) || videos[0] || null;

        // Generate content
        const content = await aiGenerateModuleContent(
          mod.title, chapter, subject, cls, transcript
        );

        // Cache module content
        const modData = {
          moduleId:        mod.id,
          title:           mod.title,
          description:     mod.description,
          emoji:           mod.emoji,
          estimatedMinutes: mod.estimatedMinutes,
          keyTopics:       mod.keyTopics,
          videoId:         bestVidId || null,
          videoTitle:      topVideo?.title || null,
          videoChannel:    topVideo?.channel || null,
          videoThumbnail:  topVideo?.thumbnail || null,
          searchResults:   videos,
          transcript:      transcript || null,
          transcriptStatus: transcript ? 'success' : bestVidId ? 'unavailable' : 'none',
          notes:           content.notes,
          qa:              content.qa,
          quiz:            content.quiz,
          generatedAt:     new Date().toISOString(),
        };
        await setCacheEntry(modKey, modData, { subject, cls, chapter });

        // Update skeleton with video info
        skeleton[mod.id - 1] = {
          ...skeleton[mod.id - 1],
          status:          'done',
          videoId:         bestVidId || null,
          videoTitle:      topVideo?.title || null,
          videoChannel:    topVideo?.channel || null,
          videoThumbnail:  topVideo?.thumbnail || null,
          transcriptStatus: modData.transcriptStatus,
        };
        await setCacheEntry(listKey, { modules: skeleton, generatedAt: new Date().toISOString() }, { subject, cls, chapter });

        emit({ type: 'module_done', moduleId: mod.id, videoId: bestVidId, transcriptStatus: modData.transcriptStatus });

        // Brief pause to avoid rate limits
        await new Promise(r => setTimeout(r, 800));

      } catch (e) {
        console.error(`[module ${mod.id} error]`, e.message);
        skeleton[mod.id - 1].status = 'error';
        await setCacheEntry(listKey, { modules: skeleton, generatedAt: new Date().toISOString() }, { subject, cls, chapter });
        emit({ type: 'module_error', moduleId: mod.id });
      }
    }

    emit({ type: 'generation_complete', modules: skeleton });
    logActivity(userId, 'notes', { subject, chapter, xpEarned: 30 }).catch(() => {});

  } catch (e) {
    console.error('[generateChapterCourse]', e.message);
    emit({ type: 'error', message: e.message });
  } finally {
    // Clean up emitter after 3 minutes
    setTimeout(() => moduleEventBus.delete(listKey), 3 * 60 * 1000);
  }
}
// ═══════════ END OF MODULE COURSE ADDITIONS ═══════════════════


// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ════════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  let ai = 'unknown';
  try {
    await anthropic.messages.create({ model: 'claude-haiku-4-5-20251001', max_tokens: 10, messages: [{ role: 'user', content: 'ok' }] });
    ai = 'claude:ok';
  } catch (e) { ai = `claude:error`; }
  res.json({
    status:   'ok',
    time:     new Date().toISOString(),
    version:  '5.0.0',
    ai,
    openai:   !!openai,
    groq:     !!groq,
    razorpay: !!razorpay,
    email:    !!mailer,
  });
});

// ════════════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => { console.error('[Unhandled]', err); res.status(500).json({ error: 'Internal server error' }); });
app.use((req, res) => res.status(404).json({ error: `Not found: ${req.method} ${req.path}` }));

app.listen(PORT, () => {
  console.log(`\n🚀 BrainSpark AI v5 — http://localhost:${PORT}`);
  console.log(`   Claude:   ${process.env.ANTHROPIC_API_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   OpenAI:   ${process.env.OPENAI_API_KEY   ? '✅' : '⚠️  not set (fallback disabled)'}`);
  console.log(`   Groq:     ${process.env.GROQ_API_KEY     ? '✅' : '⚠️  not set (fallback disabled)'}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL     ? '✅' : '❌ MISSING'}`);
  console.log(`   Razorpay: ${process.env.RAZORPAY_KEY_ID  ? '✅' : '⚠️  not set (payments disabled)'}`);
  console.log(`   Email:    ${process.env.EMAIL_USER       ? '✅' : '⚠️  not set (password reset disabled)'}\n`);
});
