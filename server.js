/**
 * BrainSpark AI — Backend Server v3.0
 * Node.js + Express
 *
 * NEW in v3:
 *  - Single-device enforcement (session tokens)
 *  - Free-tier (60 min) tracking for personal users
 *  - Razorpay subscription payments (India)
 *  - Password reset via email (Nodemailer)
 *  - Microsoft OAuth (Graph API)
 *  - Google OAuth fixed
 *  - Achievement auto-unlock system (44 achievements)
 *  - Cheat Sheet AI route (student feature)
 *  - Lesson Planner AI route (teacher feature)
 *  - Multi-chapter question paper
 *  - Enhanced notes prompts
 *
 * INSTALL:
 *   npm install express cors bcryptjs jsonwebtoken express-rate-limit helmet
 *              morgan @supabase/supabase-js @google/generative-ai groq-sdk
 *              google-auth-library razorpay nodemailer crypto dotenv
 */

const express           = require('express');
const cors              = require('cors');
const bcrypt            = require('bcryptjs');
const jwt               = require('jsonwebtoken');
const rateLimit         = require('express-rate-limit');
const helmet            = require('helmet');
const morgan            = require('morgan');
const { createClient }  = require('@supabase/supabase-js');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const Groq              = require('groq-sdk');
const { OAuth2Client }  = require('google-auth-library');
const Razorpay          = require('razorpay');
const nodemailer        = require('nodemailer');
const crypto            = require('crypto');
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
    const ok = allowed.includes(origin) || origin.includes('vercel.app');
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

const genAI      = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const groq       = process.env.GROQ_API_KEY ? new Groq({ apiKey: process.env.GROQ_API_KEY }) : null;
const googleAuth = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const razorpay = process.env.RAZORPAY_KEY_ID
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const mailer = process.env.EMAIL_USER
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } })
  : null;

// ════════════════════════════════════════════════════════════════
//  AI Abstraction Layer
// ════════════════════════════════════════════════════════════════
async function callAI(messages, system = '', maxTokens = 2000) {
  try {
    const model = genAI.getGenerativeModel({
      model: 'gemini-2.5-flash',
      systemInstruction: system || undefined,
    });
    const history = messages.slice(0, -1).map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));
    const chat   = model.startChat({ history, generationConfig: { maxOutputTokens: maxTokens } });
    const result = await chat.sendMessage(messages[messages.length - 1].content);
    return { text: result.response.text(), provider: 'gemini' };
  } catch (err) {
    console.warn('[Gemini] fallback:', err.message);
    if (!groq) throw new Error('AI service unavailable.');
    const msgs = [];
    if (system) msgs.push({ role: 'system', content: system });
    messages.forEach(m => msgs.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));
    const r = await groq.chat.completions.create({ model: 'llama-3.3-70b-versatile', messages: msgs, max_tokens: maxTokens, temperature: 0.7 });
    return { text: r.choices[0].message.content, provider: 'groq' };
  }
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
  const auth  = req.headers.authorization;
  const stok  = req.headers['x-session-token'];
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
  // Single-device check
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
//  Free-Tier Middleware  (personal users: 60 min free)
// ════════════════════════════════════════════════════════════════
async function checkAccess(req, res, next) {
  // School users always have access (school manages subscription)
  if (req.user.type === 'school') return next();

  const { data: u } = await db.from('users')
    .select('subscription_status, subscription_expires_at, free_tier_minutes_used, free_tier_exhausted')
    .eq('id', req.user.id).single();

  // Active paid subscription
  if (u?.subscription_status === 'active' && u.subscription_expires_at && new Date(u.subscription_expires_at) > new Date()) {
    return next();
  }

  // Free tier exhausted
  if (u?.free_tier_exhausted || (u?.free_tier_minutes_used || 0) >= 60) {
    await db.from('users').update({ free_tier_exhausted: true }).eq('id', req.user.id);
    return res.status(402).json({
      error: 'Your free 1-hour trial has ended.',
      code: 'SUBSCRIPTION_REQUIRED',
      minutesUsed: u?.free_tier_minutes_used || 60,
    });
  }
  req.freeMinutesRemaining = 60 - (u?.free_tier_minutes_used || 0);
  next();
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

    const counters = { doubt: 'doubts_solved', quiz: 'quizzes_done', notes: 'notes_made',
      paper: 'papers_made', flashcards: 'flashcards_made', cheatsheet: 'cheat_sheets_made', lessonplan: 'lesson_plans_made' };
    if (counters[tool]) await db.rpc('increment_counter', { p_user_id: userId, p_field: counters[tool] });

    // Behavioral flags
    const hour = new Date().getHours();
    if (hour >= 22) await db.from('user_xp').update({ night_owl_unlocked: true }).eq('user_id', userId).eq('night_owl_unlocked', false);
    if (hour < 7)  await db.from('user_xp').update({ early_bird_unlocked: true }).eq('user_id', userId).eq('early_bird_unlocked', false);

    // Tools-used-today tracking
    const today = new Date().toISOString().split('T')[0];
    const { data: xpRow } = await db.from('user_xp').select('tools_used_today, tools_used_today_date, subjects_used').eq('user_id', userId).single();
    if (xpRow) {
      const sameDay   = xpRow.tools_used_today_date === today;
      const tools     = [...new Set([...(sameDay ? xpRow.tools_used_today || [] : []), tool])];
      const subjects  = [...new Set([...(xpRow.subjects_used || []), ...(subject ? [subject] : [])])];
      await db.from('user_xp').update({ tools_used_today: tools, tools_used_today_date: today, subjects_used: subjects }).eq('user_id', userId);
    }

    // Free-tier usage: 2 min per AI call for personal users
    const { data: uRow } = await db.from('users').select('type, free_tier_minutes_used').eq('id', userId).single();
    if (uRow?.type === 'personal') {
      const used = (uRow.free_tier_minutes_used || 0) + 2;
      await db.from('users').update({ free_tier_minutes_used: used, free_tier_exhausted: used >= 60, last_active_at: new Date().toISOString() }).eq('id', userId);
    }

    // Async achievement check
    checkAchievements(userId).catch(() => {});
  } catch (e) { console.error('[logActivity]', e.message); }
}

// ════════════════════════════════════════════════════════════════
//  Achievement Engine
// ════════════════════════════════════════════════════════════════
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

// Register (personal)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role = 'student' } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be ≥ 8 characters' });
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

// Login (personal)
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

// Google OAuth
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

// Microsoft OAuth  (frontend sends access_token from MSAL)
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

// School Login  (student or teacher)
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

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const { data: user } = await db.from('users').select('id, name').eq('email', email.toLowerCase()).maybeSingle();
    // Always return success (don't leak whether email exists)
    if (!user || !mailer) return res.json({ success: true, message: 'If that email exists, a reset link was sent.' });

    const token = crypto.randomBytes(32).toString('hex');
    await db.from('password_reset_tokens').insert({
      email: email.toLowerCase(), token,
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1 hour
    });

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await mailer.sendMail({
      from:    `"BrainSpark AI" <${process.env.EMAIL_USER}>`,
      to:      email,
      subject: 'Reset your BrainSpark AI password',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px">
          <h2 style="color:#6366F1">Password Reset</h2>
          <p>Hi ${user.name},</p>
          <p>Click the button below to reset your password. This link expires in 1 hour.</p>
          <a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:12px 24px;background:#6366F1;color:#fff;text-decoration:none;border-radius:8px;font-weight:700">Reset Password</a>
          <p style="color:#888;font-size:12px">If you didn't request this, ignore this email.</p>
        </div>`,
    });

    res.json({ success: true, message: 'If that email exists, a reset link was sent.' });
  } catch (e) { console.error('[forgot-password]', e); res.status(500).json({ error: 'Failed to send reset email.' }); }
});

// Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be ≥ 8 characters' });

    const { data: rec } = await db.from('password_reset_tokens')
      .select('*').eq('token', token).eq('used', false).maybeSingle();
    if (!rec || new Date(rec.expires_at) < new Date()) return res.status(400).json({ error: 'Invalid or expired reset link.' });

    await db.from('users').update({ password_hash: await bcrypt.hash(newPassword, 12), updated_at: new Date().toISOString() }).eq('email', rec.email);
    await db.from('password_reset_tokens').update({ used: true }).eq('id', rec.id);

    res.json({ success: true });
  } catch (e) { console.error('[reset-password]', e); res.status(500).json({ error: 'Reset failed.' }); }
});

// Me
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const { data: user } = await db.from('users').select('*, schools(name, school_code, logo_url)').eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Logout (invalidate session)
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
      ...(name                 && { name: name.trim() }),
      ...(bio         !== undefined && { bio }),
      ...(phone       !== undefined && { phone }),
      ...(classLevel  !== undefined && { class_level: classLevel }),
      ...(section     !== undefined && { section }),
      ...(subjectSpecialization !== undefined && { subject_specialization: subjectSpecialization }),
      ...(preferredSubjects     !== undefined && { preferred_subjects: preferredSubjects }),
      updated_at: new Date().toISOString(),
    }).eq('id', req.user.id).select().single();
    if (error) throw error;
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be ≥ 8 characters' });
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

// Achievements
app.get('/api/user/achievements', verifyToken, async (req, res) => {
  const { data: all } = await db.from('achievements').select('*').order('sort_order');
  const { data: unlocked } = await db.from('user_achievements').select('achievement_id, unlocked_at').eq('user_id', req.user.id);
  const unlockedMap = Object.fromEntries((unlocked || []).map(u => [u.achievement_id, u.unlocked_at]));
  res.json((all || []).map(a => ({ ...a, unlocked: !!unlockedMap[a.id], unlocked_at: unlockedMap[a.id] || null })));
});

// Subscription status
app.get('/api/user/subscription', verifyToken, async (req, res) => {
  const { data: user } = await db.from('users').select('subscription_status, subscription_plan, subscription_expires_at, free_tier_minutes_used, free_tier_exhausted, type, role').eq('id', req.user.id).single();
  res.json(user);
});

// ── Saved Notes ────────────────────────────────────────────────
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

// ── Saved Papers ───────────────────────────────────────────────
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

// ── Cheat Sheets ───────────────────────────────────────────────
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

// ── Lesson Plans ───────────────────────────────────────────────
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

// ── Quiz History ───────────────────────────────────────────────
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
  // Increment perfect counter if needed
  if (isPerfect) await db.rpc('increment_counter', { p_user_id: req.user.id, p_field: 'quizzes_perfect' });
  res.status(201).json(data);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: AI (all protected + access-checked)
// ════════════════════════════════════════════════════════════════

const AI_CONFIGS = {
  doubt:      { xp: 15, maxTokens: 800,  label: 'doubt'      },
  quiz:       { xp: 5,  maxTokens: 1500, label: 'quiz'       },
  notes:      { xp: 20, maxTokens: 2500, label: 'notes'      },
  paper:      { xp: 25, maxTokens: 3000, label: 'paper'      },
  flashcards: { xp: 15, maxTokens: 1200, label: 'flashcards' },
  cheatsheet: { xp: 30, maxTokens: 4000, label: 'cheatsheet' },
  lessonplan: { xp: 30, maxTokens: 4000, label: 'lessonplan' },
};

app.post('/api/ai/:tool', verifyToken, checkAccess, aiLimiter, async (req, res) => {
  const cfg = AI_CONFIGS[req.params.tool];
  if (!cfg) return res.status(400).json({ error: `Unknown tool: ${req.params.tool}` });

  try {
    const { messages, system = '', subject = '', chapter = '', chapters = [] } = req.body;
    if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'Messages array required' });

    const { text, provider } = await callAI(messages, system, cfg.maxTokens);

    logActivity(req.user.id, cfg.label, { subject, chapter, chapters, xpEarned: cfg.xp, provider, meta: { subject, chapter } }).catch(console.error);

    const resp = { content: text, xpEarned: cfg.xp, provider };
    if (req.freeMinutesRemaining !== undefined) resp.freeMinutesRemaining = Math.max(0, req.freeMinutesRemaining - 2);
    res.json(resp);
  } catch (e) {
    console.error(`[AI /${req.params.tool}]`, e.message);
    if (e.message?.includes('429') || e.message?.includes('quota')) return res.status(429).json({ error: 'AI is busy. Try again in a moment.' });
    res.status(500).json({ error: 'AI service error.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SUBSCRIPTION  (Razorpay)
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
      amount:   plan.amount,
      currency: 'INR',
      receipt:  `bs_${req.user.id.slice(0, 8)}_${Date.now()}`,
      notes:    { userId: req.user.id, planType },
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
      status: 'active', starts_at: new Date().toISOString(), expires_at: exp.toISOString(), updated_at: new Date().toISOString(),
    }).eq('razorpay_order_id', orderId);

    await db.from('users').update({
      subscription_status: 'active', subscription_plan: planType, subscription_expires_at: exp.toISOString(),
    }).eq('id', req.user.id);

    res.json({ success: true, expiresAt: exp.toISOString() });
  } catch (e) { console.error('[verify]', e); res.status(500).json({ error: 'Verification error.' }); }
});

// School subscription (admin creates)
app.post('/api/subscription/school', verifyAdmin, async (req, res) => {
  try {
    if (!razorpay) return res.status(503).json({ error: 'Payment not configured' });
    const { schoolCode, studentCount = 0, teacherCount = 0, planMonths = 12 } = req.body;
    const { data: school } = await db.from('schools').select('id').eq('school_code', schoolCode.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });

    const studentCost = studentCount * (planMonths === 12 ? 130000 : 13000) * studentCount;
    const teacherCost = teacherCount * (planMonths === 12 ? 150000 : 15000) * teacherCount;
    // NOTE: amounts are per-person. Calculate properly:
    const stuTotal = studentCount * (planMonths >= 12 ? 130000 : 13000); // 1300/yr or 130/mo in paise
    const tchTotal = teacherCount * (planMonths >= 12 ? 150000 : 15000);
    const total    = stuTotal + tchTotal;

    const exp = new Date(Date.now() + planMonths * 30 * 24 * 60 * 60 * 1000);
    await db.from('schools').update({ subscription_status: 'active', subscription_expires_at: exp.toISOString(), student_slots: studentCount, teacher_slots: teacherCount }).eq('id', school.id);
    await db.from('subscriptions').insert({ school_id: school.id, plan_type: 'school', amount_paise: total, status: 'active', starts_at: new Date().toISOString(), expires_at: exp.toISOString(), student_count: studentCount, teacher_count: teacherCount });

    res.json({ success: true, expiresAt: exp.toISOString(), totalPaise: total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL ADMIN
// ════════════════════════════════════════════════════════════════

app.post('/api/admin/schools', verifyAdmin, async (req, res) => {
  try {
    const { name, schoolCode, address, city, state, contactEmail, contactPhone, maxStudents = 500, maxTeachers = 50 } = req.body;
    if (!name || !schoolCode) return res.status(400).json({ error: 'Name and code required' });
    const { data, error } = await db.from('schools').insert({ name: name.trim(), school_code: schoolCode.toUpperCase().trim(), address, city, state, contact_email: contactEmail, contact_phone: contactPhone, max_students: maxStudents, max_teachers: maxTeachers }).select().single();
    if (error?.code === '23505') return res.status(409).json({ error: 'School code already exists' });
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/schools', verifyAdmin, async (req, res) => {
  const { data } = await db.from('schools').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

// Bulk import students (from Excel-parsed JSON on frontend)
app.post('/api/admin/schools/:code/students', verifyAdmin, async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });
    const { students } = req.body;
    if (!Array.isArray(students) || !students.length) return res.status(400).json({ error: 'students array required' });
    const rows = await Promise.all(students.map(async s => ({
      school_id: school.id, roll_number: s.rollNumber?.trim(), name: s.name?.trim(),
      class_level: s.class || s.classLevel || '', section: s.section || '', email: s.email || null,
      phone: s.phone || null, parent_name: s.parentName || null, parent_phone: s.parentPhone || null,
      password_hash: await bcrypt.hash(s.password || s.rollNumber?.trim(), 12),
    })));
    const { data, error } = await db.from('school_students').upsert(rows, { onConflict: 'school_id,roll_number' }).select();
    if (error) throw error;
    res.json({ success: true, imported: data.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bulk import teachers
app.post('/api/admin/schools/:code/teachers', verifyAdmin, async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });
    const { teachers } = req.body;
    if (!Array.isArray(teachers) || !teachers.length) return res.status(400).json({ error: 'teachers array required' });
    const rows = await Promise.all(teachers.map(async t => ({
      school_id: school.id, employee_id: t.employeeId?.trim(), name: t.name?.trim(),
      subjects: t.subjects || [], email: t.email || null, phone: t.phone || null,
      qualification: t.qualification || null, experience_years: t.experienceYears || null,
      password_hash: await bcrypt.hash(t.password || t.employeeId?.trim(), 12),
    })));
    const { data, error } = await db.from('school_teachers').upsert(rows, { onConflict: 'school_id,employee_id' }).select();
    if (error) throw error;
    res.json({ success: true, imported: data.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/schools/:code/students', verifyAdmin, async (req, res) => {
  const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
  if (!school) return res.status(404).json({ error: 'School not found' });
  const { data } = await db.from('school_students').select('roll_number,name,class_level,section,is_active,created_at').eq('school_id', school.id).order('class_level').order('roll_number');
  res.json(data || []);
});

app.put('/api/admin/schools/:code/status', verifyAdmin, async (req, res) => {
  const { data } = await db.from('schools').update({ is_active: req.body.isActive }).eq('school_code', req.params.code.toUpperCase()).select().single();
  res.json(data);
});

// ════════════════════════════════════════════════════════════════
//  HEALTH
// ════════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  let ai = 'unknown';
  try { const m = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' }); await m.generateContent('ok'); ai = 'ok'; } catch (e) { ai = 'error'; }
  res.json({ status: 'ok', time: new Date().toISOString(), version: '3.0.0', ai, razorpay: !!razorpay, email: !!mailer });
});

// ════════════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => { console.error('[Unhandled]', err); res.status(500).json({ error: 'Internal server error' }); });
app.use((req, res) => res.status(404).json({ error: `Not found: ${req.method} ${req.path}` }));

app.listen(PORT, () => {
  console.log(`\n🚀 BrainSpark AI v3 — http://localhost:${PORT}`);
  console.log(`   Gemini:   ${process.env.GEMINI_API_KEY ? '✅' : '❌ MISSING'}`);
  console.log(`   Groq:     ${process.env.GROQ_API_KEY   ? '✅' : '⚠️  not set'}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL   ? '✅' : '❌ MISSING'}`);
  console.log(`   Razorpay: ${process.env.RAZORPAY_KEY_ID ? '✅' : '⚠️  not set (payments disabled)'}`);
  console.log(`   Email:    ${process.env.EMAIL_USER     ? '✅' : '⚠️  not set (password reset disabled)'}\n`);
});
