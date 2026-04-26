/**
 * BrainSpark AI — Backend Server
 * Node.js + Express
 * AI: Google Gemini 2.0 Flash (FREE) + Groq/Llama fallback (FREE)
 *
 * HOW TO RUN:
 *   npm install
 *   cp .env.example .env   ← fill in your keys
 *   node server.js         ← or: npm run dev
 */

const express          = require('express');
const cors             = require('cors');
const bcrypt           = require('bcryptjs');
const jwt              = require('jsonwebtoken');
const rateLimit        = require('express-rate-limit');
const helmet           = require('helmet');
const morgan           = require('morgan');
const { createClient } = require('@supabase/supabase-js');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const Groq             = require('groq-sdk');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

// ════════════════════════════════════════════════════════════════
//  App & Middleware
// ════════════════════════════════════════════════════════════════
const app  = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(morgan('dev'));
app.use(cors({
  origin:      process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// Rate limits
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: 'Too many requests. Please wait.' });
app.use(globalLimiter);

// AI routes: 60 req / 15 min per IP (generous since Gemini is free)
const aiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, message: 'AI rate limit reached. Please wait a moment.' });

// ════════════════════════════════════════════════════════════════
//  Service Clients
// ════════════════════════════════════════════════════════════════

// Supabase — use service_role key to bypass RLS
const db = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Google Gemini — FREE tier
// Get key: aistudio.google.com → Get API Key
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiModel = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

// Groq — FREE tier fallback (llama-3.3-70b)
// Get key: console.groq.com → API Keys
const groq = process.env.GROQ_API_KEY
  ? new Groq({ apiKey: process.env.GROQ_API_KEY })
  : null;

// Google OAuth verifier (for Google Sign-In)
const googleOAuth = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ════════════════════════════════════════════════════════════════
//  AI Abstraction Layer
//  Calls Gemini first. If it fails (quota / error), falls back to Groq.
// ════════════════════════════════════════════════════════════════

/**
 * callAI(messages, system)
 *
 * messages = [{ role: 'user'|'assistant', content: '...' }]
 * system   = string (system prompt)
 *
 * Returns: { text: string, provider: 'gemini'|'groq' }
 */
async function callAI(messages, system = '', maxTokens = 1000) {
  // ── Try Gemini first ──────────────────────────────────────────
  try {
    const gemini = genAI.getGenerativeModel({
      model: 'gemini-2.5-flash',
      systemInstruction: system || undefined,
    });

    // Convert our message format → Gemini format
    // Gemini uses { role: 'user'|'model', parts: [{ text }] }
    const history = messages.slice(0, -1).map(m => ({
      role:  m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));
    const lastMsg = messages[messages.length - 1].content;

    const chat   = gemini.startChat({ history, generationConfig: { maxOutputTokens: maxTokens } });
    const result = await chat.sendMessage(lastMsg);
    const text   = result.response.text();

    return { text, provider: 'gemini' };

  } catch (geminiErr) {
    console.warn('[Gemini] Failed, trying Groq fallback:', geminiErr.message);

    // ── Fallback: Groq (Llama 3.3 70B) ─────────────────────────
    if (!groq) throw new Error('Gemini failed and no Groq key configured.');

    try {
      const groqMessages = [];
      if (system) groqMessages.push({ role: 'system', content: system });
      messages.forEach(m => groqMessages.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));

      const completion = await groq.chat.completions.create({
        model:      'llama-3.3-70b-versatile',
        messages:   groqMessages,
        max_tokens: maxTokens,
        temperature: 0.7,
      });

      return { text: completion.choices[0].message.content, provider: 'groq' };

    } catch (groqErr) {
      console.error('[Groq] Also failed:', groqErr.message);
      throw new Error('Both AI providers failed. Please try again in a moment.');
    }
  }
}

// ════════════════════════════════════════════════════════════════
//  Auth Helpers
// ════════════════════════════════════════════════════════════════
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

function verifyAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ════════════════════════════════════════════════════════════════
//  DB Helpers
// ════════════════════════════════════════════════════════════════
async function ensureXPRecord(userId) {
  await db.from('user_xp').upsert(
    { user_id: userId, total_xp: 0 },
    { onConflict: 'user_id', ignoreDuplicates: true }
  );
}

async function logActivity(userId, tool, subject = '', chapter = '', xpEarned = 0, meta = {}) {
  try {
    await db.from('activity_log').insert({ user_id: userId, tool, subject, chapter, xp_earned: xpEarned, metadata: meta });
    await db.rpc('increment_xp',   { p_user_id: userId, p_amount: xpEarned });
    await db.rpc('update_streak',  { p_user_id: userId });
  } catch (e) {
    console.error('[logActivity]', e.message);
  }
}

function safeUser(u) {
  if (!u) return null;
  const { password_hash, ...safe } = u;
  return safe;
}

// ════════════════════════════════════════════════════════════════
//  ROUTES: AUTH
// ════════════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 8)          return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const { data: exists } = await db.from('users').select('id').eq('email', email.toLowerCase()).maybeSingle();
    if (exists) return res.status(409).json({ error: 'This email is already registered.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const { data: user, error } = await db.from('users').insert({
      name: name.trim(), email: email.toLowerCase().trim(),
      password_hash: passwordHash, type: 'personal', provider: 'email',
    }).select().single();

    if (error) throw error;
    await ensureXPRecord(user.id);

    res.status(201).json({ token: signToken({ id: user.id, email: user.email }), user: safeUser(user) });
  } catch (e) {
    console.error('[register]', e.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const { data: user } = await db.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid email or password' });

    if (!await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await db.from('users').update({ last_login_at: new Date().toISOString() }).eq('id', user.id);
    await ensureXPRecord(user.id);

    res.json({ token: signToken({ id: user.id, email: user.email }), user: safeUser(user) });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Google OAuth
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'Google token required' });

    let payload;
    try {
      const ticket = await googleOAuth.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
      payload = ticket.getPayload();
    } catch {
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const { email, name, picture } = payload;
    let { data: user } = await db.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();

    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({
        name, email: email.toLowerCase(), type: 'personal', provider: 'google', avatar_url: picture,
      }).select().single();
      if (error) throw error;
      user = newUser;
      await ensureXPRecord(user.id);
    } else {
      await db.from('users').update({ avatar_url: picture, last_login_at: new Date().toISOString() }).eq('id', user.id);
    }

    res.json({ token: signToken({ id: user.id, email: user.email }), user: safeUser(user) });
  } catch (e) {
    console.error('[google]', e.message);
    res.status(500).json({ error: 'Google sign-in failed.' });
  }
});

// Microsoft OAuth
app.post('/api/auth/microsoft', async (req, res) => {
  try {
    const { accessToken } = req.body;
    const graphRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!graphRes.ok) return res.status(401).json({ error: 'Invalid Microsoft token' });

    const profile = await graphRes.json();
    const email   = (profile.mail || profile.userPrincipalName).toLowerCase();
    const name    = profile.displayName;

    let { data: user } = await db.from('users').select('*').eq('email', email).maybeSingle();
    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({ name, email, type: 'personal', provider: 'microsoft' }).select().single();
      if (error) throw error;
      user = newUser;
      await ensureXPRecord(user.id);
    } else {
      await db.from('users').update({ last_login_at: new Date().toISOString() }).eq('id', user.id);
    }

    res.json({ token: signToken({ id: user.id, email: user.email }), user: safeUser(user) });
  } catch (e) {
    console.error('[microsoft]', e.message);
    res.status(500).json({ error: 'Microsoft sign-in failed.' });
  }
});

// School Login
app.post('/api/auth/school', async (req, res) => {
  try {
    const { schoolCode, rollNumber, password, role = 'student' } = req.body;
    if (!schoolCode || !rollNumber || !password) {
      return res.status(400).json({ error: 'School code, ID, and password are required' });
    }

    const { data: school } = await db.from('schools')
      .select('*').eq('school_code', schoolCode.toUpperCase()).maybeSingle();
    if (!school)          return res.status(404).json({ error: 'School code not found.' });
    if (!school.is_active) return res.status(403).json({ error: 'School account is inactive.' });

    const table   = role === 'teacher' ? 'school_teachers' : 'school_students';
    const idField = role === 'teacher' ? 'teacher_id'      : 'roll_number';

    const { data: member } = await db.from(table)
      .select('*').eq('school_id', school.id).eq(idField, rollNumber.trim()).maybeSingle();
    if (!member)          return res.status(401).json({ error: `${role === 'teacher' ? 'Teacher ID' : 'Roll number'} not found.` });
    if (!member.is_active) return res.status(403).json({ error: 'This account is deactivated.' });
    if (!await bcrypt.compare(password, member.password_hash)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    const syntheticEmail = `${rollNumber.toLowerCase().replace(/[^a-z0-9]/g, '')}@${schoolCode.toLowerCase()}.school`;
    let { data: user } = await db.from('users').select('*').eq('email', syntheticEmail).maybeSingle();

    if (!user) {
      const { data: newUser, error } = await db.from('users').insert({
        name: member.name, email: syntheticEmail, type: 'school', role,
        school_id: school.id, class_level: member.class_level,
        section: member.section, roll_number: rollNumber.trim(), provider: 'school',
      }).select().single();
      if (error) throw error;
      user = newUser;
      await ensureXPRecord(user.id);
    } else {
      await db.from('users').update({ last_login_at: new Date().toISOString() }).eq('id', user.id);
    }

    res.json({
      token: signToken({ id: user.id, email: user.email, type: 'school', schoolId: school.id }),
      user: { ...safeUser(user), schoolName: school.name, schoolCode: school.school_code, schoolLogo: school.logo_url },
    });
  } catch (e) {
    console.error('[school login]', e.message);
    res.status(500).json({ error: 'School login failed.' });
  }
});

// Verify token + return user
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const { data: user } = await db.from('users')
      .select('*, schools(name, school_code, logo_url)')
      .eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: USER PROFILE & SETTINGS
// ════════════════════════════════════════════════════════════════

app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const { data: user } = await db.from('users')
      .select('*, schools(name, school_code, logo_url)')
      .eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const { name, bio, phone, classLevel, section } = req.body;
    if (name && name.trim().length < 2) return res.status(400).json({ error: 'Name too short' });

    const { data: user, error } = await db.from('users').update({
      ...(name       && { name: name.trim() }),
      ...(bio        !== undefined && { bio }),
      ...(phone      !== undefined && { phone }),
      ...(classLevel !== undefined && { class_level: classLevel }),
      ...(section    !== undefined && { section }),
      updated_at: new Date().toISOString(),
    }).eq('id', req.user.id).select().single();

    if (error) throw error;
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    const { data: user } = await db.from('users').select('password_hash, provider').eq('id', req.user.id).single();
    if (user.password_hash && !await bcrypt.compare(currentPassword, user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    await db.from('users').update({ password_hash: await bcrypt.hash(newPassword, 12), updated_at: new Date().toISOString() }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Full stats for dashboard
app.get('/api/user/stats', verifyToken, async (req, res) => {
  try {
    const { data: stats } = await db.rpc('get_user_stats', { p_user_id: req.user.id });

    const { data: recent } = await db.from('activity_log')
      .select('tool, subject, chapter, xp_earned, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false }).limit(20);

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data: weekly } = await db.from('activity_log')
      .select('tool, xp_earned, created_at')
      .eq('user_id', req.user.id).gte('created_at', sevenDaysAgo);

    res.json({ stats: stats || {}, recentActivity: recent || [], weeklyActivity: weekly || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Saved Notes ───────────────────────────────────────────────────
app.get('/api/user/notes', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_notes').select('id,title,subject,class_level,chapter,style,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.get('/api/user/notes/:id', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_notes').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
  if (!data) return res.status(404).json({ error: 'Note not found' });
  res.json(data);
});
app.post('/api/user/notes', verifyToken, async (req, res) => {
  const { subject, classLevel, chapter, style, content } = req.body;
  const { data, error } = await db.from('saved_notes').insert({ user_id: req.user.id, title: `${chapter} — ${subject}`, subject, class_level: classLevel, chapter, style, content }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/notes/:id', verifyToken, async (req, res) => {
  await db.from('saved_notes').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// ── Saved Papers ──────────────────────────────────────────────────
app.get('/api/user/papers', verifyToken, async (req, res) => {
  const { data } = await db.from('saved_papers').select('id,title,subject,class_level,marks,duration,created_at').eq('user_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});
app.post('/api/user/papers', verifyToken, async (req, res) => {
  const { subject, classLevel, marks, duration, description, content } = req.body;
  const { data, error } = await db.from('saved_papers').insert({ user_id: req.user.id, title: `${subject} — ${classLevel} — ${marks}M`, subject, class_level: classLevel, marks, duration, description, content }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});
app.delete('/api/user/papers/:id', verifyToken, async (req, res) => {
  await db.from('saved_papers').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// ── Quiz History ──────────────────────────────────────────────────
app.get('/api/user/quiz-history', verifyToken, async (req, res) => {
  const { data } = await db.from('quiz_history').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
  res.json(data || []);
});
app.post('/api/user/quiz-history', verifyToken, async (req, res) => {
  const { subject, topic, difficulty, totalQuestions, correctAnswers, xpEarned } = req.body;
  const { data, error } = await db.from('quiz_history').insert({ user_id: req.user.id, subject, topic, difficulty, total_questions: totalQuestions, correct_answers: correctAnswers, score_percent: Math.round((correctAnswers / totalQuestions) * 100), xp_earned: xpEarned }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: AI PROXY
//  All AI calls go through here — API keys stay on the server
// ════════════════════════════════════════════════════════════════

const AI_TOOLS = {
  doubt:      { xp: 15, maxTokens: 600,  label: 'doubt'      },
  quiz:       { xp: 5,  maxTokens: 1000, label: 'quiz'       },
  notes:      { xp: 20, maxTokens: 1200, label: 'notes'      },
  paper:      { xp: 25, maxTokens: 1200, label: 'paper'      },
  flashcards: { xp: 15, maxTokens: 800,  label: 'flashcards' },
};

app.post('/api/ai/:tool', verifyToken, aiLimiter, async (req, res) => {
  const config = AI_TOOLS[req.params.tool];
  if (!config) return res.status(400).json({ error: `Unknown tool: ${req.params.tool}` });

  try {
    const { messages, system = '', subject = '', chapter = '' } = req.body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required' });
    }

    const { text, provider } = await callAI(messages, system, config.maxTokens);

    // Log activity + XP — non-blocking
    logActivity(req.user.id, config.label, subject, chapter, config.xp, { subject, chapter, provider }).catch(console.error);

    res.json({ content: text, xpEarned: config.xp, provider });

  } catch (e) {
    console.error(`[AI /${req.params.tool}]`, e.message);
    if (e.message.includes('quota') || e.message.includes('429')) {
      return res.status(429).json({ error: 'AI is busy right now. Please try again in a few seconds.' });
    }
    res.status(500).json({ error: 'AI service error. Please try again.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  ROUTES: SCHOOL ADMIN
//  Protected by ADMIN_SECRET_KEY header — only you can call these
// ════════════════════════════════════════════════════════════════

// Create school
app.post('/api/admin/schools', verifyAdmin, async (req, res) => {
  try {
    const { name, schoolCode, address, city, contactEmail, contactPhone, maxStudents = 500, plan = 'basic' } = req.body;
    if (!name || !schoolCode) return res.status(400).json({ error: 'Name and school code required' });

    const { data, error } = await db.from('schools').insert({
      name: name.trim(), school_code: schoolCode.toUpperCase().trim(),
      address, city, contact_email: contactEmail, contact_phone: contactPhone,
      max_students: maxStudents, subscription_plan: plan,
    }).select().single();

    if (error?.code === '23505') return res.status(409).json({ error: 'School code already exists' });
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// List all schools
app.get('/api/admin/schools', verifyAdmin, async (req, res) => {
  const { data } = await db.from('schools').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

// Get school + stats
app.get('/api/admin/schools/:code', verifyAdmin, async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('*').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });

    const { count: studentCount } = await db.from('school_students').select('id', { count: 'exact', head: true }).eq('school_id', school.id);
    const { count: activeUsers }  = await db.from('users').select('id', { count: 'exact', head: true }).eq('school_id', school.id);

    res.json({ ...school, studentCount, activeUsers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bulk import students
app.post('/api/admin/schools/:code/students', verifyAdmin, async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });

    const { students } = req.body;
    if (!Array.isArray(students) || students.length === 0) {
      return res.status(400).json({ error: 'students array required' });
    }

    const toInsert = await Promise.all(students.map(async s => ({
      school_id:     school.id,
      roll_number:   s.rollNumber.trim(),
      name:          s.name.trim(),
      class_level:   s.class || s.classLevel || '',
      section:       s.section || '',
      email:         s.email || null,
      password_hash: await bcrypt.hash(s.password || s.rollNumber.trim(), 12),
    })));

    const { data, error } = await db.from('school_students')
      .upsert(toInsert, { onConflict: 'school_id,roll_number' }).select();
    if (error) throw error;

    res.json({ success: true, imported: data.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all students
app.get('/api/admin/schools/:code/students', verifyAdmin, async (req, res) => {
  try {
    const { data: school } = await db.from('schools').select('id').eq('school_code', req.params.code.toUpperCase()).maybeSingle();
    if (!school) return res.status(404).json({ error: 'School not found' });

    const { data } = await db.from('school_students')
      .select('roll_number,name,class_level,section,is_active,created_at')
      .eq('school_id', school.id).order('class_level').order('roll_number');
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Toggle school status
app.put('/api/admin/schools/:code/status', verifyAdmin, async (req, res) => {
  const { data } = await db.from('schools').update({ is_active: req.body.isActive }).eq('school_code', req.params.code.toUpperCase()).select().single();
  res.json(data);
});

// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ════════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  const aiStatus = {};
  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });
    const result = await model.generateContent('Say ok');
    aiStatus.gemini = 'ok';
  } catch (e) {
    aiStatus.gemini = `error: ${e.message.slice(0, 60)}`;
  }
  aiStatus.groq = groq ? 'configured' : 'not configured';
  res.json({ status: 'ok', time: new Date().toISOString(), version: '2.0.0', ai: aiStatus });
});

// ════════════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('[Unhandled]', err);
  res.status(500).json({ error: 'Internal server error' });
});
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

// ════════════════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n🚀 BrainSpark AI — Server running at http://localhost:${PORT}`);
  console.log(`   AI: Gemini 2.0 Flash (primary) + Groq Llama (fallback)`);
  console.log(`   Gemini key: ${process.env.GEMINI_API_KEY ? '✅ Set' : '❌ MISSING'}`);
  console.log(`   Groq key:   ${process.env.GROQ_API_KEY   ? '✅ Set' : '⚠️  Not set (fallback disabled)'}`);
  console.log(`   Supabase:   ${process.env.SUPABASE_URL   ? '✅ Set' : '❌ MISSING'}\n`);
});
