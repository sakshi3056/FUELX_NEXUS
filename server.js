require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const authDb = new Database(path.join(__dirname, 'auth.sqlite'));
authDb.pragma('journal_mode = WAL');
authDb.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT UNIQUE, phone TEXT UNIQUE, name TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, verified_at TEXT, password_hash TEXT
);
CREATE TABLE IF NOT EXISTS otp_challenges (
 id TEXT PRIMARY KEY, identifier TEXT NOT NULL, channel TEXT NOT NULL, mode TEXT NOT NULL,
 otp_hash TEXT NOT NULL, payload_json TEXT, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, identifier TEXT NOT NULL, expires_at INTEGER NOT NULL
);
`);

try { authDb.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
try { authDb.exec('ALTER TABLE otp_challenges ADD COLUMN payload_json TEXT'); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

const emptyDB = () => ({ users: [], sessions: [], orders: [], subscriptions: [], addresses: [], contacts: [], payments: [] });
function readDB() { try { return { ...emptyDB(), ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) }; } catch { return emptyDB(); } }
function writeDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
const clean = v => String(v ?? '').trim().slice(0, 500);
const emailOK = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length < 255;
const hash = v => crypto.createHash('sha256').update(v).digest('hex');
function makePasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}
function checkPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, expected] = stored.split(':');
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });
  const session = authDb.prepare('SELECT identifier FROM sessions WHERE token_hash = ? AND expires_at > ?').get(hash(token), Date.now());
  if (!session) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
  const user = authDb.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(session.identifier, session.identifier);
  if (!user) return res.status(401).json({ error: 'Account not found. Please sign in again.' });
  req.email = user.email || user.phone;
  req.authUser = user;
  req.db = readDB();
  next();
}
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const otpTransport = (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)
  ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE || 'false') === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } })
  : null;
function normalizeIdentifier(channel, raw) {
  const value = clean(raw);
  if (channel === 'email') return value.toLowerCase();
  return value.replace(/[()\s-]/g, '');
}
function validIdentifier(channel, value) {
  if (channel === 'email') return emailOK(value);
  return /^\+[1-9]\d{7,14}$/.test(value);
}
async function deliverOTP(channel, identifier, otp) {
  if (channel === 'email') {
    if (!otpTransport || !process.env.SMTP_FROM) {
      if (process.env.DEV_OTP_MODE === 'true' && process.env.NODE_ENV !== 'production') { console.log(`[DEV OTP] ${identifier} => ${otp}`); return { devMode: true }; }
      throw new Error('Email OTP is not configured. Set SMTP values in .env or use DEV_OTP_MODE=true for local demo only.');
    }
    await otpTransport.sendMail({ from: process.env.SMTP_FROM, to: identifier, subject: 'Your FUELX NEXUS verification code', text: `Your FUELX NEXUS verification code is ${otp}. It expires in 5 minutes. If you did not request this, ignore this email.`, html: `<div style="font-family:Arial;background:#10120f;color:#f4f3ed;padding:28px"><h2>FUELX NEXUS</h2><p>Your verification code is:</p><div style="font-size:32px;letter-spacing:8px;color:#c8ff55;font-weight:bold">${otp}</div><p>This code expires in 5 minutes. Never share it with anyone.</p></div>` });
    return;
  }
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FROM) {
    if (process.env.DEV_OTP_MODE === 'true' && process.env.NODE_ENV !== 'production') { console.log(`[DEV OTP] ${identifier} => ${otp}`); return { devMode: true }; }
    throw new Error('SMS OTP is not configured. Set Twilio values in .env or use DEV_OTP_MODE=true for local demo only.');
  }
  const body = new URLSearchParams({ To: identifier, From: TWILIO_FROM, Body: `FUELX NEXUS code: ${otp}. Expires in 5 minutes. Do not share it.` });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (!response.ok) throw new Error('SMS delivery failed. Check your Twilio setup and destination number.');
}
app.post('/api/auth/send-otp', authLimiter, async (req, res) => {
  const channel = req.body.channel === 'phone' ? 'phone' : 'email';
  const identifier = normalizeIdentifier(channel, req.body.identifier);
  const mode = req.body.mode === 'register' ? 'register' : 'login';
  const name = clean(req.body.name);
  if (mode !== 'register') return res.status(400).json({ error: 'OTP is used for registration only. Please sign in with your password.' });
  if (!validIdentifier(channel, identifier)) return res.status(400).json({ error: channel === 'email' ? 'Enter a valid email address.' : 'Enter phone number in international format, e.g. +919876543210.' });
  if (!name) return res.status(400).json({ error: 'Enter your full name to create an account.' });
  const existing = authDb.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(identifier, identifier);
  if (existing) return res.status(409).json({ error: 'An account already exists. Choose Login instead.' });
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Create a password with at least 8 characters.' });
  const passwordHash = makePasswordHash(password);
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const id = crypto.randomUUID();
  authDb.prepare('DELETE FROM otp_challenges WHERE identifier = ?').run(identifier);
  authDb.prepare('INSERT INTO otp_challenges (id, identifier, channel, mode, otp_hash, payload_json, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)').run(id, identifier, channel, 'register', hash(otp), JSON.stringify({ name, passwordHash }), Date.now()+5*60*1000, Date.now());
  let delivery;
  try { delivery = await deliverOTP(channel, identifier, otp); }
  catch (e) { authDb.prepare('DELETE FROM otp_challenges WHERE id = ?').run(id); return res.status(503).json({ error: e.message }); }
  res.json({ challengeId: id, message: delivery?.devMode ? 'LOCAL DEMO: OTP printed in the terminal running npm start. Expires in 5 minutes.' : `Verification code sent to your ${channel}. It expires in 5 minutes.` });
});

app.post('/api/auth/register', authLimiter, (req, res) => {
  const channel = req.body.channel === 'phone' ? 'phone' : 'email';
  const identifier = normalizeIdentifier(channel, req.body.identifier);
  const name = clean(req.body.name);
  const password = String(req.body.password || '');
  if (!validIdentifier(channel, identifier)) return res.status(400).json({ error: channel === 'email' ? 'Enter a valid email address.' : 'Enter phone number in international format, e.g. +919876543210.' });
  if (!name) return res.status(400).json({ error: 'Enter your full name.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const existing = authDb.prepare('SELECT id FROM users WHERE email = ? OR phone = ?').get(identifier, identifier);
  if (existing) return res.status(409).json({ error: 'An account already exists. Choose Login instead.' });
  const id = crypto.randomUUID();
  try {
    authDb.prepare('INSERT INTO users (id,email,phone,name,created_at,verified_at,password_hash) VALUES (?,?,?,?,?,?,?)')
      .run(id, channel === 'email' ? identifier : null, channel === 'phone' ? identifier : null, name, new Date().toISOString(), null, makePasswordHash(password));
  } catch (e) {
    return res.status(409).json({ error: 'An account already exists with that email or phone. Choose Login instead.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  authDb.prepare('INSERT INTO sessions (token_hash,identifier,expires_at) VALUES (?,?,?)').run(hash(token), identifier, Date.now()+7*86400000);
  res.status(201).json({ token, user: { id, email: channel === 'email' ? identifier : null, phone: channel === 'phone' ? identifier : null, name } });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const channel = req.body.channel === 'phone' ? 'phone' : 'email';
  const identifier = normalizeIdentifier(channel, req.body.identifier);
  const password = String(req.body.password || '');
  if (!validIdentifier(channel, identifier)) return res.status(400).json({ error: channel === 'email' ? 'Enter a valid email address.' : 'Enter phone number in international format, e.g. +919876543210.' });
  const user = authDb.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(identifier, identifier);
  if (!user || !user.password_hash) return res.status(401).json({ error: 'Account not found or password is incorrect. Register first if you are a new customer.' });
  const ok = checkPassword(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Account not found or password is incorrect.' });
  const token = crypto.randomBytes(32).toString('hex');
  authDb.prepare('DELETE FROM sessions WHERE identifier = ?').run(identifier);
  authDb.prepare('INSERT INTO sessions (token_hash,identifier,expires_at) VALUES (?,?,?)').run(hash(token),identifier,Date.now()+7*86400000);
  res.json({ token, user: { id:user.id, email:user.email, phone:user.phone, name:user.name } });
});
app.post('/api/auth/verify-otp', authLimiter, (req, res) => {
  const challengeId = clean(req.body.challengeId), otp = clean(req.body.otp), name = clean(req.body.name);
  const challenge = authDb.prepare('SELECT * FROM otp_challenges WHERE id = ?').get(challengeId);
  if (!challenge) return res.status(400).json({ error: 'Request a new verification code.' });
  if (challenge.expires_at < Date.now()) { authDb.prepare('DELETE FROM otp_challenges WHERE id = ?').run(challengeId); return res.status(400).json({ error: 'Code expired. Request a new one.' }); }
  if (challenge.attempts >= 5) { authDb.prepare('DELETE FROM otp_challenges WHERE id = ?').run(challengeId); return res.status(429).json({ error: 'Too many attempts. Request a new code.' }); }
  let payload;
  try { payload = JSON.parse(challenge.payload_json || '{}'); } catch { payload = {}; }
  if (!/^\d{6}$/.test(otp) || hash(otp) !== challenge.otp_hash) {
    authDb.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(challengeId);
    return res.status(400).json({ error: 'Incorrect code. Check it and try again.' });
  }
  let user = authDb.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(challenge.identifier, challenge.identifier);
  if (!user && challenge.mode === 'register') {
    const registerName = payload.name || name;
    try {
      authDb.prepare('INSERT INTO users (id,email,phone,name,created_at,verified_at,password_hash) VALUES (?,?,?,?,?,?,?)').run(crypto.randomUUID(), challenge.channel==='email'?challenge.identifier:null, challenge.channel==='phone'?challenge.identifier:null, registerName, new Date().toISOString(), new Date().toISOString(), payload.passwordHash || null);
    } catch { return res.status(409).json({ error: 'This email or phone is already linked to an account.' }); }
    user = authDb.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(challenge.identifier, challenge.identifier);
  }
  if (!user) return res.status(404).json({ error: 'Account not found. Choose Create account.' });
  if (challenge.mode === 'register' && name && user.name !== name) authDb.prepare('UPDATE users SET name = ? WHERE id = ?').run(name,user.id);
  authDb.prepare('DELETE FROM otp_challenges WHERE identifier = ?').run(challenge.identifier);
  const token = crypto.randomBytes(32).toString('hex');
  authDb.prepare('DELETE FROM sessions WHERE identifier = ?').run(challenge.identifier);
  authDb.prepare('INSERT INTO sessions (token_hash,identifier,expires_at) VALUES (?,?,?)').run(hash(token),challenge.identifier,Date.now()+7*86400000);
  res.json({ token, user: { id:user.id, email:user.email, phone:user.phone, name:user.name } });
});
app.post('/api/auth/logout', auth, (req,res) => { const token=(req.headers.authorization||'').replace(/^Bearer /,''); authDb.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash(token)); res.json({ok:true}); });
app.get('/api/profile', auth, (req, res) => { const u = authDb.prepare('SELECT * FROM users WHERE id = ?').get(req.authUser.id); res.json({ user: { id:u.id, email:u.email, phone:u.phone, name:u.name, createdAt:u.created_at } }); });
app.patch('/api/profile', auth, (req, res) => {
  const name = clean(req.body.name), phone = clean(req.body.phone);
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  if (phone && !/^\+[1-9]\d{7,14}$/.test(phone)) return res.status(400).json({ error: 'Phone must use international format, e.g. +919876543210.' });
  try { authDb.prepare('UPDATE users SET name = ?, phone = ? WHERE id = ?').run(name, phone || null, req.authUser.id); }
  catch { return res.status(409).json({ error: 'That phone number is already linked to another account.' }); }
  const u = authDb.prepare('SELECT * FROM users WHERE id = ?').get(req.authUser.id);
  res.json({ user: { id:u.id, email:u.email, phone:u.phone, name:u.name, createdAt:u.created_at } });
});
app.get('/api/orders', auth, (req, res) => res.json({ orders: req.db.orders.filter(o => o.email === req.email).sort((a,b) => b.createdAt.localeCompare(a.createdAt)) }));
const FUEL_RATES = { 'Petrol': 112.39, 'Diesel': 99.05, 'Premium fuel': 117.39 }; // Satara, Maharashtra indicative rates, 27 Oct 2026; refresh from an authorized data source before launch.
app.post('/api/orders', auth, (req, res) => {
  const b = req.body, litres = Number(b.litres);
  const paymentTypes = ['UPI','Credit card','Debit card','Net banking','Wallet','Cash on delivery','Subscription card'];
  if (!['Petrol','Diesel','Premium fuel'].includes(b.fuelType) || !Number.isInteger(litres) || litres < 5 || litres > 500 || !clean(b.address) || !clean(b.phone) || !paymentTypes.includes(b.paymentType))
    return res.status(400).json({ error: 'Check fuel, quantity, delivery address, phone and payment type.' });
  const scheduleMode = ['instant','scheduled'].includes(b.scheduleMode) ? b.scheduleMode : 'instant';
  let scheduledAt = null, etaMinutes = null;
  if (scheduleMode === 'instant') {
    etaMinutes = 10; // target only, not a guaranteed SLA; dispatch must confirm nearby pump availability.
  } else {
    if (!b.deliveryDate || !b.deliveryTime) return res.status(400).json({ error: 'Choose a delivery date and time.' });
    const dt = new Date(`${b.deliveryDate}T${b.deliveryTime}:00`);
    const now = new Date();
    if (Number.isNaN(dt.getTime()) || dt <= now || dt > new Date(now.getTime() + 7*24*60*60*1000))
      return res.status(400).json({ error: 'Scheduled delivery must be in the next 7 days.' });
    scheduledAt = dt.toISOString();
  }
  const rate = FUEL_RATES[b.fuelType];
  const subtotal = Math.round(rate * litres * 100) / 100;
  const subscription = req.db.subscriptions.find(s => s.email === req.email && ['Active','Active (test payment)'].includes(s.status));
  const discount = (subscription && b.paymentType === 'Subscription card') ? Math.round(subtotal * 0.10 * 100) / 100 : 0;
  const total = Math.round((subtotal - discount) * 100) / 100;
  let paymentStatus = b.paymentType === 'Cash on delivery' ? 'Pay on delivery' : 'Payment required';
  let status = scheduleMode === 'instant' ? 'Awaiting nearby pump confirmation' : 'Scheduled — awaiting confirmation';
  if (b.paymentType === 'Subscription card') {
    if (!subscription) return res.status(400).json({ error: 'Activate a subscription plan before paying with the subscription card.' });
    if ((Number(subscription.balance)||0) < total) return res.status(400).js
app.post('/api/orders/:id/cancel', auth, (req, res) => {
  const order = req.db.orders.find(o => o.id === req.params.id && o.email === req.email);
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (['Cancelled','Delivered'].includes(order.status)) return res.status(400).json({ error: `This order cannot be cancelled (status: ${order.status}).` });
  const dispatched = ['Dispatched','Out for delivery','Confirmed','Confirmed (test)','Paid — awaiting nearby pump confirmation'].includes(order.status);
  const fee = dispatched ? Math.max(50, Math.round((Number(order.total)||0)*0.05*100)/100) : 0;
  order.status = 'Cancelled';
  order.cancelledAt = new Date().toISOString();
  order.cancellationFee = fee;
  order.cancellationNote = fee ? 'Cancellation fee estimate: 5% of order total, minimum ₹50. Final policy and refund are subject to operator confirmation.' : 'Cancelled before dispatch; no cancellation fee in prototype.';
  writeDB(req.db);
  res.json({ order, cancellationFee: fee, message: order.cancellationNote });
});
on({ error: `Insufficient subscription card balance. Available: ₹${Number(subscription.balance)||0}; required: ₹${total}. Top up your card in My Account first.` });
    subscription.balance = Number(subscription.balance) - total;
    paymentStatus = 'Paid with subscription card (test balance)';
    status = scheduleMode === 'instant' ? 'Paid — awaiting nearby pump confirmation' : 'Paid — scheduled, awaiting confirmation';
    req.db.payments.push({ id: crypto.randomUUID(), email: req.email, kind: 'order-subscription-card', recordId: subscription.id, amount: total, outcome: 'success', mode: 'TEST ONLY', createdAt: new Date().toISOString() });
  }
  const order = {
    id: crypto.randomUUID(), orderNumber: 'FX-' + Date.now().toString().slice(-8), email: req.email,
    fuelType: b.fuelType, litres, unitPrice: rate, subtotal, subscriptionDiscount: discount, total,
    subscriptionDiscountApplied: discount > 0, address: clean(b.address), phone: clean(b.phone),
    paymentType: b.paymentType, paymentStatus, status, scheduleMode, scheduledAt,
    etaMinutes, cancellationFeePolicy: '5% of order total, minimum ₹50, if cancelled after dispatch/confirmation; subject to final business policy',
    cancellationFee: 0, createdAt: new Date().toISOString()
  };
  req.db.orders.push(order); writeDB(req.db);
  res.status(201).json({ order, pricing: { city: 'Satara, Maharashtra', unitPrice: rate, subtotal, discount, total }, subscriptionBalance: b.paymentType === 'Subscription card' ? (subscription.balance || 0) : undefined });
});

app.get('/api/addresses', auth, (req, res) => res.json({ addresses: req.db.addresses.filter(a => a.email === req.email) }));
app.post('/api/addresses', auth, (req, res) => {
  if (!clean(req.body.label) || !clean(req.body.address)) return res.status(400).json({ error: 'Label and full address are required.' });
  const address = { id: crypto.randomUUID(), email: req.email, label: clean(req.body.label), address: clean(req.body.address), phone: clean(req.body.phone) };
  req.db.addresses.push(address); writeDB(req.db); res.status(201).json({ address });
});
app.delete('/api/addresses/:id', auth, (req, res) => { req.db.addresses = req.db.addresses.filter(a => !(a.id === req.params.id && a.email === req.email)); writeDB(req.db); res.json({ ok: true }); });
const plans = {
  Starter: { name:'Starter', price:0, cycle:'month', benefits:['Order history and tracking','Save delivery addresses','Standard support'] },
  Plus: { name:'Plus', price:299, cycle:'month', benefits:['Everything in Starter','Priority support','Member-only offers'] },
  Fleet: { name:'Fleet', price:1999, cycle:'month', benefits:['Multi-vehicle management (setup required)','Centralized order overview','Business support'] }
};
app.get('/api/plans', (req, res) => res.json({ plans: Object.values(plans) }));
app.get('/api/subscription', auth, (req, res) => res.json({ subscription: req.db.subscriptions.find(s => s.email === req.email) || null }));
app.post('/api/subscriptions/checkout', auth, (req, res) => {
  const plan = plans[clean(req.body.plan)];
  if (!plan) return res.status(400).json({ error: 'Choose a valid plan.' });
  const sub = { id: crypto.randomUUID(), email: req.email, plan: plan.name, price: plan.price, cycle: plan.cycle, status: plan.price === 0 ? 'Active' : 'Pending payment', paymentStatus: plan.price === 0 ? 'No payment required' : 'Test checkout not completed', balance: plan.price === 0 ? 0 : 0, createdAt: new Date().toISOString() };
  req.db.subscriptions = req.db.subscriptions.filter(s => s.email !== req.email);
  req.db.subscriptions.push(sub); writeDB(req.db);
  res.status(201).json({ subscription: sub, checkoutRequired: plan.price > 0 });
});
app.get('/api/subscription-card', auth, (req, res) => {
  const sub = req.db.subscriptions.find(s => s.email === req.email) || null;
  res.json({ card: sub ? { id: sub.id, plan: sub.plan, status: sub.status, balance: Number(sub.balance)||0, paymentStatus: sub.paymentStatus } : null });
});
app.post('/api/subscription-card/top-up', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount < 100 || amount > 50000) return res.status(400).json({ error: 'Choose a top-up amount between ₹100 and ₹50,000.' });
  const sub = req.db.subscriptions.find(s => s.email === req.email);
  if (!sub || !['Active','Active (test payment)'].includes(sub.status)) return res.status(400).json({ error: 'Purchase and activate a subscription plan before adding card balance.' });
  // Prototype-only wallet credit; production must only credit funds after verified payment gateway webhooks.
  sub.balance = (Number(sub.balance)||0) + amount;
  sub.lastTopUpMode = 'TEST ONLY';
  req.db.payments.push({ id: crypto.randomUUID(), email: req.email, kind: 'subscription-card-top-up', recordId: sub.id, amount, outcome: 'success', mode: 'TEST ONLY', createdAt: new Date().toISOString() });
  writeDB(req.db); res.json({ card: { id: sub.id, plan: sub.plan, status: sub.status, balance: sub.balance, paymentStatus: sub.paymentStatus } });
});
app.post('/api/payments/test-complete', auth, (req, res) => {
  const { kind, id, outcome } = req.body;
  if (!['success','failure'].includes(outcome) || !['order','subscription'].includes(kind)) return res.status(400).json({ error: 'Invalid test payment result.' });
  const list = kind === 'order' ? req.db.orders : req.db.subscriptions;
  const record = list.find(x => x.id === id && x.email === req.email);
  if (!record) return res.status(404).json({ error: 'Checkout record not found.' });
  record.paymentStatus = outcome === 'success' ? 'Test payment successful' : 'Payment failed';
  if (kind === 'subscription') record.status = outcome === 'success' ? 'Active (test payment)' : 'Payment failed';
  if (kind === 'order' && outcome === 'success') record.status = 'Confirmed';
  req.db.payments.push({ id: crypto.randomUUID(), email: req.email, kind, recordId: id, outcome, mode: 'TEST ONLY', createdAt: new Date().toISOString() });
  writeDB(req.db); res.json({ ok: true, record });
});
app.post('/api/contact', rateLimit({ windowMs: 60*60*1000, max: 8 }), (req,res) => {
  const name=clean(req.body.name), email=clean(req.body.email).toLowerCase(), message=clean(req.body.message);
  if (!name || !emailOK(email) || !message) return res.status(400).json({ error:'Complete all fields with a valid email.' });
  const db=readDB(); db.contacts.push({ id:crypto.randomUUID(), name, email, message, createdAt:new Date().toISOString() }); writeDB(db); res.status(201).json({ ok:true });
});

const pages = new Set(['','index','services','plans','about','contact','login','account','checkout','order-confirmation','privacy','terms','faq']);
app.get('*', (req,res,next) => {
  const route = req.path.replace(/^\/|\/$/g,'').replace(/\.html$/,'');
  if (route.startsWith('api/')) return next();
  if (pages.has(route)) return res.sendFile(path.join(__dirname,'public','index.html'));
  next();
});
app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT, () => console.log(`FUELX NEXUS running at http://localhost:${PORT}`));
