// ═══════════════════════════════════════════════════════
//  RoadmapX — Backend Server (UPDATED)
//  Stack: Node.js + Express + MongoDB (Mongoose)
//
//  KEY CHANGES vs original:
//  1. All data models (Notes, Pomodoro, Attendance, etc.)
//     now carry a `userId` field so data is per-user, not global.
//  2. New unified GET /api/user-data + POST /api/user-data
//     endpoints for the hybrid localStorage ↔ backend system.
//  3. CORS cookie fix: sameSite "none" + secure:true in
//     production so the cross-origin Cloudflare→Render cookie works.
//  4. Fixed connect-mongo import (no broken || fallback).
//  5. Fixed typo on /register comment.
//  6. All existing routes updated to scope queries by userId.
// ═══════════════════════════════════════════════════════
require('dotenv').config();
const stepRoutes = require('./routes/stepRoutes');
const roadmapRoutes = require('./routes/roadmapRoutes');
const express    = require("express");
const rateLimit  = require("express-rate-limit");
const mongoose   = require("mongoose");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const session    = require("express-session");
const MongoStore = require("connect-mongo"); // connect-mongo v6+
const app        = express();

// ── CRYPTO + MAILER (used by password reset & email verification) ──
const crypto     = require("crypto");
const nodemailer = require("nodemailer");

const TOKEN_TTL_MS  = 1000 * 60 * 30; // 30 min — password reset links
const VERIFY_TTL_MS = 1000 * 60 * 60 * 24; // 24 h — email verify links (also declared below for clarity)

const mailer = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

function hashToken(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

// ───────────────────────────────────────────────────────
//  MIDDLEWARE
// ───────────────────────────────────────────────────────

// FIX 1: Trust Render proxy so Express sees HTTPS correctly.
// Without this, secure cookies never get set even on HTTPS.
app.set("trust proxy", 1);

// FIX 2: Render does NOT auto-set NODE_ENV="production".
// Use the RENDER env var (always "true" on Render) as the reliable check.
const IS_PROD = process.env.RENDER === "true" || process.env.NODE_ENV === "production";

// FIX 3: CORS with function-based origin for better cross-origin cookie support.
app.use(cors({
  origin: function (origin, callback) {
    const allowed = [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:5500",
      "http://127.0.0.1:5500",
      "https://roadmapx.onrender.com",
      "https://roadmapx.pages.dev",
      "https://roadmapx-frontend.pages.dev",
    ];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS: origin not allowed: " + origin));
    }
  },
  credentials: true,
}));

app.use(express.json());

app.use(session({
  name:   "rx_sid",
  secret: process.env.SESSION_SECRET || "change-me-in-env",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: {
    httpOnly: true,
    // Cross-origin (Cloudflare Pages -> Render) REQUIRES sameSite:"none" + secure:true.
    // sameSite:"lax" silently drops cookies on cross-origin requests,
    // causing the "logged in but redirected back to login" bug.
    sameSite: IS_PROD ? "none" : "lax",
    secure:   IS_PROD,
    maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
  },
}));

app.use(express.static(__dirname));
app.use('/api/steps', stepRoutes);
app.use('/api/roadmaps', roadmapRoutes);

// ───────────────────────────────────────────────────────
//  DATABASE CONNECTION
// ───────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ═══════════════════════════════════════════════════════
//  SCHEMAS & MODELS
// ═══════════════════════════════════════════════════════

// 1. User — stores passwordHash (never plaintext)
const userSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  email:        { type: String, default: "" },
  loginAlerts:  { type: Boolean, default: false },
  createdAt:    { type: Date, default: Date.now },
  twoFactorEnabled:     { type: Boolean, default: false },
  twoFactorSecret:      { type: String, default: "" },
  emailVerified:        { type: Boolean, default: false },
  verifyTokenHash:      { type: String },
  verifyTokenExpires:   { type: Date },
  resetTokenHash:       { type: String },
  resetTokenExpires:    { type: Date },
});
const User = mongoose.model("User", userSchema);

// 2. Unified UserData — this is the heart of the hybrid system.
//    One document per user, contains all app data in one place.
//    Using a single document makes atomic updates simple and avoids
//    N+1 queries. We use upsert (create-or-update) on every save.
const userDataSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },  // = username
  // Streak: stores per-type streak info (ai, dsa, proj, extra)
  streaks: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // Notes: stores extra/project notes (AI+DSA notes go through /save-text)
  notes: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  // Badges: array of earned badge IDs
  badges: {
    type: [String],
    default: [],
  },
  // Pomodoro stats: { ai: N, dsa: N, projects: N, extra: N }
  pomodoroStats: {
    type: mongoose.Schema.Types.Mixed,
    default: { ai: 0, dsa: 0, projects: 0, extra: 0 },
  },
  // AI & DSA progress (day/topic completion maps)
  aiProgress: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  dsaProgress: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // Attendance calendar { "YYYY-MM-DD": "present"|"absent" }
  attendance: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // Revisions list
  revisions: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  // Projects list
  projects: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  // Pomodoro duration setting
  pomoDuration: { type: Number, default: 25 },

  // FIX: 7 fields that were previously only saved to localStorage
  // AI section notes { topicKey: "note text" }
  aiNotes: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // DSA section notes { topicKey: "note text" }
  dsaNotes: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // Earned badge IDs (separate from the general badges array)
  earnedBadges: {
    type: [String],
    default: [],
  },
  // Revision done tracking list
  revisionsDoneList: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  // Structured AI roadmap progress — beginner/intermediate/advanced
  aiStructBeginner: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  aiStructIntermediate: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  aiStructAdvanced: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  // Bug #9 fix: custom roadmaps were localStorage-only
  customRoadmaps: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },

  updatedAt: { type: Date, default: Date.now },
});
const UserData = mongoose.model("UserData", userDataSchema);

// 3. Attendance (legacy — kept for backwards compat, now scoped by userId)
const attendanceSchema = new mongoose.Schema({
  userId:    { type: String, required: true },  // FIX: added userId
  date:      { type: String, required: true },
  status:    { type: String, enum: ["present", "absent"], required: true },
  createdAt: { type: Date, default: Date.now },
});
const Attendance = mongoose.model("Attendance", attendanceSchema);

// 4. Progress (legacy, now scoped by userId)
const progressSchema = new mongoose.Schema({
  userId:    { type: String, required: true },  // FIX: added userId
  topic:     { type: String, required: true },
  completed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Progress = mongoose.model("Progress", progressSchema);

// 5. Notes (legacy /save-text endpoint, now scoped by userId)
const noteSchema = new mongoose.Schema({
  userId:    { type: String, required: true },  // FIX: added userId
  title:     { type: String, required: true },
  content:   { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Note = mongoose.model("Note", noteSchema);

// 6. Pomodoro sessions (legacy, now scoped by userId)
const pomodoroSchema = new mongoose.Schema({
  userId:  { type: String, required: true },  // FIX: added userId
  minutes: { type: Number, required: true },
  date:    { type: Date, default: Date.now },
});
const Pomodoro = mongoose.model("Pomodoro", pomodoroSchema);


// ═══════════════════════════════════════════════════════
//  RATE LIMITERS  (Bug #5 fix — brute-force protection)
// ═══════════════════════════════════════════════════════

// Max 10 auth attempts (register or login) per IP per 15 minutes.
// After 10 failures the attacker must wait — passwords stay safe.
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000, // 15 minutes
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { success: false, message: "Too many attempts. Please try again in 15 minutes." },
  // Skip successful responses so only failures count against the limit
  skipSuccessfulRequests: true,
});

// ═══════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, message: "Not logged in." });
}

// ═══════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════

// ── AUTH ─────────────────────────────────────────────────

// GET /me — called by frontend isLoggedIn() on every page load
app.get("/me", (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ success: true, username: req.session.user });
  }
  return res.status(401).json({ success: false, message: "Not logged in." });
});

// POST /logout
app.post("/logout", (req, res) => {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(() => {
    res.clearCookie("rx_sid");
    res.json({ success: true, message: "Logged out." });
  });
});

// ── GOOGLE SIGN-IN ──────────────────────────────────────
let OAuth2Client, gsiClient;
try {
  ({ OAuth2Client } = require("google-auth-library"));
  if (process.env.GOOGLE_CLIENT_ID) {
    gsiClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }
} catch (e) {
  console.warn("google-auth-library not available, Google Sign-In disabled.");
}

app.post("/auth/google", async (req, res) => {
  if (!gsiClient) {
    return res.status(503).json({ success: false, message: "Google Sign-In not configured." });
  }
  try {
    const { credential } = req.body;
    if (!credential)
      return res.status(400).json({ success: false, message: "No credential provided." });

    const ticket = await gsiClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const googleEmail = payload.email;
    const googleName  = payload.name || googleEmail.split("@")[0];

    let user = await User.findOne({ email: googleEmail });
    if (!user) {
      const safeUsername = googleName.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20)
                         + "_" + Math.random().toString(36).slice(2, 6);
      const dummyHash = await bcrypt.hash(Math.random().toString(36), 12);
      user = await User.create({ username: safeUsername, passwordHash: dummyHash, email: googleEmail });
    }

    req.session.user = user.username;
    tagSession(req);
    res.json({ success: true, username: user.username, email: googleEmail });
  } catch (err) {
    console.error("Google auth error:", err);
    res.status(401).json({ success: false, message: "Google sign-in failed." });
  }
});

// ══════════════════════════════════════════════════════════
//  UNIFIED USER DATA API  ← The core of the hybrid system
//
//  GET  /api/user-data   → returns the full data blob for
//                          the logged-in user from MongoDB.
//  POST /api/user-data   → upserts (creates or fully updates)
//                          the data blob for the logged-in user.
//
//  Both endpoints require a valid session. The frontend
//  loadUserData() / saveUserData() call these when logged in,
//  and fall back to localStorage when not logged in.
// ══════════════════════════════════════════════════════════

// GET /api/user-data
app.get("/api/user-data", requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;

    // Find the user's data document. If it doesn't exist yet
    // (first login), return the default empty structure so
    // the frontend always gets a consistent shape.
    let doc = await UserData.findOne({ userId });

    if (!doc) {
      // Return defaults — don't create yet (no write on every GET)
      return res.json({
        success: true,
        data: {
          streaks:              {},
          notes:                [],
          badges:               [],
          pomodoroStats:        { ai: 0, dsa: 0, projects: 0, extra: 0 },
          aiProgress:           {},
          dsaProgress:          {},
          attendance:           {},
          revisions:            [],
          projects:             [],
          pomoDuration:         25,
          aiNotes:              {},
          dsaNotes:             {},
          earnedBadges:         [],
          revisionsDoneList:    [],
          aiStructBeginner:     {},
          aiStructIntermediate: {},
          aiStructAdvanced:     {},
          customRoadmaps:       [],
        },
      });
    }

    res.json({ success: true, data: doc.toObject() });
  } catch (err) {
    console.error("GET /api/user-data error:", err);
    res.status(500).json({ success: false, message: "Failed to load user data." });
  }
});

// POST /api/user-data
app.post("/api/user-data", requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const incoming = req.body;

    // Validate: we only accept an object body
    if (!incoming || typeof incoming !== "object") {
      return res.status(400).json({ success: false, message: "Invalid data format." });
    }

    // Build the update payload — only allow known safe fields
    // (never let the client overwrite userId itself)
    const allowedFields = [
      "streaks", "notes", "badges", "pomodoroStats",
      "aiProgress", "dsaProgress", "attendance",
      "revisions", "projects", "pomoDuration",
      // FIX: 7 fields previously missing from backend sync
      "aiNotes", "dsaNotes", "earnedBadges", "revisionsDoneList",
      "aiStructBeginner", "aiStructIntermediate", "aiStructAdvanced",
      // Bug #9 fix: custom roadmaps were localStorage-only
      "customRoadmaps",
    ];
    const update = { updatedAt: new Date() };
    allowedFields.forEach(field => {
      if (incoming[field] !== undefined) {
        update[field] = incoming[field];
      }
    });

    // upsert:true → creates the document if it doesn't exist yet
    // new:true    → returns the updated document
    const doc = await UserData.findOneAndUpdate(
      { userId },
      { $set: update },
      { upsert: true, new: true }
    );

    res.json({ success: true, message: "Data saved.", data: doc.toObject() });
  } catch (err) {
    console.error("POST /api/user-data error:", err);
    res.status(500).json({ success: false, message: "Failed to save user data." });
  }
});

// ── ATTENDANCE (legacy endpoints, now userId-scoped) ────

app.post("/save-attendance", requireAuth, async (req, res) => {
  try {
    const { date, status } = req.body;
    if (!date || !status)
      return res.status(400).json({ success: false, message: "Date and status are required." });
    // FIX: attach userId to every record
    const record = await Attendance.create({ userId: req.session.user, date, status });
    res.status(201).json({ success: true, message: "Attendance saved.", data: record });
  } catch (err) {
    console.error("Save attendance error:", err);
    res.status(500).json({ success: false, message: "Server error saving attendance." });
  }
});

app.get("/get-attendance", requireAuth, async (req, res) => {
  try {
    // FIX: only return THIS user's records
    const records = await Attendance.find({ userId: req.session.user }).sort({ createdAt: -1 });
    res.json({ success: true, data: records });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

// ── PROGRESS (legacy, userId-scoped) ─────────────────────

app.post("/save-progress", requireAuth, async (req, res) => {
  try {
    const { topic, completed } = req.body;
    if (!topic)
      return res.status(400).json({ success: false, message: "Topic is required." });
    const progress = await Progress.create({ userId: req.session.user, topic, completed: completed ?? false });
    res.status(201).json({ success: true, message: "Progress saved.", data: progress });
  } catch (err) {
    console.error("Save progress error:", err);
    res.status(500).json({ success: false, message: "Server error saving progress." });
  }
});

app.get("/get-progress", requireAuth, async (req, res) => {
  try {
    const topics = await Progress.find({ userId: req.session.user }).sort({ createdAt: -1 });
    res.json({ success: true, data: topics });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

// ── NOTES (legacy, userId-scoped) ────────────────────────

app.post("/save-text", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content)
      return res.status(400).json({ success: false, message: "Title and content are required." });
    const note = await Note.create({ userId: req.session.user, title, content });
    res.status(201).json({ success: true, message: "Note saved.", data: note });
  } catch (err) {
    console.error("Save note error:", err);
    res.status(500).json({ success: false, message: "Server error saving note." });
  }
});

app.get("/get-text", requireAuth, async (req, res) => {
  try {
    // FIX: only return THIS user's notes
    const notes = await Note.find({ userId: req.session.user }).sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: notes });
  } catch (err) {
    console.error("Get notes error:", err);
    res.status(500).json({ success: false, message: "Server error fetching notes." });
  }
});

// ── POMODORO (legacy, userId-scoped) ─────────────────────

app.post("/save-pomo", requireAuth, async (req, res) => {
  try {
    const { minutes } = req.body;
    if (minutes === undefined || minutes === null)
      return res.status(400).json({ success: false, message: "Minutes are required." });
    const pomo = await Pomodoro.create({ userId: req.session.user, minutes });
    res.status(201).json({ success: true, message: "Pomodoro session saved.", data: pomo });
  } catch (err) {
    console.error("Save pomodoro error:", err);
    res.status(500).json({ success: false, message: "Server error saving pomodoro session." });
  }
});

app.get("/get-pomo", requireAuth, async (req, res) => {
  try {
    const sessions = await Pomodoro.find({ userId: req.session.user }).sort({ date: -1 });
    res.json({ success: true, data: sessions });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});


// ── PROFILE ───────────────────────────────────────────────

app.get("/profile", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user })
                           .select("username createdAt").lean();
    if (!user) return res.status(404).json({ success: false, message: "Not found." });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

app.post("/profile/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6)
    return res.json({ success: false, message: "New password must be at least 6 characters." });
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false, message: "Not found." });
    const ok = await bcrypt.compare(currentPassword || "", user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Current password is wrong." });
    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true, message: "Password updated." });
  } catch (err) {
    res.status(500).json({ success: false, message: "Update failed." });
  }
});

app.delete("/profile", requireAuth, async (req, res) => {
  const { password } = req.body || {};
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false, message: "Not found." });
    const ok = await bcrypt.compare(password || "", user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Wrong password." });
    await User.deleteOne({ _id: user._id });
    // Also delete all user data when account is deleted
    await UserData.deleteOne({ userId: req.session.user });
    req.session.destroy(() => {
      res.clearCookie("rx_sid");
      res.json({ success: true });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Delete failed." });
  }
});

app.post("/profile/username", requireAuth, async (req, res) => {
  const { newUsername, password } = req.body || {};
  if (!newUsername || newUsername.length < 3)
    return res.json({ success: false, message: "Username must be at least 3 characters." });
  if (!/^[a-zA-Z0-9_]+$/.test(newUsername))
    return res.json({ success: false, message: "Letters, numbers, and underscores only." });
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false, message: "Not found." });
    const ok = await bcrypt.compare(password || "", user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Wrong password." });
    if (newUsername === user.username)
      return res.json({ success: false, message: "That is already your username." });
    if (await User.findOne({ username: newUsername }))
      return res.json({ success: false, message: "Username already taken." });
    const oldUsername = user.username;
    user.username = newUsername;
    await user.save();
    // Keep UserData in sync with the new username
    await UserData.updateOne({ userId: oldUsername }, { $set: { userId: newUsername } });
    req.session.user = newUsername;
    res.json({ success: true, username: newUsername });
  } catch (err) {
    res.status(500).json({ success: false, message: "Update failed." });
  }
});

app.post("/profile/email", requireAuth, async (req, res) => {
  const { newEmail, password } = req.body || {};
  if (!newEmail || !/.+@.+\..+/.test(newEmail))
    return res.json({ success: false, message: "Invalid email address." });
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false, message: "Not found." });
    const ok = await bcrypt.compare(password || "", user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Wrong password." });
    if (newEmail.toLowerCase() === user.email)
      return res.json({ success: false, message: "That is already your email." });
    user.email = newEmail.toLowerCase();
    await user.save();
    res.json({ success: true, message: "Email updated." });
  } catch (err) {
    res.status(500).json({ success: false, message: "Update failed." });
  }
});

app.get("/profile/login-alerts", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user }).lean();
    if (!user) return res.status(404).json({ success: false });
    res.json({ success: true, enabled: !!user.loginAlerts });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.post("/profile/login-alerts", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false });
    user.loginAlerts = !!req.body.enabled;
    await user.save();
    res.json({ success: true, enabled: user.loginAlerts });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// ─────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.send("RoadmapX Backend is running 🚀");
});

// ── GLOBAL ERROR HANDLER ──────────────────────────────────
// Must be defined with 4 parameters so Express treats it as
// an error-handling middleware (not a regular route).
// Without this, unhandled throws reach Express's built-in

// ═══════════════════════════════════════════════════════
//  RoadmapX — Sessions & Devices management
//
//  Builds on backend_remember_snippet.js (express-session +
//  connect-mongo). On every login we tag req.session with
//  device metadata so users can later see and revoke them.
//
//  No new npm packages required.
// ═══════════════════════════════════════════════════════


// 1) Middleware — call this AFTER req.session.user is set
//    (i.e. inside /login and /auth/google success branches,
//     right before res.json({ success: true })).
//
//    Usage in /login:
//      req.session.user = user.username;
//      tagSession(req);
function tagSession(req) {
  const ua = req.headers["user-agent"] || "Unknown device";
  req.session.meta = {
    ua,
    ip:        req.ip,
    createdAt: new Date().toISOString(),
    device:    parseDevice(ua),
  };
}

function parseDevice(ua) {
  const u = ua.toLowerCase();
  let os = "Unknown OS";
  if (u.includes("windows"))      os = "Windows";
  else if (u.includes("mac os"))  os = "macOS";
  else if (u.includes("iphone"))  os = "iOS";
  else if (u.includes("ipad"))    os = "iPadOS";
  else if (u.includes("android")) os = "Android";
  else if (u.includes("linux"))   os = "Linux";

  let browser = "Browser";
  if (u.includes("edg/"))             browser = "Edge";
  else if (u.includes("chrome/"))     browser = "Chrome";
  else if (u.includes("firefox/"))    browser = "Firefox";
  else if (u.includes("safari/"))     browser = "Safari";

  return `${browser} on ${os}`;
}

// 3) GET /sessions  — list all active sessions for the current user
app.get("/sessions", requireAuth, async (req, res) => {
  try {
    const coll = mongoose.connection.collection("sessions"); // connect-mongo default
    const all  = await coll.find({}).toArray();

    const username = req.session.user;
    const out = [];

    for (const row of all) {
      let parsed;
      try { parsed = JSON.parse(row.session); } catch (_) { continue; }
      if (!parsed || parsed.user !== username) continue;

      out.push({
        id:        row._id,
        device:    parsed.meta?.device    || "Unknown device",
        ua:        parsed.meta?.ua        || "",
        ip:        parsed.meta?.ip        || "",
        createdAt: parsed.meta?.createdAt || null,
        expiresAt: row.expires || null,
        current:   row._id === req.sessionID,
      });
    }

    out.sort((a, b) => (a.current ? -1 : b.current ? 1 : 0));
    res.json({ success: true, sessions: out });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not load sessions." });
  }
});

// 4) DELETE /sessions/:id  — revoke a specific session
app.delete("/sessions/:id", requireAuth, async (req, res) => {
  try {
    const coll = mongoose.connection.collection("sessions");
    const row  = await coll.findOne({ _id: req.params.id });
    if (!row) return res.json({ success: false, message: "Session not found." });

    let parsed;
    try { parsed = JSON.parse(row.session); } catch (_) {}
    if (!parsed || parsed.user !== req.session.user) {
      return res.status(403).json({ success: false, message: "Not allowed." });
    }

    await coll.deleteOne({ _id: req.params.id });

    // If the user revoked their own current session, kill the cookie too.
    if (req.params.id === req.sessionID) {
      req.session.destroy(() => {
        res.clearCookie("rx_sid");
        res.json({ success: true, signedOut: true });
      });
      return;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not revoke session." });
  }
});

// 5) POST /sessions/revoke-others  — sign out everywhere except here
app.post("/sessions/revoke-others", requireAuth, async (req, res) => {
  try {
    const coll = mongoose.connection.collection("sessions");
    const all  = await coll.find({}).toArray();
    const username   = req.session.user;
    const currentId  = req.sessionID;
    const toDelete   = [];

    for (const row of all) {
      if (row._id === currentId) continue;
      let parsed;
      try { parsed = JSON.parse(row.session); } catch (_) { continue; }
      if (parsed && parsed.user === username) toDelete.push(row._id);
    }

    if (toDelete.length) {
      await coll.deleteMany({ _id: { $in: toDelete } });
    }
    res.json({ success: true, revoked: toDelete.length });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not revoke sessions." });
  }
});

// ═══════════════════════════════════════════════════════
//  RoadmapX — Two-Factor Authentication (TOTP)
//
//  npm install speakeasy qrcode
//
//  User schema additions:
//    twoFactorEnabled    : Boolean  (default false)
//    twoFactorSecret     : String   (base32, set during setup)
//    twoFactorBackupHashes: [String] (sha256 of single-use backup codes)
//
//  Flow:
//    1) Logged-in user calls /2fa/setup → gets QR code + secret.
//    2) User scans into Google Authenticator / Authy / 1Password.
//    3) User submits a code to /2fa/enable → 2FA is on, backup codes returned.
//    4) On future /login, if 2FA is enabled, the response is:
//         { success:false, code:"2FA_REQUIRED", challengeId }
//       Frontend collects the code and calls /2fa/verify-login.
//    5) /2fa/disable requires a current TOTP code.
// ═══════════════════════════════════════════════════════

const speakeasy = require("speakeasy");
const QRCode    = require("qrcode");
// Reuses `crypto`, `hashToken`, `requireAuth`, `tagSession` from earlier snippets.

// In-memory pending-login store (keyed by random challengeId).
// For production with multiple servers, move this to Redis or Mongo.
const pendingLogins = new Map(); // challengeId -> { username, remember, expires }
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of pendingLogins) if (p.expires < now) pendingLogins.delete(id);
}, 60_000);

function newBackupCodes(n = 10) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    // Format: XXXX-XXXX (uppercase alphanumeric)
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}`);
  }
  return codes;
}

// 1) /2fa/setup  — generate a secret + QR for the logged-in user
app.post("/2fa/setup", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    if (user.twoFactorEnabled) {
      return res.json({ success: false, message: "2FA is already enabled." });
    }

    const secret = speakeasy.generateSecret({
      name: `RoadmapX (${user.username})`,
      issuer: "RoadmapX",
      length: 20,
    });

    // Stash provisionally — only marked "enabled" after /2fa/enable succeeds.
    user.twoFactorSecret = secret.base32;
    await user.save();

    const otpauthUrl = secret.otpauth_url;
    const qrDataUrl  = await QRCode.toDataURL(otpauthUrl);

    res.json({
      success: true,
      secret:  secret.base32,
      qrDataUrl,
      otpauthUrl,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Setup failed." });
  }
});

// 2) /2fa/enable  body: { code }
app.post("/2fa/enable", requireAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.json({ success: false, message: "Code required." });

  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user || !user.twoFactorSecret) {
      return res.json({ success: false, message: "Run setup first." });
    }
    const ok = speakeasy.totp.verify({
      secret:   user.twoFactorSecret,
      encoding: "base32",
      token:    String(code).replace(/\s/g, ""),
      window:   1,
    });
    if (!ok) return res.json({ success: false, message: "Invalid code. Try again." });

    const backupCodes = newBackupCodes();
    user.twoFactorEnabled       = true;
    user.twoFactorBackupHashes  = backupCodes.map(hashToken);
    await user.save();

    res.json({ success: true, backupCodes });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not enable 2FA." });
  }
});

// 3) /2fa/disable  body: { code }
app.post("/2fa/disable", requireAuth, async (req, res) => {
  const { code } = req.body || {};
  try {
    const user = await User.findOne({ username: req.session.user });
    if (!user || !user.twoFactorEnabled) {
      return res.json({ success: false, message: "2FA is not enabled." });
    }
    const ok = speakeasy.totp.verify({
      secret:   user.twoFactorSecret,
      encoding: "base32",
      token:    String(code || "").replace(/\s/g, ""),
      window:   1,
    });
    if (!ok) return res.json({ success: false, message: "Invalid code." });

    user.twoFactorEnabled      = false;
    user.twoFactorSecret       = undefined;
    user.twoFactorBackupHashes = [];
    await user.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not disable 2FA." });
  }
});

// 4) /2fa/status  — used by the settings page
app.get("/2fa/status", requireAuth, async (req, res) => {
  const user = await User.findOne({ username: req.session.user });
  res.json({
    success: true,
    enabled: !!(user && user.twoFactorEnabled),
  });
});

// 5) Modify your existing /login: AFTER password check passes,
//    BEFORE setting req.session.user, insert this block:
//
//    if (user.twoFactorEnabled) {
//      const challengeId = crypto.randomBytes(24).toString("hex");
//      pendingLogins.set(challengeId, {
//        username: user.username,
//        remember: !!remember,
//        expires:  Date.now() + 5 * 60 * 1000, // 5 min
//      });
//      return res.json({ success: false, code: "2FA_REQUIRED", challengeId });
//    }
//    req.session.user = user.username;
//    tagSession(req);
//    ...

// 6) /2fa/verify-login  body: { challengeId, code }
app.post("/2fa/verify-login", async (req, res) => {
  const { challengeId, code } = req.body || {};
  if (!challengeId || !code) {
    return res.json({ success: false, message: "Missing fields." });
  }
  const pending = pendingLogins.get(challengeId);
  if (!pending || pending.expires < Date.now()) {
    pendingLogins.delete(challengeId);
    return res.json({ success: false, message: "Login session expired. Sign in again." });
  }

  try {
    const user = await User.findOne({ username: pending.username });
    if (!user || !user.twoFactorEnabled) {
      pendingLogins.delete(challengeId);
      return res.json({ success: false, message: "Invalid request." });
    }

    const cleaned = String(code).replace(/\s/g, "").toUpperCase();
    let ok = false;

    // Try TOTP first (6 digits)
    if (/^\d{6}$/.test(cleaned)) {
      ok = speakeasy.totp.verify({
        secret:   user.twoFactorSecret,
        encoding: "base32",
        token:    cleaned,
        window:   1,
      });
    }

    // Then try a backup code (one-time use)
    if (!ok && /^[A-Z0-9]{4}-?[A-Z0-9]{4}$/.test(cleaned)) {
      const normalized = cleaned.includes("-") ? cleaned : `${cleaned.slice(0,4)}-${cleaned.slice(4)}`;
      const h = hashToken(normalized);
      const idx = (user.twoFactorBackupHashes || []).indexOf(h);
      if (idx !== -1) {
        ok = true;
        user.twoFactorBackupHashes.splice(idx, 1);
        await user.save();
      }
    }

    if (!ok) return res.json({ success: false, message: "Invalid code." });

    pendingLogins.delete(challengeId);
    req.session.user = user.username;
    tagSession(req);
    if (pending.remember) {
      req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
    } else {
      req.session.cookie.expires = false;
    }
    res.json({
      success: true,
      username: user.username,
      backupCodesRemaining: (user.twoFactorBackupHashes || []).length,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Verification failed." });
  }
});

// 1) POST /forgot-password  body: { email }
//    Always responds success — never reveal whether the email exists.
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.json({ success: false, message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email: String(email).toLowerCase() });

    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      user.resetTokenHash    = hashToken(rawToken);
      user.resetTokenExpires = new Date(Date.now() + TOKEN_TTL_MS);
      await user.save();

      const link = `${process.env.APP_URL}/reset-password.html` +
                   `?token=${rawToken}&u=${encodeURIComponent(user.username)}`;

      await mailer.sendMail({
        from: process.env.MAIL_FROM,
        to:   user.email,
        subject: "Reset your RoadmapX password",
        text:
`Hi ${user.username},

We received a request to reset your RoadmapX password.
Click the link below within 30 minutes to choose a new password:

${link}

If you didn't request this, you can ignore this email.`,
      });
    }

    return res.json({
      success: true,
      message: "If that email is registered, a reset link has been sent.",
    });
  } catch (err) {
    return res
      .status(500)
      .json({ success: false, message: "Could not send reset email." });
  }
});

// 2) POST /reset-password  body: { token, username, password }
app.post("/reset-password", async (req, res) => {
  const { token, username, password } = req.body || {};
  if (!token || !username || !password) {
    return res.json({ success: false, message: "Missing fields." });
  }
  if (password.length < 6) {
    return res.json({
      success: false,
      message: "Password must be at least 6 characters.",
    });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !user.resetTokenHash || !user.resetTokenExpires) {
      return res.json({ success: false, message: "Invalid or expired link." });
    }
    if (user.resetTokenExpires.getTime() < Date.now()) {
      return res.json({ success: false, message: "This link has expired." });
    }
    if (user.resetTokenHash !== hashToken(token)) {
      return res.json({ success: false, message: "Invalid or expired link." });
    }

    user.passwordHash       = await bcrypt.hash(password, 10);
    user.resetTokenHash     = undefined;
    user.resetTokenExpires  = undefined;
    await user.save();

    return res.json({ success: true, message: "Password updated. You can log in now." });
  } catch (err) {
    return res
      .status(500)
      .json({ success: false, message: "Could not reset password." });
  }
});

async function sendVerificationEmail(user) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  user.verifyTokenHash    = hashToken(rawToken);
  user.verifyTokenExpires = new Date(Date.now() + VERIFY_TTL_MS);
  await user.save();

  const link = `${process.env.APP_URL}/verify-email.html` +
               `?token=${rawToken}&u=${encodeURIComponent(user.username)}`;

  await mailer.sendMail({
    from: process.env.MAIL_FROM,
    to:   user.email,
    subject: "Confirm your RoadmapX email",
    text:
`Hi ${user.username},

Welcome to RoadmapX! Please confirm your email by clicking
the link below within 24 hours:

${link}

If you didn't sign up, you can ignore this message.`,
  });
}

// 1) /register — create unverified account + send verification email.
//    body: { username, email, password }
app.post("/register", authLimiter, async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.json({ success: false, message: "All fields are required." });
  }
  if (password.length < 6) {
    return res.json({ success: false, message: "Password must be at least 6 characters." });
  }

  try {
    const normEmail = String(email).toLowerCase();
    const exists = await User.findOne({ $or: [{ username }, { email: normEmail }] });
    if (exists) {
      return res.json({ success: false, message: "Username or email already in use." });
    }

    const user = new User({
      username,
      email: normEmail,
      passwordHash: await bcrypt.hash(password, 10),
      emailVerified: false,
    });
    await user.save();
    await sendVerificationEmail(user);

    return res.json({
      success: true,
      message: "Account created. Check your inbox to verify your email.",
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Could not create account." });
  }
});

// 2) /login — refuse unverified accounts.
//    Includes authLimiter (brute-force protection) + tagSession (device tracking).
app.post("/login", authLimiter, async (req, res) => {
  const { username, password, remember } = req.body || {};
  if (!username || !password) {
    return res.json({ success: false, message: "Missing credentials." });
  }

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.json({ success: false, message: "Invalid username or password." });
  }

  if (!user.emailVerified) {
    return res.json({
      success: false,
      code: "EMAIL_NOT_VERIFIED",
      message: "Please verify your email before logging in.",
    });
  }

  req.session.user = user.username;
  tagSession(req); // tag device/IP metadata for sessions page
  if (remember) {
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 days
  } else {
    req.session.cookie.expires = false;
  }
  return res.json({ success: true, username: user.username });
});

// 3) /verify-email  body: { token, username }
app.post("/verify-email", async (req, res) => {
  const { token, username } = req.body || {};
  if (!token || !username) {
    return res.json({ success: false, message: "Invalid verification link." });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.json({ success: false, message: "Invalid verification link." });
    }
    if (user.emailVerified) {
      return res.json({ success: true, message: "Email already verified." });
    }
    if (
      !user.verifyTokenHash ||
      !user.verifyTokenExpires ||
      user.verifyTokenExpires.getTime() < Date.now() ||
      user.verifyTokenHash !== hashToken(token)
    ) {
      return res.json({
        success: false,
        code: "EXPIRED",
        message: "This link is invalid or has expired.",
      });
    }

    user.emailVerified      = true;
    user.verifyTokenHash    = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    return res.json({ success: true, message: "Email verified! You can log in now." });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Verification failed." });
  }
});

// 4) /resend-verification  body: { email }
//    Always responds success — never reveals if the email exists.
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.json({ success: false, message: "Email is required." });

  try {
    const user = await User.findOne({ email: String(email).toLowerCase() });
    if (user && !user.emailVerified) {
      await sendVerificationEmail(user);
    }
    return res.json({
      success: true,
      message: "If that account needs verification, a new email has been sent.",
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Could not send email." });
  }
});
// handler which returns an HTML page, breaking JSON clients.
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error("[unhandled error]", err);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    success: false,
    message: err.message || "An unexpected server error occurred.",
  });
});

// ── 404 FALLBACK ──────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found." });
});

// ── START SERVER ──────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
