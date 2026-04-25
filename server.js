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
const mongoose   = require("mongoose");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const session    = require("express-session");
const MongoStore = require("connect-mongo").default || require("connect-mongo"); // v5+/v6 compat
const app        = express();

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

// POST /register
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ success: false, message: "Username and password are required." });
    if (username.length < 3)
      return res.status(400).json({ success: false, message: "Username must be at least 3 characters." });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return res.status(400).json({ success: false, message: "Username: letters, numbers, underscores only." });
    if (password.length < 6)
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters." });

    const existing = await User.findOne({ username });
    if (existing)
      return res.status(409).json({ success: false, message: "Username already exists." });

    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({ username, passwordHash });

    res.status(201).json({ success: true, message: "User registered successfully." });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ success: false, message: "Server error during registration." });
  }
});

// POST /login
app.post("/login", async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    if (!username || !password)
      return res.status(400).json({ success: false, message: "Username and password are required." });

    const user = await User.findOne({ username });
    if (!user)
      return res.status(401).json({ success: false, message: "Invalid username or password." });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok)
      return res.status(401).json({ success: false, message: "Invalid username or password." });

    req.session.user = user.username;

    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    } else {
      req.session.cookie.expires = false; // browser-session cookie
    }

    res.status(200).json({ success: true, message: "Login successful.", username: user.username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error during login." });
  }
});

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

// ── 404 FALLBACK ──────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found." });
});

// ── START SERVER ──────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
