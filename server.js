// ═══════════════════════════════════════════════════════
//  RoadmapX — Backend Server
//  Stack: Node.js + Express + MongoDB (Mongoose)
// ═══════════════════════════════════════════════════════
require('dotenv').config();
const express    = require("express");
const mongoose   = require("mongoose");
const cors       = require("cors");
const bcrypt = require("bcryptjs");
const session    = require("express-session");
const MongoStore = require("connect-mongo").default || require("connect-mongo");
const app        = express();

// ───────────────────────────────────────────────────────
//  MIDDLEWARE
// ───────────────────────────────────────────────────────

// FIX: cors must allow credentials so the session cookie works
app.use(cors({
  origin: [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://roadmapx.onrender.com",
    "https://roadmapx.pages.dev"
    "https://roadmapx-frontend.pages.dev"
  ],
  credentials: true
}));

app.use(express.json());

app.use(session({
  name:   "rx_sid",
  secret: process.env.SESSION_SECRET || "change-me",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure:   process.env.NODE_ENV === "production", // false in dev
    maxAge:   7 * 24 * 60 * 60 * 1000,              // 7 days default
  },
}));

app.use(express.static(__dirname));

// ───────────────────────────────────────────────────────
//  DATABASE CONNECTION
// ───────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ═══════════════════════════════════════════════════════
//  SCHEMAS & MODELS
// ═══════════════════════════════════════════════════════

// 1. User — FIX: store passwordHash not plain password
const userSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  email:        { type: String, default: "" },
  loginAlerts:  { type: Boolean, default: false },
  createdAt:    { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// 2. Attendance
const attendanceSchema = new mongoose.Schema({
  date:      { type: String, required: true },
  status:    { type: String, enum: ["present", "absent"], required: true },
  createdAt: { type: Date, default: Date.now },
});
const Attendance = mongoose.model("Attendance", attendanceSchema);

// 3. Progress
const progressSchema = new mongoose.Schema({
  topic:     { type: String, required: true },
  completed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Progress = mongoose.model("Progress", progressSchema);

// 4. Notes
const noteSchema = new mongoose.Schema({
  title:     { type: String, required: true },
  content:   { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Note = mongoose.model("Note", noteSchema);

// 5. Pomodoro
const pomodoroSchema = new mongoose.Schema({
  minutes: { type: Number, required: true },
  date:    { type: Date, default: Date.now },
});
const Pomodoro = mongoose.model("Pomodoro", pomodoroSchema);

// 6. Roadmap
const roadmapSchema = new mongoose.Schema({
  level: { type: String, required: true },
  week:  { type: Number, required: true },
  topic: { type: String, required: true },
});
const Roadmap = mongoose.model("Roadmap", roadmapSchema);

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

// wPOST /register
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required." });
    }
    if (username.length < 3) {
      return res.status(400).json({ success: false, message: "Username must be at least 3 characters." });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ success: false, message: "Username: letters, numbers, underscores only." });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters." });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ success: false, message: "Username already exists." });
    }

    // FIX: hash the password before saving
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

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required." });
    }

    // FIX: find by username only, then compare hash — not plaintext
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }

    req.session.user = user.username;

    // FIX: honour rememberMe — 30-day vs browser-session cookie
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
    } else {
      req.session.cookie.expires = false;
    }

    res.status(200).json({ success: true, message: "Login successful.", username: user.username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error during login." });
  }
});

// GET /me — called by auth_guard.js on every protected page load
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

// ── GOOGLE SIGN-IN (GSI token verification) ──────────────────
const { OAuth2Client } = require("google-auth-library");
const gsiClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ success: false, message: "No credential provided." });
    }

    // Verify the JWT Google sent to the frontend
    const ticket = await gsiClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const googleEmail = payload.email;
    const googleName  = payload.name || googleEmail.split("@")[0];

    // Find or create a user by email
    let user = await User.findOne({ email: googleEmail });
    if (!user) {
      // Create a stub user — no password needed for OAuth users
      const safeUsername = googleName.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20)
                         + "_" + Math.random().toString(36).slice(2, 6);
      const dummyHash = await bcrypt.hash(Math.random().toString(36), 12);
      user = await User.create({
        username:     safeUsername,
        passwordHash: dummyHash,
        email:        googleEmail,
      });
    }

    req.session.user = user.username;
    res.json({ success: true, username: user.username, email: googleEmail });
  } catch (err) {
    console.error("Google auth error:", err);
    res.status(401).json({ success: false, message: "Google sign-in failed." });
  }
});

// ── ATTENDANCE ───────────────────────────────────────────

app.post("/save-attendance", requireAuth, async (req, res) => {
  try {
    const { date, status } = req.body;
    if (!date || !status) {
      return res.status(400).json({ success: false, message: "Date and status are required." });
    }
    const record = await Attendance.create({ date, status });
    res.status(201).json({ success: true, message: "Attendance saved.", data: record });
  } catch (err) {
    console.error("Save attendance error:", err);
    res.status(500).json({ success: false, message: "Server error saving attendance." });
  }
});

app.get("/get-attendance", requireAuth, async (req, res) => {
  try {
    const records = await Attendance.find().sort({ createdAt: -1 });
    res.json({ success: true, data: records });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

// ── PROGRESS ─────────────────────────────────────────────

app.post("/save-progress", requireAuth, async (req, res) => {
  try {
    const { topic, completed } = req.body;
    if (!topic) {
      return res.status(400).json({ success: false, message: "Topic is required." });
    }
    const progress = await Progress.create({ topic, completed: completed ?? false });
    res.status(201).json({ success: true, message: "Progress saved.", data: progress });
  } catch (err) {
    console.error("Save progress error:", err);
    res.status(500).json({ success: false, message: "Server error saving progress." });
  }
});

app.get("/get-progress", requireAuth, async (req, res) => {
  try {
    const topics = await Progress.find().sort({ createdAt: -1 });
    res.json({ success: true, data: topics });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

// ── NOTES ────────────────────────────────────────────────

app.post("/save-text", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.status(400).json({ success: false, message: "Title and content are required." });
    }
    const note = await Note.create({ title, content });
    res.status(201).json({ success: true, message: "Note saved.", data: note });
  } catch (err) {
    console.error("Save note error:", err);
    res.status(500).json({ success: false, message: "Server error saving note." });
  }
});

app.get("/get-text", requireAuth, async (req, res) => {
  try {
    const notes = await Note.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: notes });
  } catch (err) {
    console.error("Get notes error:", err);
    res.status(500).json({ success: false, message: "Server error fetching notes." });
  }
});

// ── POMODORO ─────────────────────────────────────────────

app.post("/save-pomo", requireAuth, async (req, res) => {
  try {
    const { minutes } = req.body;
    if (minutes === undefined || minutes === null) {
      return res.status(400).json({ success: false, message: "Minutes are required." });
    }
    const pomo = await Pomodoro.create({ minutes });
    res.status(201).json({ success: true, message: "Pomodoro session saved.", data: pomo });
  } catch (err) {
    console.error("Save pomodoro error:", err);
    res.status(500).json({ success: false, message: "Server error saving pomodoro session." });
  }
});

app.get("/get-pomo", requireAuth, async (req, res) => {
  try {
    const sessions = await Pomodoro.find().sort({ date: -1 });
    res.json({ success: true, data: sessions });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed." });
  }
});

// ── ROADMAP ──────────────────────────────────────────────

app.post("/save-roadmap", requireAuth, async (req, res) => {
  try {
    const { level, week, topic } = req.body;
    if (!level || !week || !topic) {
      return res.status(400).json({ success: false, message: "Level, week, and topic are required." });
    }
    const roadmap = await Roadmap.create({ level, week, topic });
    res.status(201).json({ success: true, message: "Roadmap data saved.", data: roadmap });
  } catch (err) {
    console.error("Save roadmap error:", err);
    res.status(500).json({ success: false, message: "Server error saving roadmap data." });
  }
});

// ── PROFILE ──────────────────────────────────────────────

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
  if (!newPassword || newPassword.length < 6) {
    return res.json({ success: false, message: "New password must be at least 6 characters." });
  }
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
    req.session.destroy(() => {
      res.clearCookie("rx_sid");
      res.json({ success: true });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Delete failed." });
  }
});


// POST /profile/username — change username
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
    user.username = newUsername;
    await user.save();
    req.session.user = newUsername; // keep session in sync
    res.json({ success: true, username: newUsername });
  } catch (err) {
    res.status(500).json({ success: false, message: "Update failed." });
  }
});

// POST /profile/email — update email address
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

// GET /profile/login-alerts — fetch current setting
app.get("/profile/login-alerts", requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.session.user }).lean();
    if (!user) return res.status(404).json({ success: false });
    res.json({ success: true, enabled: !!user.loginAlerts });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// POST /profile/login-alerts — toggle setting
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

app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

// ───────────────────────────────────────────────────────
//  404 FALLBACK
// ───────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found." });
});

// ───────────────────────────────────────────────────────
//  START SERVER
// ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
