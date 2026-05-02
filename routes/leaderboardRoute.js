// ═══════════════════════════════════════════════════════
//  RoadmapX — Leaderboard API Route  (v2 — field-correct)
//  GET /api/leaderboard?category=streak|pomodoro|progress|allround&limit=50
//
//  Fixes in v2:
//   - streaks: reads global.current correctly (was iterating wrong keys)
//   - aiProgress / dsaProgress: values are { done: true } objects, not booleans
//   - aiStruct*: same — { done: true } objects
//   - Zero-score tie-breaking by join date so ranking is stable
//   - Cache busted to avoid serving stale zero scores
// ═══════════════════════════════════════════════════════

const express  = require('express');
const router   = express.Router();
const mongoose = require('mongoose');

// ── In-memory cache ──────────────────────────────────────
const _cache   = new Map();
const CACHE_TTL = 60 * 1000; // 60 s

function getCached(key) {
  const hit = _cache.get(key);
  if (hit && Date.now() - hit.ts < CACHE_TTL) return hit.data;
  return null;
}
function setCache(key, data) {
  _cache.set(key, { data, ts: Date.now() });
}

// ── Count "done" entries in an aiProgress / dsaProgress map ──
// Values look like:  { done: true, completedDate: "2025-01-01" }
// OR legacy boolean: true
function countDoneInProgressMap(obj) {
  if (!obj || typeof obj !== 'object') return 0;
  return Object.values(obj).filter(v => {
    if (v === true) return true;                          // legacy boolean
    if (v && typeof v === 'object') return v.done === true; // normal object
    return false;
  }).length;
}

// ── Compute all scores from one UserData document ────────
function computeScores(doc) {

  // ── 1. STREAK ─────────────────────────────────────────
  // Schema: streaks is Mixed, structured as:
  //   { global: { current, longest, lastDate, history, parts }, ai: {...}, dsa: {...} }
  let bestStreak = 0;
  try {
    const streaks = doc.streaks || {};

    // Prefer the unified global streak
    if (streaks.global && typeof streaks.global === 'object') {
      const cur = Number(streaks.global.current) || 0;
      const lng = Number(streaks.global.longest)  || 0;
      bestStreak = Math.max(cur, lng);
    }

    // Fallback: per-type streaks (legacy users without global)
    ['ai', 'dsa', 'proj', 'extra'].forEach(key => {
      if (!streaks[key] || typeof streaks[key] !== 'object') return;
      const cur = Number(streaks[key].current) || 0;
      const lng = Number(streaks[key].longest)  || 0;
      if (cur > bestStreak) bestStreak = cur;
      if (lng > bestStreak) bestStreak = lng;
    });
  } catch (_) {}

  // ── 2. POMODORO ───────────────────────────────────────
  // Schema: pomodoroStats = { ai: N, dsa: N, projects: N, extra: N }
  let totalPomo = 0;
  try {
    const ps = doc.pomodoroStats || {};
    totalPomo =
      (Number(ps.ai)       || 0) +
      (Number(ps.dsa)      || 0) +
      (Number(ps.projects) || 0) +
      (Number(ps.extra)    || 0);
  } catch (_) {}

  // ── 3. PROGRESS ───────────────────────────────────────
  let progressScore = 0;

  try {
    // a) Flat AI roadmap progress  { dayNum: { done: true, completedDate } }
    progressScore += countDoneInProgressMap(doc.aiProgress);
  } catch (_) {}

  try {
    // b) DSA progress — topic keys "t1","t2"... and project keys "proj_X"
    const dsa = doc.dsaProgress || {};
    Object.entries(dsa).forEach(([key, val]) => {
      if (key.startsWith('proj_')) {
        if (val === 'completed') progressScore++;
      } else {
        if (val === true || (val && typeof val === 'object' && val.done === true)) {
          progressScore++;
        }
      }
    });
  } catch (_) {}

  try {
    // c) Structured AI roadmap (3 levels)
    progressScore += countDoneInProgressMap(doc.aiStructBeginner);
    progressScore += countDoneInProgressMap(doc.aiStructIntermediate);
    progressScore += countDoneInProgressMap(doc.aiStructAdvanced);
  } catch (_) {}

  try {
    // d) Custom roadmaps (week/day structure)
    const roadmaps = doc.customRoadmaps || [];
    roadmaps.forEach(rm => {
      (rm.weeks || []).forEach(wk => {
        (wk.days || []).forEach(d => {
          if (d.completed) progressScore++;
        });
      });
    });
  } catch (_) {}

  // ── 4. ALL-ROUND composite ────────────────────────────
  const allround = Math.round(
    bestStreak    * 10 +
    totalPomo     * 3  +
    progressScore * 5
  );

  return { bestStreak, totalPomo, progressScore, allround };
}

// ── GET /api/leaderboard ─────────────────────────────────
router.get('/', async (req, res) => {
  const category = (req.query.category || 'allround').toLowerCase();
  const limit    = Math.min(parseInt(req.query.limit) || 50, 100);

  const validCategories = ['streak', 'pomodoro', 'progress', 'allround'];
  if (!validCategories.includes(category)) {
    return res.status(400).json({ success: false, message: 'Invalid category.' });
  }

  const cacheKey = `${category}:${limit}`;
  const cached   = getCached(cacheKey);
  if (cached) {
    return res.json({ success: true, cached: true, data: cached });
  }

  try {
    const UserData = mongoose.model('UserData');
    const User     = mongoose.model('User');

    const [allDocs, allUsers] = await Promise.all([
      UserData.find({}).lean(),
      User.find({}).select('username createdAt').lean(),
    ]);

    const joinMap = {};
    allUsers.forEach(u => { joinMap[u.username] = u.createdAt; });

    const sortKey = {
      streak:   'bestStreak',
      pomodoro: 'totalPomo',
      progress: 'progressScore',
      allround: 'allround',
    }[category];

    const scored = allDocs.map(doc => ({
      userId:   doc.userId,
      joinedAt: joinMap[doc.userId] || null,
      ...computeScores(doc),
    }));

    // Primary sort: score desc. Tie-break: earlier join date wins.
    scored.sort((a, b) => {
      const diff = b[sortKey] - a[sortKey];
      if (diff !== 0) return diff;
      const da = a.joinedAt ? new Date(a.joinedAt).getTime() : Infinity;
      const db = b.joinedAt ? new Date(b.joinedAt).getTime() : Infinity;
      return da - db;
    });

    const finalList = scored.slice(0, limit);

    const data = finalList.map((entry, idx) => ({
      rank:     idx + 1,
      username: entry.userId,
      scores: {
        streak:   entry.bestStreak,
        pomodoro: entry.totalPomo,
        progress: entry.progressScore,
        allround: entry.allround,
      },
      joinedAt: entry.joinedAt,
    }));

    setCache(cacheKey, data);
    return res.json({ success: true, cached: false, category, data });

  } catch (err) {
    console.error('[Leaderboard] GET / error:', err);
    return res.status(500).json({ success: false, message: 'Could not load leaderboard.' });
  }
});

// ── GET /api/leaderboard/me ──────────────────────────────
router.get('/me', async (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, message: 'Not logged in.' });
  }

  const userId = req.session.user;

  try {
    const UserData = mongoose.model('UserData');
    const allDocs  = await UserData.find({}).lean();

    const scored = allDocs.map(doc => ({
      userId: doc.userId,
      ...computeScores(doc),
    }));

    const myEntry = scored.find(s => s.userId === userId);

    const rankIn = (key) => {
      const sorted = [...scored].sort((a, b) => b[key] - a[key]);
      const idx    = sorted.findIndex(s => s.userId === userId);
      return idx >= 0 ? idx + 1 : null;
    };

    const scores = myEntry
      ? { streak: myEntry.bestStreak, pomodoro: myEntry.totalPomo, progress: myEntry.progressScore, allround: myEntry.allround }
      : { streak: 0, pomodoro: 0, progress: 0, allround: 0 };

    return res.json({
      success: true,
      data: {
        username: userId,
        scores,
        ranks: {
          streak:   rankIn('bestStreak'),
          pomodoro: rankIn('totalPomo'),
          progress: rankIn('progressScore'),
          allround: rankIn('allround'),
        },
        totalUsers: scored.length,
      },
    });

  } catch (err) {
    console.error('[Leaderboard] GET /me error:', err);
    return res.status(500).json({ success: false, message: 'Could not fetch your rank.' });
  }
});

module.exports = router;
