// ═══════════════════════════════════════════════════════
//  RoadmapX — Leaderboard API Route
//  GET /api/leaderboard?category=streak&limit=50
//
//  Categories:
//    streak      — best current streak (from streaks object)
//    pomodoro    — total pomodoro sessions (pomodoroStats sum)
//    progress    — most roadmap days completed (customRoadmaps)
//    allround    — composite score across all three
//
//  Privacy: only username is exposed, no emails or IDs.
//  Caching: results are cached in-memory for 60 seconds to
//  avoid hammering MongoDB on every page load.
// ═══════════════════════════════════════════════════════

const express = require('express');
const router  = express.Router();
const mongoose = require('mongoose');

// ── In-memory cache (per category) ──────────────────────
const _cache = new Map(); // key: category → { data, ts }
const CACHE_TTL = 60 * 1000; // 60 seconds

function getCached(key) {
  const hit = _cache.get(key);
  if (hit && Date.now() - hit.ts < CACHE_TTL) return hit.data;
  return null;
}
function setCache(key, data) {
  _cache.set(key, { data, ts: Date.now() });
}

// ── Helper: compute scores from a UserData document ─────
function computeScores(doc) {
  // 1. Best streak across all roadmap types
  let bestStreak = 0;
  try {
    const streaks = doc.streaks || {};
    Object.values(streaks).forEach(s => {
      const v = typeof s === 'object' ? (s.current || s.count || 0) : (Number(s) || 0);
      if (v > bestStreak) bestStreak = v;
    });
  } catch (_) {}

  // 2. Total pomodoro sessions (sum of all categories)
  let totalPomo = 0;
  try {
    const ps = doc.pomodoroStats || {};
    totalPomo = (ps.ai || 0) + (ps.dsa || 0) + (ps.projects || 0) + (ps.extra || 0);
  } catch (_) {}

  // 3. Completed roadmap days across all custom roadmaps
  let completedDays = 0;
  let totalDays = 0;
  try {
    const roadmaps = doc.customRoadmaps || [];
    roadmaps.forEach(rm => {
      (rm.weeks || []).forEach(wk => {
        (wk.days || []).forEach(d => {
          totalDays++;
          if (d.completed) completedDays++;
        });
      });
    });
  } catch (_) {}

  // Also count AI/DSA structured progress as topics done
  let topicsDone = 0;
  try {
    const countDone = (obj) => {
      if (!obj || typeof obj !== 'object') return 0;
      return Object.values(obj).filter(v => v === true || v === 'done' || v === 1).length;
    };
    topicsDone += countDone(doc.aiProgress) + countDone(doc.dsaProgress);
    topicsDone += countDone(doc.aiStructBeginner) + countDone(doc.aiStructIntermediate) + countDone(doc.aiStructAdvanced);
  } catch (_) {}

  const progressScore = completedDays + topicsDone;

  // 4. All-round composite (weighted)
  const allround = Math.round(
    bestStreak    * 10 +   // streak is hardest to maintain
    totalPomo     * 2  +   // consistent focus time
    progressScore * 3      // actual learning progress
  );

  return { bestStreak, totalPomo, progressScore, allround, completedDays, topicsDone };
}

// ── GET /api/leaderboard ─────────────────────────────────
router.get('/', async (req, res) => {
  const category = (req.query.category || 'allround').toLowerCase();
  const limit    = Math.min(parseInt(req.query.limit) || 50, 100);
  const validCategories = ['streak', 'pomodoro', 'progress', 'allround'];

  if (!validCategories.includes(category)) {
    return res.status(400).json({ success: false, message: 'Invalid category.' });
  }

  // Check cache
  const cacheKey = `${category}:${limit}`;
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ success: true, cached: true, data: cached });
  }

  try {
    const UserData = mongoose.model('UserData');
    const User     = mongoose.model('User');

    // Fetch all UserData documents (we need computed scores, can't sort in DB)
    const allDocs = await UserData.find({}).lean();

    // Build scored list
    const scored = allDocs.map(doc => {
      const scores = computeScores(doc);
      return { userId: doc.userId, ...scores };
    });

    // Sort by chosen category
    const sortKey = {
      streak:   'bestStreak',
      pomodoro: 'totalPomo',
      progress: 'progressScore',
      allround: 'allround',
    }[category];

    scored.sort((a, b) => b[sortKey] - a[sortKey]);
    const top = scored.slice(0, limit);

    // Filter out zero-score entries for cleaner leaderboard
    const nonZero = top.filter(e => e[sortKey] > 0);
    const finalList = nonZero.length > 0 ? nonZero : top.slice(0, 10);

    // Get join dates for top users (for tiebreaking display)
    const usernames = finalList.map(e => e.userId);
    const users = await User.find({ username: { $in: usernames } })
      .select('username createdAt').lean();
    const joinMap = {};
    users.forEach(u => { joinMap[u.username] = u.createdAt; });

    // Build final response (no sensitive data)
    const data = finalList.map((entry, idx) => ({
      rank:        idx + 1,
      username:    entry.userId,
      scores: {
        streak:   entry.bestStreak,
        pomodoro: entry.totalPomo,
        progress: entry.progressScore,
        allround: entry.allround,
      },
      joinedAt: joinMap[entry.userId] || null,
    }));

    setCache(cacheKey, data);
    return res.json({ success: true, cached: false, category, data });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return res.status(500).json({ success: false, message: 'Could not load leaderboard.' });
  }
});

// ── GET /api/leaderboard/me ──────────────────────────────
// Returns the current user's rank + scores across all categories
router.get('/me', async (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, message: 'Not logged in.' });
  }

  try {
    const UserData = mongoose.model('UserData');
    const allDocs  = await UserData.find({}).lean();
    const userId   = req.session.user;

    const scored = allDocs.map(doc => ({
      userId: doc.userId,
      ...computeScores(doc),
    }));

    const myDoc = scored.find(s => s.userId === userId);
    if (!myDoc) {
      return res.json({
        success: true,
        data: {
          username: userId,
          scores: { streak: 0, pomodoro: 0, progress: 0, allround: 0 },
          ranks:  { streak: null, pomodoro: null, progress: null, allround: null },
          totalUsers: scored.length,
        },
      });
    }

    // Compute rank in each category
    const rankIn = (key) => {
      const sorted = [...scored].sort((a, b) => b[key] - a[key]);
      return sorted.findIndex(s => s.userId === userId) + 1;
    };

    return res.json({
      success: true,
      data: {
        username: userId,
        scores: {
          streak:   myDoc.bestStreak,
          pomodoro: myDoc.totalPomo,
          progress: myDoc.progressScore,
          allround: myDoc.allround,
        },
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
    console.error('Leaderboard /me error:', err);
    return res.status(500).json({ success: false, message: 'Could not fetch your rank.' });
  }
});

module.exports = router;
