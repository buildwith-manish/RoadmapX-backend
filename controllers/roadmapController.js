const mongoose = require('mongoose');
const { randomUUID } = require('crypto');
const Roadmap = require('../models/Roadmap');

/* ══════════════════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════════════════ */

const VALID_LEVELS  = ['Beginner', 'Intermediate', 'Advanced'];
const ISO_DATE_RE   = /^\d{4}-\d{2}-\d{2}$/;
const MAX_TASKS_PER_DAY = 50;

/* ══════════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════════ */

/**
 * Validate a MongoDB ObjectId string.
 * Returns a 400 response and true if invalid, so callers can do:
 *   if (rejectBadId(req, res)) return;
 */
function rejectBadId(req, res) {
  if (!mongoose.isValidObjectId(req.params.id)) {
    res.status(400).json({ success: false, error: 'Invalid roadmap ID format.' });
    return true;
  }
  return false;
}

/** Build week+day skeleton for a new roadmap */
function buildWeeks(numWeeks) {
  const weeks = [];
  for (let w = 1; w <= numWeeks; w++) {
    const days = [];
    for (let d = 1; d <= 7; d++) {
      days.push({
        day:           (w - 1) * 7 + d,
        notes:         '',
        tasks:         [],
        completed:     false,
        pomodoroCount: 0,
        revisionDates: [],
      });
    }
    weeks.push({ week: w, days });
  }
  return weeks;
}

/** Find a day object inside a roadmap document */
function findDay(roadmap, dayNum) {
  for (const wk of roadmap.weeks) {
    const d = wk.days.find(d => d.day === dayNum);
    if (d) return { week: wk, day: d };
  }
  return null;
}

/** Compute stats from a single roadmap document */
function computeStats(roadmap) {
  let completedDays = 0;
  let totalPomodoro = 0;
  let totalDays     = 0;
  for (const wk of roadmap.weeks) {
    for (const d of wk.days) {
      totalDays++;
      if (d.completed) completedDays++;
      totalPomodoro += (d.pomodoroCount || 0);
    }
  }
  return { completedDays, totalPomodoro, totalDays };
}

/** Strip dangerous HTML from a string (no external deps) */
function sanitize(str) {
  return String(str)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/* ══════════════════════════════════════════════════════
   POST /api/roadmaps/create
   Body: { title, level?, numWeeks }
   Returns: { success, roadmap }
══════════════════════════════════════════════════════ */
exports.createRoadmap = async (req, res) => {
  try {
    const { title, level, numWeeks } = req.body;

    // --- Validate title ---
    if (!title || !String(title).trim()) {
      return res.status(400).json({ success: false, error: 'Title is required.' });
    }
    const safeTitle = sanitize(title.trim());
    if (safeTitle.length > 100) {
      return res.status(400).json({ success: false, error: 'Title must be 100 characters or fewer.' });
    }

    // --- Validate level ---
    const safeLevel = level || null;
    if (safeLevel && !VALID_LEVELS.includes(safeLevel)) {
      return res.status(400).json({ success: false, error: `level must be one of: ${VALID_LEVELS.join(', ')}.` });
    }

    // --- Validate numWeeks ---
    const weeks = parseInt(numWeeks, 10);
    if (!weeks || weeks < 1 || weeks > 52) {
      return res.status(400).json({ success: false, error: 'numWeeks must be an integer between 1 and 52.' });
    }

    const emojiMap = { Beginner: '🟢', Intermediate: '🟡', Advanced: '🔴' };

    const roadmap = await Roadmap.create({
      userId:   req.session.user,
      title:    safeTitle,
      level:    safeLevel,
      emoji:    emojiMap[safeLevel] || '📚',
      weeks:    buildWeeks(weeks),
    });

    res.status(201).json({ success: true, roadmap });
  } catch (err) {
    console.error('createRoadmap:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   GET /api/roadmaps
   Returns a summary list — progress is computed server-side
   so the full weeks payload is NOT sent to the client.
   Returns: { success, roadmaps }
══════════════════════════════════════════════════════ */
exports.getAllRoadmaps = async (req, res) => {
  try {
    const raw = await Roadmap.find({ userId: req.session.user }, {
      title: 1, level: 1, emoji: 1, createdAt: 1, updatedAt: 1, weeks: 1,
    }).lean();

    // Compute per-roadmap progress server-side — keeps the response lean
    const roadmaps = raw.map(rm => {
      const allDays     = (rm.weeks || []).flatMap(w => w.days || []);
      const totalDays   = allDays.length;
      const completed   = allDays.filter(d => d.completed).length;
      const numWeeks    = (rm.weeks || []).length;
      return {
        _id:       rm._id,
        title:     rm.title,
        level:     rm.level,
        emoji:     rm.emoji,
        numWeeks,
        createdAt: rm.createdAt,
        updatedAt: rm.updatedAt,
        progress:  { completed, total: totalDays },
      };
    });

    res.json({ success: true, roadmaps });
  } catch (err) {
    console.error('getAllRoadmaps:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   GET /api/roadmaps/:id
   Returns: { success, roadmap }
══════════════════════════════════════════════════════ */
exports.getRoadmap = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const roadmap = await Roadmap.findById(req.params.id).lean();
    if (!roadmap) {
      return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    }
    if (roadmap.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }
    res.json({ success: true, roadmap });
  } catch (err) {
    console.error('getRoadmap:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   PATCH /api/roadmaps/:id
   Update top-level fields: title, level, emoji
   Body: { title?, level?, emoji? }
   Returns: { success, roadmap }
══════════════════════════════════════════════════════ */
exports.updateRoadmap = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const { title, level, emoji } = req.body;
    const updates = {};

    if (title !== undefined) {
      const safeTitle = sanitize(String(title).trim());
      if (!safeTitle) return res.status(400).json({ success: false, error: 'Title cannot be empty.' });
      if (safeTitle.length > 100) return res.status(400).json({ success: false, error: 'Title max 100 chars.' });
      updates.title = safeTitle;
    }

    if (level !== undefined) {
      if (level !== null && !VALID_LEVELS.includes(level)) {
        return res.status(400).json({ success: false, error: `level must be one of: ${VALID_LEVELS.join(', ')}.` });
      }
      updates.level = level;
    }

    if (emoji !== undefined) {
      updates.emoji = String(emoji).slice(0, 8);  // cap to avoid abuse
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ success: false, error: 'No valid fields provided for update.' });
    }

    // Ownership check before update
    const existing = await Roadmap.findById(req.params.id).lean();
    if (!existing) return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    if (existing.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }

    const roadmap = await Roadmap.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).lean();

    if (!roadmap) return res.status(404).json({ success: false, error: 'Roadmap not found.' });

    res.json({ success: true, roadmap });
  } catch (err) {
    console.error('updateRoadmap:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   DELETE /api/roadmaps/:id
   Returns: { success }
══════════════════════════════════════════════════════ */
exports.deleteRoadmap = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const result = await Roadmap.findById(req.params.id);
    if (!result) {
      return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    }
    if (result.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }
    await Roadmap.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('deleteRoadmap:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   PUT /api/roadmaps/:id/day
   Update a single day: notes, completed, pomodoroCount, revisionDates
   Body: { dayNum, notes?, completed?, pomodoroCount?, revisionDates? }
   Returns: { success, day, stats }
══════════════════════════════════════════════════════ */
exports.updateDay = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const { dayNum, notes, completed, pomodoroCount, revisionDates } = req.body;

    if (dayNum === undefined || dayNum === null) {
      return res.status(400).json({ success: false, error: 'dayNum is required.' });
    }
    const dayNumber = Number(dayNum);
    if (!Number.isInteger(dayNumber) || dayNumber < 1) {
      return res.status(400).json({ success: false, error: 'dayNum must be a positive integer.' });
    }

    // --- Validate optional fields before DB load ---
    if (notes !== undefined) {
      if (typeof notes !== 'string') {
        return res.status(400).json({ success: false, error: 'notes must be a string.' });
      }
      if (notes.length > 2000) {
        return res.status(400).json({ success: false, error: 'notes must be 2000 characters or fewer.' });
      }
    }

    if (pomodoroCount !== undefined) {
      const pc = Number(pomodoroCount);
      if (isNaN(pc) || pc < 0 || pc > 200) {
        return res.status(400).json({ success: false, error: 'pomodoroCount must be between 0 and 200.' });
      }
    }

    if (revisionDates !== undefined) {
      if (!Array.isArray(revisionDates)) {
        return res.status(400).json({ success: false, error: 'revisionDates must be an array.' });
      }
      if (!revisionDates.every(d => typeof d === 'string' && ISO_DATE_RE.test(d))) {
        return res.status(400).json({ success: false, error: 'revisionDates entries must be YYYY-MM-DD strings.' });
      }
    }

    const roadmap = await Roadmap.findById(req.params.id);
    if (!roadmap) {
      return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    }
    if (roadmap.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }

    const found = findDay(roadmap, dayNumber);
    if (!found) {
      return res.status(404).json({ success: false, error: `Day ${dayNumber} not found in this roadmap.` });
    }

    const d = found.day;

    if (notes         !== undefined) d.notes         = sanitize(notes);
    if (completed     !== undefined) d.completed      = Boolean(completed);
    if (pomodoroCount !== undefined) d.pomodoroCount  = Math.min(200, Math.max(0, Number(pomodoroCount)));
    if (revisionDates !== undefined) d.revisionDates  = revisionDates;

    roadmap.markModified('weeks');
    await roadmap.save();

    const stats = computeStats(roadmap);
    res.json({ success: true, day: d, stats });
  } catch (err) {
    console.error('updateDay:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   POST /api/roadmaps/:id/task
   Manage tasks: action = 'add' | 'toggle' | 'delete'
   Body: { dayNum, action, taskText?, taskId? }
   Returns: { success, tasks, taskProgress }
══════════════════════════════════════════════════════ */
exports.manageTask = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const { dayNum, action, taskText, taskId } = req.body;

    if (dayNum === undefined || dayNum === null) {
      return res.status(400).json({ success: false, error: 'dayNum is required.' });
    }
    const dayNumber = Number(dayNum);
    if (!Number.isInteger(dayNumber) || dayNumber < 1) {
      return res.status(400).json({ success: false, error: 'dayNum must be a positive integer.' });
    }

    if (!action) {
      return res.status(400).json({ success: false, error: 'action is required.' });
    }

    const roadmap = await Roadmap.findById(req.params.id);
    if (!roadmap) {
      return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    }
    if (roadmap.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }

    const found = findDay(roadmap, dayNumber);
    if (!found) {
      return res.status(404).json({ success: false, error: `Day ${dayNumber} not found in this roadmap.` });
    }

    const d = found.day;

    switch (action) {
      case 'add': {
        if (!taskText || !String(taskText).trim()) {
          return res.status(400).json({ success: false, error: 'taskText is required for add.' });
        }
        if (d.tasks.length >= MAX_TASKS_PER_DAY) {
          return res.status(400).json({
            success: false,
            error: `Maximum ${MAX_TASKS_PER_DAY} tasks per day reached.`,
          });
        }
        const safeText = sanitize(taskText.trim().slice(0, 200));
        d.tasks.push({ id: randomUUID(), text: safeText, done: false });
        break;
      }

      case 'toggle': {
        if (!taskId) {
          return res.status(400).json({ success: false, error: 'taskId is required for toggle.' });
        }
        const t = d.tasks.find(t => t.id === String(taskId));
        if (!t) return res.status(404).json({ success: false, error: 'Task not found.' });
        t.done = !t.done;
        break;
      }

      case 'delete': {
        if (!taskId) {
          return res.status(400).json({ success: false, error: 'taskId is required for delete.' });
        }
        const before = d.tasks.length;
        d.tasks = d.tasks.filter(t => t.id !== String(taskId));
        if (d.tasks.length === before) {
          return res.status(404).json({ success: false, error: 'Task not found.' });
        }
        break;
      }

      default:
        return res.status(400).json({ success: false, error: `Unknown action "${action}". Use add, toggle, or delete.` });
    }

    roadmap.markModified('weeks');
    await roadmap.save();

    const total = d.tasks.length;
    const done  = d.tasks.filter(t => t.done).length;
    const pct   = total > 0 ? Math.round((done / total) * 100) : 0;

    res.json({
      success:      true,
      tasks:        d.tasks,
      taskProgress: { done, total, pct },
    });
  } catch (err) {
    console.error('manageTask:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   GET /api/roadmaps/:id/stats
   Per-roadmap stats (fixed: now actually uses :id)
   Returns: { success, stats }
══════════════════════════════════════════════════════ */
exports.getRoadmapStats = async (req, res) => {
  if (rejectBadId(req, res)) return;
  try {
    const roadmap = await Roadmap.findById(req.params.id).lean();
    if (!roadmap) {
      return res.status(404).json({ success: false, error: 'Roadmap not found.' });
    }
    if (roadmap.userId !== req.session.user) {
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    }
    const stats = computeStats(roadmap);
    res.json({ success: true, stats });
  } catch (err) {
    console.error('getRoadmapStats:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};

/* ══════════════════════════════════════════════════════
   GET /api/roadmaps/global-stats
   Aggregated stats across ALL roadmaps — uses MongoDB
   aggregation pipeline instead of JS-level iteration.
   Returns: { success, stats }
══════════════════════════════════════════════════════ */
exports.getGlobalStats = async (req, res) => {
  try {
    const [result] = await Roadmap.aggregate([
      { $match: { userId: req.session.user } },
      { $unwind: '$weeks' },
      { $unwind: '$weeks.days' },
      {
        $group: {
          _id:          null,
          totalRoadmaps: { $addToSet: '$_id' },
          completedDays: { $sum: { $cond: ['$weeks.days.completed', 1, 0] } },
          totalPomodoro: { $sum: '$weeks.days.pomodoroCount' },
          totalDays:     { $sum: 1 },
        },
      },
      {
        $project: {
          _id:          0,
          totalRoadmaps: { $size: '$totalRoadmaps' },
          completedDays: 1,
          totalPomodoro: 1,
          totalDays:     1,
        },
      },
    ]);

    const stats = result || { totalRoadmaps: 0, completedDays: 0, totalPomodoro: 0, totalDays: 0 };
    res.json({ success: true, stats });
  } catch (err) {
    console.error('getGlobalStats:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
};
