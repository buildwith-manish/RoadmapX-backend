/**
 * routes/roadmapRoutes.js
 * Mounted at: app.use('/api/roadmaps', router)
 *
 * Route map:
 *   POST   /api/roadmaps/create          → createRoadmap
 *   GET    /api/roadmaps                 → getAllRoadmaps
 *   GET    /api/roadmaps/global-stats    → getGlobalStats  (all roadmaps)
 *   GET    /api/roadmaps/:id             → getRoadmap
 *   PATCH  /api/roadmaps/:id             → updateRoadmap   (title / level / emoji)
 *   DELETE /api/roadmaps/:id             → deleteRoadmap
 *   PUT    /api/roadmaps/:id/day         → updateDay
 *   POST   /api/roadmaps/:id/task        → manageTask
 *   GET    /api/roadmaps/:id/stats       → getRoadmapStats (single roadmap)
 */

const express       = require('express');
const rateLimit     = require('express-rate-limit');
const router        = express.Router();
const ctrl          = require('../controllers/roadmapController');
const { requireAuth } = require('../middleware/auth');

/* ── Rate limiting ──────────────────────────────────────────
   Install: npm install express-rate-limit
   Limits each IP to 60 requests per minute across all routes,
   and 10 creates per minute on the create endpoint.
──────────────────────────────────────────────────────────── */
const globalLimiter = rateLimit({
  windowMs:         60 * 1000,  // 1 minute
  max:              60,
  standardHeaders:  true,
  legacyHeaders:    false,
  message:          { success: false, error: 'Too many requests. Please slow down.' },
});

const createLimiter = rateLimit({
  windowMs:         60 * 1000,  // 1 minute
  max:              10,
  standardHeaders:  true,
  legacyHeaders:    false,
  message:          { success: false, error: 'Too many create requests. Please wait a moment.' },
});

router.use(requireAuth);
router.use(globalLimiter);

/* ── Static routes FIRST (must come before /:id) ─────────── */

// POST /api/roadmaps/create
router.post('/create', createLimiter, ctrl.createRoadmap);

// GET /api/roadmaps
router.get('/', ctrl.getAllRoadmaps);

// GET /api/roadmaps/global-stats  — cross-roadmap dashboard stats
router.get('/global-stats', ctrl.getGlobalStats);

/* ── Dynamic :id routes ─────────────────────────────────── */

// GET /api/roadmaps/:id
router.get('/:id', ctrl.getRoadmap);

// PATCH /api/roadmaps/:id  — update title / level / emoji
router.patch('/:id', ctrl.updateRoadmap);

// DELETE /api/roadmaps/:id
router.delete('/:id', ctrl.deleteRoadmap);

// PUT /api/roadmaps/:id/day
// Body: { dayNum, notes?, completed?, pomodoroCount?, revisionDates? }
router.put('/:id/day', ctrl.updateDay);

// POST /api/roadmaps/:id/task
// Body: { dayNum, action: 'add'|'toggle'|'delete', taskText?, taskId? }
router.post('/:id/task', ctrl.manageTask);

// GET /api/roadmaps/:id/stats  — stats for a single roadmap
router.get('/:id/stats', ctrl.getRoadmapStats);

module.exports = router;
