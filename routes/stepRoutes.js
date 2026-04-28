const express                              = require('express');
const router                               = express.Router();
const { addStep, getSteps, completeStep }  = require('../controllers/stepController');
const { requireAuth }                      = require('../middleware/auth');

// Protect all step routes — must be logged in
router.use(requireAuth);

// POST   /api/steps              → add a step to a roadmap
router.post('/',            addStep);

// GET    /api/steps/:roadmapId   → get all steps for a roadmap
router.get('/:roadmapId',   getSteps);

// PUT    /api/steps/:id          → mark a step complete
router.put('/:id',          completeStep);

module.exports = router;
