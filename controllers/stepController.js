const Step    = require('../models/Step');
const Roadmap = require('../models/Roadmap');

// ─────────────────────────────────────────────────────────────
// POST /api/steps
// Add a new step to an existing roadmap.
// Body: { roadmapId, title, description? }
// ─────────────────────────────────────────────────────────────
const addStep = async (req, res) => {
  try {
    const { roadmapId, title, description } = req.body;

    if (!roadmapId || !title) {
      return res.status(400).json({
        success: false,
        message: 'roadmapId and title are required.',
      });
    }

    // Verify the parent roadmap actually exists
    const roadmap = await Roadmap.findById(roadmapId);
    if (!roadmap) {
      return res.status(404).json({
        success: false,
        message: 'Roadmap not found.',
      });
    }

    const step = await Step.create({ roadmapId, title, description });

    return res.status(201).json({
      success: true,
      data: step,
    });
  } catch (err) {
    console.error('[stepController] addStep -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not add step.',
    });
  }
};

// ─────────────────────────────────────────────────────────────
// GET /api/steps/:roadmapId
// Return all steps for a given roadmap, in insertion order.
// ─────────────────────────────────────────────────────────────
const getSteps = async (req, res) => {
  try {
    const { roadmapId } = req.params;

    // Verify parent roadmap exists before querying steps
    const roadmap = await Roadmap.findById(roadmapId);
    if (!roadmap) {
      return res.status(404).json({
        success: false,
        message: 'Roadmap not found.',
      });
    }

    const steps = await Step.find({ roadmapId }).sort({ _id: 1 });

    return res.status(200).json({
      success: true,
      data: steps,
    });
  } catch (err) {
    console.error('[stepController] getSteps -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not fetch steps.',
    });
  }
};

// ─────────────────────────────────────────────────────────────
// PUT /api/steps/:id
// Mark a step as complete.
// Sets completed = true and completedAt = now.
// ─────────────────────────────────────────────────────────────
const completeStep = async (req, res) => {
  try {
    const step = await Step.findByIdAndUpdate(
      req.params.id,
      {
        completed:   true,
        completedAt: new Date(),
      },
      { new: true }   // return the updated document
    );

    if (!step) {
      return res.status(404).json({
        success: false,
        message: 'Step not found.',
      });
    }

    return res.status(200).json({
      success: true,
      data: step,
    });
  } catch (err) {
    console.error('[stepController] completeStep -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not update step.',
    });
  }
};

module.exports = { addStep, getSteps, completeStep };
