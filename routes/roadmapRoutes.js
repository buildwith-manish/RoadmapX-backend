const express     = require('express');
const router      = express.Router();
const UserRoadmap = require('../models/UserRoadmap');

// ─────────────────────────────────────────────────────────────
// POST /api/roadmaps
// Create a new roadmap for the authenticated user.
// Body: { userId, title, description? }
// ─────────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const { userId, title, description } = req.body;

    if (!userId || !title) {
      return res.status(400).json({
        success: false,
        message: 'userId and title are required.',
      });
    }

    const roadmap = await UserRoadmap.create({ userId, title, description });

    return res.status(201).json({
      success: true,
      data: roadmap,
    });
  } catch (err) {
    console.error('[roadmapRoutes] POST /api/roadmaps -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not create roadmap.',
    });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/roadmaps?userId=<id>
// Return all roadmaps belonging to the given user,
// sorted newest first.
// ─────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'userId query parameter is required.',
      });
    }

    const roadmaps = await UserRoadmap.find({ userId }).sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      data: roadmaps,
    });
  } catch (err) {
    console.error('[roadmapRoutes] GET /api/roadmaps -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not fetch roadmaps.',
    });
  }
});

// ─────────────────────────────────────────────────────────────
// DELETE /api/roadmaps/:id
// Delete a roadmap by its MongoDB _id.
// ─────────────────────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    const roadmap = await UserRoadmap.findByIdAndDelete(req.params.id);

    if (!roadmap) {
      return res.status(404).json({
        success: false,
        message: 'Roadmap not found.',
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Roadmap deleted successfully.',
    });
  } catch (err) {
    console.error('[roadmapRoutes] DELETE /api/roadmaps/:id -', err.message);
    return res.status(500).json({
      success: false,
      message: 'Server error. Could not delete roadmap.',
    });
  }
});

module.exports = router;
