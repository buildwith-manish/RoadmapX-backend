const mongoose = require('mongoose');

// Named "UserRoadmap" to avoid colliding with the legacy
// "Roadmap" model already defined in server.js.
const userRoadmapSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    default: '',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('UserRoadmap', userRoadmapSchema);
