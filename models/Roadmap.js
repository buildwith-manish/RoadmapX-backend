const mongoose = require('mongoose');

/* ── Task sub-schema ── */
const TaskSchema = new mongoose.Schema({
  id:   { type: String, required: true },
  text: { type: String, required: true, trim: true, maxlength: 200 },
  done: { type: Boolean, default: false },
}, { _id: false });

/* ── Day sub-schema ── */
const DaySchema = new mongoose.Schema({
  day:           { type: Number, required: true },          // global day number (1-based)
  notes:         { type: String, default: '', maxlength: 2000 },
  tasks:         { type: [TaskSchema], default: [] },
  completed:     { type: Boolean, default: false },
  pomodoroCount: { type: Number, default: 0, min: 0, max: 200 },
  revisionDates: { type: [String], default: [] },           // validated as 'YYYY-MM-DD' in controller
}, { _id: false });

/* ── Week sub-schema ── */
const WeekSchema = new mongoose.Schema({
  week: { type: Number, required: true },
  days: { type: [DaySchema], default: [] },
}, { _id: false });

/* ── Roadmap root schema ── */
const RoadmapSchema = new mongoose.Schema({
  userId:   {
    type:     String,
    required: true,
    index:    true,
  },
  title:    { type: String, required: true, trim: true, maxlength: 100 },
  level:    {
    type:    String,
    enum:    { values: ['Beginner', 'Intermediate', 'Advanced'], message: 'Invalid level.' },
    default: null,
  },
  emoji:    { type: String, default: '📚' },
  weeks:    { type: [WeekSchema], default: [] },
}, {
  versionKey: false,
  timestamps: true,   // adds createdAt + updatedAt automatically and keeps them in sync
});

/*
 * Virtual: numWeeks
 * Replaces the old stored `numWeeks` field to avoid it drifting
 * out of sync with the actual weeks array length.
 * Use { virtuals: true } when calling .toJSON() or .toObject() if needed.
 */
RoadmapSchema.virtual('numWeeks').get(function () {
  return this.weeks.length;
});

/* ── Indexes ── */
RoadmapSchema.index({ userId: 1, createdAt: -1 });         // fast per-user listing

module.exports = mongoose.model('Roadmap', RoadmapSchema);
