/**
 * middleware/auth.js
 * Shared authentication middleware for RoadmapX.
 * Imported by any route file that requires a valid session.
 */

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, message: 'Not logged in.' });
}

module.exports = { requireAuth };
