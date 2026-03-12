const express = require('express');
const { Pool } = require('pg');
const auth = require('../middleware/auth');
const { professorScope } = require('../middleware/professorScope');


const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

router.get('/', auth(), professorScope, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const type   = req.query.type || null;
    let query, params;
    if (req.professorCourseIds === null) {
      query = `SELECT * FROM activity_log ${type ? 'WHERE type = $1' : ''}
               ORDER BY created_at DESC LIMIT $${type ? 2 : 1} OFFSET $${type ? 3 : 2}`;
      params = type ? [type, limit, offset] : [limit, offset];
    } else if (req.professorCourseIds.length === 0) {
      query = `SELECT * FROM activity_log WHERE user_email = $1
               ${type ? 'AND type = $2' : ''}
               ORDER BY created_at DESC LIMIT $${type ? 3 : 2} OFFSET $${type ? 4 : 3}`;
      params = type ? [req.user.email, type, limit, offset] : [req.user.email, limit, offset];
    } else {
      query = `SELECT al.* FROM activity_log al
               WHERE (al.user_email = $1 OR al.user_email IN (
                 SELECT u.email FROM users u
                 JOIN course_enrollments ce ON ce.student_id = u.id
                 WHERE ce.course_id = ANY($2::int[]) AND u.role = 1
               ))
               ${type ? 'AND al.type = $3' : ''}
               ORDER BY al.created_at DESC LIMIT $${type ? 4 : 3} OFFSET $${type ? 5 : 4}`;
      params = type
        ? [req.user.email, req.professorCourseIds, type, limit, offset]
        : [req.user.email, req.professorCourseIds, limit, offset];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('[GET /api/activity-log]', err);
    res.status(500).json({ error: 'Failed to fetch activity log' });
  }
});

module.exports = router;
