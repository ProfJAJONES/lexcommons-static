const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function professorScope(req, res, next) {
  try {
    if (req.user.role >= 3) {
      req.professorCourseIds = null;
      return next();
    }
    if (req.user.role === 2) {
      const { rows } = await pool.query(
        'SELECT id FROM courses WHERE faculty_id = $1',
        [req.user.id]
      );
      req.professorCourseIds = rows.map(r => r.id);
      return next();
    }
    return res.status(403).json({ error: 'Forbidden' });
  } catch (err) {
    console.error('[professorScope] error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

function scopeClause(courseIds, column, paramOffset = 1) {
  if (courseIds === null) return { clause: '', params: [], offset: paramOffset };
  if (courseIds.length === 0) return { clause: 'AND 1=0', params: [], offset: paramOffset };
  const placeholders = courseIds.map((_, i) => `$${paramOffset + i}`).join(', ');
  return {
    clause: `AND ${column} = ANY(ARRAY[${placeholders}]::int[])`,
    params: courseIds,
    offset: paramOffset + courseIds.length,
  };
}

module.exports = { professorScope, scopeClause };
