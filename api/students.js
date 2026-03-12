const express = require('express');
const { Pool } = require('pg');
const auth = require('../middleware/auth');
const { professorScope } = require('../middleware/professorScope');


const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

router.get('/', auth(), professorScope, async (req, res) => {
  try {
    let query, params;
    if (req.professorCourseIds === null) {
      query = `SELECT id, first_name, last_name, email, active, created_at
               FROM users WHERE role = 1 ORDER BY last_name, first_name`;
      params = [];
    } else if (req.professorCourseIds.length === 0) {
      return res.json([]);
    } else {
      query = `SELECT DISTINCT u.id, u.first_name, u.last_name, u.email, u.active, u.created_at
               FROM users u JOIN course_enrollments ce ON ce.student_id = u.id
               WHERE u.role = 1 AND ce.course_id = ANY($1::int[])
               ORDER BY u.last_name, u.first_name`;
      params = [req.professorCourseIds];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('[GET /api/students]', err);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

router.get('/by-course/:courseId', auth(), professorScope, async (req, res) => {
  try {
    const courseId = parseInt(req.params.courseId);
    if (req.professorCourseIds !== null && !req.professorCourseIds.includes(courseId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const { rows } = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.email, u.active, ce.enrolled_at
       FROM users u JOIN course_enrollments ce ON ce.student_id = u.id
       WHERE ce.course_id = $1 AND u.role = 1
       ORDER BY u.last_name, u.first_name`,
      [courseId]
    );
    res.json(rows);
  } catch (err) {
    console.error('[GET /api/students/by-course/:courseId]', err);
    res.status(500).json({ error: 'Failed to fetch students for course' });
  }
});

router.get('/:id', auth(), professorScope, async (req, res) => {
  try {
    const studentId = parseInt(req.params.id);
    if (req.professorCourseIds !== null) {
      if (req.professorCourseIds.length === 0) return res.status(403).json({ error: 'Access denied' });
      const { rows: check } = await pool.query(
        `SELECT 1 FROM course_enrollments WHERE student_id = $1 AND course_id = ANY($2::int[]) LIMIT 1`,
        [studentId, req.professorCourseIds]
      );
      if (!check.length) return res.status(403).json({ error: 'Access denied' });
    }
    const { rows } = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.email, u.active, u.created_at,
              json_agg(json_build_object('course_id', ce.course_id, 'enrolled_at', ce.enrolled_at)) AS enrollments
       FROM users u LEFT JOIN course_enrollments ce ON ce.student_id = u.id
       WHERE u.id = $1 AND u.role = 1 GROUP BY u.id`,
      [studentId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('[GET /api/students/:id]', err);
    res.status(500).json({ error: 'Failed to fetch student' });
  }
});

module.exports = router;
