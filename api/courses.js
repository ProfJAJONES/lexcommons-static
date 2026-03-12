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
      query = `SELECT c.*, u.first_name || ' ' || u.last_name AS faculty_name
               FROM courses c LEFT JOIN users u ON u.id = c.faculty_id
               ORDER BY c.created_at DESC`;
      params = [];
    } else if (req.professorCourseIds.length === 0) {
      return res.json([]);
    } else {
      query = `SELECT c.*, u.first_name || ' ' || u.last_name AS faculty_name
               FROM courses c LEFT JOIN users u ON u.id = c.faculty_id
               WHERE c.faculty_id = $1 ORDER BY c.created_at DESC`;
      params = [req.user.id];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('[GET /api/courses]', err);
    res.status(500).json({ error: 'Failed to fetch courses' });
  }
});

router.get('/:id', auth(), professorScope, async (req, res) => {
  try {
    const courseId = parseInt(req.params.id);
    if (req.professorCourseIds !== null && !req.professorCourseIds.includes(courseId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const { rows } = await pool.query(
      `SELECT c.*, u.first_name || ' ' || u.last_name AS faculty_name
       FROM courses c LEFT JOIN users u ON u.id = c.faculty_id WHERE c.id = $1`,
      [courseId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Course not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('[GET /api/courses/:id]', err);
    res.status(500).json({ error: 'Failed to fetch course' });
  }
});

router.post('/', auth(), async (req, res) => {
  if (req.user.role < 2) return res.status(403).json({ error: 'Forbidden' });
  try {
    const { title, description, term, site } = req.body;
    const facultyId = req.user.role >= 3 && req.body.faculty_id ? req.body.faculty_id : req.user.id;
    const { rows } = await pool.query(
      `INSERT INTO courses (title, description, term, site, faculty_id, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [title, description || null, term || null, site || null, facultyId]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('[POST /api/courses]', err);
    res.status(500).json({ error: 'Failed to create course' });
  }
});

router.put('/:id', auth(), professorScope, async (req, res) => {
  try {
    const courseId = parseInt(req.params.id);
    if (req.professorCourseIds !== null && !req.professorCourseIds.includes(courseId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const { title, description, term, site } = req.body;
    const { rows } = await pool.query(
      `UPDATE courses SET title=$1, description=$2, term=$3, site=$4 WHERE id=$5 RETURNING *`,
      [title, description || null, term || null, site || null, courseId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Course not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('[PUT /api/courses/:id]', err);
    res.status(500).json({ error: 'Failed to update course' });
  }
});

module.exports = router;
