const express = require('express');
const { Pool } = require('pg');
const auth = require('../middleware/auth');
const { professorScope } = require('../middleware/professorScope');


const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

router.get('/', auth(), professorScope, async (req, res) => {
  try {
    const { site } = req.query;
    let query, params;
    if (req.professorCourseIds === null) {
      query = `SELECT p.*, u.first_name || ' ' || u.last_name AS created_by_name
               FROM pages p LEFT JOIN users u ON u.id = p.created_by
               ${site ? 'WHERE p.site = $1' : ''} ORDER BY p.last_modified DESC`;
      params = site ? [site] : [];
    } else if (req.professorCourseIds.length === 0) {
      query = `SELECT p.*, u.first_name || ' ' || u.last_name AS created_by_name
               FROM pages p LEFT JOIN users u ON u.id = p.created_by
               WHERE p.created_by = $1 AND p.course_id IS NULL
               ${site ? 'AND p.site = $2' : ''} ORDER BY p.last_modified DESC`;
      params = site ? [req.user.id, site] : [req.user.id];
    } else {
      query = `SELECT p.*, u.first_name || ' ' || u.last_name AS created_by_name
               FROM pages p LEFT JOIN users u ON u.id = p.created_by
               WHERE (p.course_id = ANY($1::int[]) OR (p.created_by = $2 AND p.course_id IS NULL))
               ${site ? 'AND p.site = $3' : ''} ORDER BY p.last_modified DESC`;
      params = site ? [req.professorCourseIds, req.user.id, site] : [req.professorCourseIds, req.user.id];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('[GET /api/pages]', err);
    res.status(500).json({ error: 'Failed to fetch pages' });
  }
});

router.get('/:id', auth(), professorScope, async (req, res) => {
  try {
    const pageId = parseInt(req.params.id);
    const { rows } = await pool.query('SELECT * FROM pages WHERE id = $1', [pageId]);
    if (!rows.length) return res.status(404).json({ error: 'Page not found' });
    const page = rows[0];
    if (req.professorCourseIds !== null) {
      const ownsCourse = page.course_id && req.professorCourseIds.includes(page.course_id);
      const createdIt  = !page.course_id && page.created_by === req.user.id;
      if (!ownsCourse && !createdIt) return res.status(403).json({ error: 'Access denied' });
    }
    res.json(page);
  } catch (err) {
    console.error('[GET /api/pages/:id]', err);
    res.status(500).json({ error: 'Failed to fetch page' });
  }
});

router.post('/', auth(), async (req, res) => {
  if (req.user.role < 2) return res.status(403).json({ error: 'Forbidden' });
  try {
    const { site, filename, title, content, course_id, created_from_template } = req.body;
    if (req.user.role === 2 && course_id) {
      const { rows: check } = await pool.query(
        'SELECT 1 FROM courses WHERE id = $1 AND faculty_id = $2 LIMIT 1',
        [course_id, req.user.id]
      );
      if (!check.length) return res.status(403).json({ error: 'You do not own that course' });
    }
    const { rows } = await pool.query(
      `INSERT INTO pages (site, filename, title, content, created_by, course_id, created_from_template, last_modified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
      [site, filename, title, content || '', req.user.id, course_id || null, created_from_template || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('[POST /api/pages]', err);
    res.status(500).json({ error: 'Failed to create page' });
  }
});

router.put('/:id', auth(), professorScope, async (req, res) => {
  try {
    const pageId = parseInt(req.params.id);
    const { rows: existing } = await pool.query('SELECT * FROM pages WHERE id = $1', [pageId]);
    if (!existing.length) return res.status(404).json({ error: 'Page not found' });
    const page = existing[0];
    if (req.professorCourseIds !== null) {
      const ownsCourse = page.course_id && req.professorCourseIds.includes(page.course_id);
      const createdIt  = !page.course_id && page.created_by === req.user.id;
      if (!ownsCourse && !createdIt) return res.status(403).json({ error: 'Access denied' });
    }
    const { title, content, filename, site } = req.body;
    const { rows } = await pool.query(
      `UPDATE pages SET title=$1, content=$2, filename=$3, site=$4, last_modified=NOW()
       WHERE id=$5 RETURNING *`,
      [title, content, filename, site, pageId]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('[PUT /api/pages/:id]', err);
    res.status(500).json({ error: 'Failed to update page' });
  }
});

module.exports = router;
