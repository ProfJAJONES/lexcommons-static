// LexCommons — Course Templates Routes
// Audited: 2026-03-12
// Fixes: req.user.id vs userId normalization, fork missing created_by/last_modified/course_id

const express = require('express');
const router  = express.Router();
const auth    = require('../middleware/auth');
const pool    = require('../database');

// Normalize user id across password auth (userId) and SSO (id) JWTs
const uid = (req) => req.user.id || req.user.userId;

// GET /api/templates — all templates, grouped by category
router.get('/', auth(2), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, title, description, category, content, created_by, created_at FROM course_templates ORDER BY category ASC, title ASC'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/templates/:id
router.get('/:id', auth(2), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM course_templates WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Template not found' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/templates — create a new template
router.post('/', auth(2), async (req, res) => {
  const { title, description, category, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO course_templates (title, description, category, content, created_by, created_at) VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *',
      [title, description || '', category || 'General', content, uid(req)]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/templates/:id/fork — create a page from a template
// Body: { title, site, filename, course_id? }
router.post('/:id/fork', auth(2), async (req, res) => {
  const { title, site, filename, course_id } = req.body;
  if (!title || !site || !filename) return res.status(400).json({ error: 'title, site, filename required' });
  try {
    const { rows: tRows } = await pool.query('SELECT * FROM course_templates WHERE id = $1', [req.params.id]);
    if (!tRows.length) return res.status(404).json({ error: 'Template not found' });

    // Faculty: verify they own the course_id if provided
    if (req.user.role === 2 && course_id) {
      const { rows: check } = await pool.query(
        'SELECT 1 FROM courses WHERE id = $1 AND faculty_id = $2 LIMIT 1',
        [course_id, uid(req)]
      );
      if (!check.length) return res.status(403).json({ error: 'You do not own that course' });
    }

    const { rows } = await pool.query(
      `INSERT INTO pages (site, filename, title, content, created_by, course_id, created_from_template, last_modified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
       ON CONFLICT (site, filename) DO NOTHING
       RETURNING *`,
      [site, filename, title, tRows[0].content, uid(req), course_id || null, tRows[0].id]
    );
    if (!rows.length) return res.status(409).json({ error: 'A page with that filename already exists' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/templates/:id — update a template (owner or admin only)
router.put('/:id', auth(2), async (req, res) => {
  const { title, description, category, content } = req.body;
  try {
    const { rows: ex } = await pool.query('SELECT * FROM course_templates WHERE id = $1', [req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Template not found' });
    if (ex[0].created_by !== uid(req) && req.user.role < 4) return res.status(403).json({ error: 'Not authorized' });
    const { rows } = await pool.query(
      'UPDATE course_templates SET title=$1,description=$2,category=$3,content=$4,updated_at=NOW() WHERE id=$5 RETURNING *',
      [title || ex[0].title, description ?? ex[0].description, category || ex[0].category, content || ex[0].content, req.params.id]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/templates/:id — admin only
router.delete('/:id', auth(4), async (req, res) => {
  try {
    await pool.query('DELETE FROM course_templates WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
