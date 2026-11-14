const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const session = require('express-session');

const { createDatabase, metrics, participants } = require('./db');
const { analyzeUrl, resolveDestinationIp, inspectRedirectChain } = require('./url-analyzer');
const { inspectInIsolatedBrowser } = require('./browser-sandbox');

function createApp(options = {}) {
  const app = express();
  const databasePath = options.database || process.env.DATABASE || path.join(__dirname, '..', 'instance', 'phishguard.sqlite3');
  // The public lab has no username/password gate. A hidden local owner record
  // remains only because the existing SQLite schema requires created_by.
  const adminUsername = '__local_lab_owner__';
  const adminPassword = crypto.randomBytes(32).toString('hex');
  const db = createDatabase(databasePath, adminUsername, adminPassword);

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, '..', 'public')));
  app.use(session({ secret: options.sessionSecret || process.env.SESSION_SECRET || 'local-awareness-simulator-key', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax' } }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    req.user = db.prepare('SELECT id, username FROM users WHERE username = ?').get(adminUsername);
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    res.locals.user = req.user;
    res.locals.csrfToken = req.session.csrfToken;
    res.locals.urlFor = (name, value) => {
      const routes = { dashboard: '/dashboard', campaigns: '/campaigns', campaignNew: '/campaigns/new', analyzer: '/analyze' };
      return value ? `${routes[name]}/${value}` : routes[name];
    };
    next();
  });

  const requireAuth = (req, res, next) => next();
  const requireCsrf = (req, res, next) => {
    if (req.body.csrf_token === req.session.csrfToken) return next();
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    res.locals.csrfToken = req.session.csrfToken;
    return res.status(400).send('Your form expired. Refresh the page and try again.');
  };
  const campaign = (idOrToken) => db.prepare('SELECT * FROM campaigns WHERE id = ? OR public_token = ?').get(idOrToken, idOrToken);
  const safeCode = (value) => String(value || 'demo-participant').trim().slice(0, 40) || 'demo-participant';

  app.get('/', (req, res) => res.redirect('/dashboard'));

  app.get('/dashboard', requireAuth, (req, res) => {
    const campaigns = db.prepare('SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 6').all();
    const total = db.prepare("SELECT COUNT(*) AS campaigns, SUM(status = 'active') AS active_campaigns FROM campaigns").get();
    res.render('dashboard', { campaigns, totals: { ...total, ...metrics(db) } });
  });
  app.get('/campaigns', requireAuth, (req, res) => res.render('campaigns', { campaigns: db.prepare('SELECT * FROM campaigns ORDER BY created_at DESC').all() }));
  app.get('/campaigns/new', requireAuth, (req, res) => res.render('campaign-new', { form: {}, error: null }));
  app.post('/campaigns/new', requireAuth, requireCsrf, (req, res) => {
    const fields = ['name', 'audience_label', 'subject', 'sender_label', 'lure_text', 'landing_message'];
    const form = Object.fromEntries(fields.map((field) => [field, String(req.body[field] || '').trim()]));
    if (fields.some((field) => !form[field])) return res.status(400).render('campaign-new', { form, error: 'Complete every field before creating the campaign.' });
    const token = crypto.randomBytes(8).toString('hex');
    const result = db.prepare(`INSERT INTO campaigns (name, audience_label, subject, sender_label, lure_text, landing_message, public_token, created_by) VALUES (@name, @audience_label, @subject, @sender_label, @lure_text, @landing_message, @public_token, @created_by)`).run({ ...form, public_token: token, created_by: req.user.id });
    res.redirect(`/campaigns/${result.lastInsertRowid}`);
  });
  app.get('/campaigns/:id', requireAuth, (req, res) => {
    const item = campaign(req.params.id);
    if (!item) return res.sendStatus(404);
    res.render('campaign-detail', { campaign: item, metrics: metrics(db, item.id), participants: participants(db, item.id) });
  });
  app.get('/campaigns/:id/report', requireAuth, (req, res) => {
    const item = campaign(req.params.id);
    if (!item) return res.sendStatus(404);
    res.render('report', { campaign: item, metrics: metrics(db, item.id), participants: participants(db, item.id) });
  });
  app.get('/campaigns/:id/report.csv', requireAuth, (req, res) => {
    const item = campaign(req.params.id);
    if (!item) return res.sendStatus(404);
    const lines = [['Campaign', 'Participant code', 'Clicks', 'Dummy submissions', 'Risk score', 'Risk level', 'Last seen']];
    participants(db, item.id).forEach((row) => lines.push([item.name, row.participant_code, row.clicks, row.submissions, row.risk_score, row.risk_label, row.last_seen]));
    res.type('text/csv').attachment(`${item.name.replace(/[^a-z0-9]+/gi, '_')}_report.csv`).send(lines.map((line) => line.map((cell) => `"${String(cell ?? '').replaceAll('"', '""')}"`).join(',')).join('\n'));
  });

  app.get('/simulate/:token', (req, res) => {
    const item = campaign(req.params.token);
    if (!item) return res.sendStatus(404);
    if (item.status !== 'active') return res.status(410).render('simulation-closed', { campaign: item });
    const participantCode = safeCode(req.query.participant_code);
    db.prepare("INSERT INTO events (campaign_id, participant_code, event_type, risk_score) VALUES (?, ?, 'clicked', 40)").run(item.id, participantCode);
    res.render('landing', { campaign: item, participantCode });
  });
  app.post('/simulate/:token', requireCsrf, (req, res) => {
    const item = campaign(req.params.token);
    if (!item || item.status !== 'active') return res.sendStatus(410);
    const participantCode = safeCode(req.body.participant_code);
    // Do not read, log, or persist dummy_username/dummy_password values.
    db.prepare("INSERT INTO events (campaign_id, participant_code, event_type, risk_score) VALUES (?, ?, 'submitted', 100)").run(item.id, participantCode);
    res.render('simulation-result', { campaign: item, participantCode });
  });
  app.get('/analyze', requireAuth, (req, res) => res.render('analyze', { result: null }));
  app.post('/analyze', requireAuth, requireCsrf, async (req, res) => {
    const result = analyzeUrl(req.body.url);
    if (result.domain) {
      result.destination = await resolveDestinationIp(result.domain);
      result.simulation = await inspectRedirectChain(req.body.url);
      result.browserSimulation = await inspectInIsolatedBrowser(req.body.url);
      if (result.browserSimulation.available && result.browserSimulation.warnings.length) {
        result.reasons.push(...result.browserSimulation.warnings);
        result.classification = 'Likely suspicious';
        result.severity = 'warning';
      }
      if (result.simulation.warnings.length) {
        result.reasons.push(...result.simulation.warnings);
        result.classification = 'Likely suspicious';
        result.severity = 'warning';
      }
    }
    res.render('analyze', { result });
  });

  return app;
}

module.exports = { createApp };
