const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const request = require('supertest');
const { createApp } = require('../src/app');
const { analyzeUrl } = require('../src/url-analyzer');

function makeApp(name) {
  const dbPath = path.join(__dirname, '..', '..', 'work', `phishguard-js-${name}.sqlite3`);
  try { fs.rmSync(dbPath, { force: true }); } catch {}
  return createApp({ database: dbPath, adminPassword: 'TestPassword123!', sessionSecret: 'test-secret' });
}

async function createCampaign(agent) {
  const page = await agent.get('/campaigns/new');
  const token = page.text.match(/name="csrf_token" value="([^"]+)"/)[1];
  return agent.post('/campaigns/new').type('form').send({
    csrf_token: token,
    name: 'Security Awareness Pilot',
    audience_label: 'College Lab A',
    subject: 'Review your training notice',
    sender_label: 'Campus IT Training',
    lure_text: 'This is a controlled awareness exercise.',
    landing_message: 'Use only the dummy values displayed on this page.'
  }).expect(302);
}

test('public lab routes are available without login', async () => {
  const app = makeApp('auth');
  await request(app).get('/dashboard').expect(200);
});

test('campaign and dummy tracking never expose raw password values', async () => {
  const app = makeApp('tracking');
  const agent = request.agent(app);
  const created = await createCampaign(agent);
  const detail = await agent.get(created.headers.location).expect(200);
  const token = detail.text.match(/\/simulate\/([a-f0-9]+)/)[1];
  const landing = await agent.get(`/simulate/${token}?participant_code=student-01`).expect(200);
  const csrfToken = landing.text.match(/name="csrf_token" value="([^"]+)"/)[1];
  const result = await agent.post(`/simulate/${token}`).type('form').send({ csrf_token: csrfToken, participant_code: 'student-01', dummy_username: 'training-user', dummy_password: 'not-a-real-password' }).expect(200);
  assert.match(result.text, /values entered were immediately discarded/);
  const report = await agent.get(`${created.headers.location}/report`).expect(200);
  assert.match(report.text, /student-01/);
  assert.doesNotMatch(report.text, /not-a-real-password/);
});

test('link analyzer is available without network access', async () => {
  const app = makeApp('analyzer');
  const agent = request.agent(app);
  const page = await agent.get('/analyze');
  const csrfToken = page.text.match(/name="csrf_token" value="([^"]+)"/)[1];
  const result = await agent.post('/analyze').type('form').send({ csrf_token: csrfToken, url: 'http://bit.ly/verify-account' }).expect(200);
  assert.match(result.text, /Likely suspicious/);
  assert.match(result.text, /URL-shortening service/);
});

test('analyzer rejects non-http values', () => {
  assert.equal(analyzeUrl('javascript:alert(1)').classification, 'Invalid');
});

test('flags known tracking domains without contacting them', () => {
  const result = analyzeUrl('https://grabify.link/72QD8S');
  assert.equal(result.classification, 'Likely suspicious');
  assert.match(result.reasons.join(' '), /IP-logging services/);
  assert.equal(result.embeddedLinks.length, 0);
  assert.match(result.resolutionNote, /server-side redirect/);
});

test('extracts an encoded underlying link without opening it', () => {
  const result = analyzeUrl('https://example.test/redirect?url=https%3A%2F%2Flogin.example.test%2Fverify');
  assert.deepEqual(result.embeddedLinks, ['https://login.example.test/verify']);
});
