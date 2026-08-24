'use strict';
// buildbar-deploy: eigenstaendiger Desktop-Deploy-Dienst, ISOLIERT vom mcp-hub.
// Zweck: Desktop-Teilnehmende (Claude Code Desktop) veroeffentlichen ihr Frontend
// account-frei auf der buildbar-Coolify-Infra, aus einem PRIVATEN GitHub-Repo.
//
// Ablauf (2 Schritte, beide gegen NRW_GATE_PASSWORD gegatet):
//   1) POST /prepare {repo, password}
//        -> erzeugt ein ed25519-Schluesselpaar, registriert den PRIVATE Key in
//           Coolify (bleibt server-seitig), gibt nur den PUBLIC Key + deployId zurueck.
//      Der Client haengt den Public Key als read-only Deploy-Key ans private Repo
//      (mit dem lokalen `gh` des Teilnehmers -> kein GitHub-Schreibrecht fuer uns).
//   2) POST /publish {deployId, base_dir, env, password}
//        -> legt eine Coolify-App aus dem privaten Repo an (app-<id>.buildbar.at),
//           setzt Build-Env, startet den Build.
//
// Der Coolify-API-Token bleibt ENV dieses Dienstes; Private Keys verlassen ihn nie.
// Dieser Dienst fasst weder mcp-hub noch andere Dienste an.

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const PORT = parseInt(process.env.PORT || '80', 10);
const DATA_FILE = process.env.DATA_FILE || '/data/deploys.json';
const GATE_PW = process.env.NRW_GATE_PASSWORD || '';
const COOLIFY_TOKEN = process.env.COOLIFY_TOKEN || '';
const COOLIFY_API = process.env.COOLIFY_API || 'http://coolify:8080/api/v1';
const COOLIFY_PROJECT = process.env.COOLIFY_PROJECT || '';
const COOLIFY_SERVER = process.env.COOLIFY_SERVER || '';
const DEPLOY_DOMAIN_BASE = process.env.DEPLOY_DOMAIN_BASE || 'buildbar.at';

const cf = (p, opts = {}) =>
  fetch(COOLIFY_API + p, {
    ...opts,
    headers: {
      Authorization: 'Bearer ' + COOLIFY_TOKEN,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(opts.headers || {}),
    },
  });

// deployId -> { repo, keyUuid, appUuid?, appDomain?, baseDir? }
const store = new Map();
try {
  if (fs.existsSync(DATA_FILE)) {
    const o = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const [k, v] of Object.entries(o)) store.set(k, v);
    console.log('loaded', store.size, 'deploys');
  }
} catch (e) { console.error('load failed:', e.message); }
function persist() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(Object.fromEntries(store)));
  } catch (e) { /* kein Volume -> nur In-Memory */ }
}

// Konstantzeit-Passwortpruefung (null = nicht konfiguriert)
function pwOk(given) {
  if (!GATE_PW) return null;
  const a = crypto.createHash('sha256').update(String(given == null ? '' : given)).digest();
  const b = crypto.createHash('sha256').update(GATE_PW).digest();
  return crypto.timingSafeEqual(a, b);
}

// einfaches In-Memory-Rate-Limit
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const e = hits.get(ip);
  const w = e && now - e.t < 5 * 60000;
  if (w && e.n >= 10) return true;
  hits.set(ip, { n: (w ? e.n : 0) + 1, t: w ? e.t : now });
  return false;
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
}
function repoOk(repo) {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo || '');
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

app.get('/healthz', (req, res) => res.type('text').send('ok'));
app.get('/', (req, res) =>
  res.type('text').send('buildbar-deploy: POST /prepare dann /publish (Event-Passwort noetig).'));

function gate(req, res, next) {
  if (limited(clientIp(req))) return res.status(429).json({ error: 'zu viele Versuche' });
  const ok = pwOk(req.body && req.body.password);
  if (ok === null) return res.status(503).json({ error: 'Deploy-Dienst noch nicht konfiguriert' });
  if (!ok) return res.status(401).json({ error: 'falsches Passwort' });
  next();
}

// 1) Schluesselpaar erzeugen, Private Key in Coolify, Public Key zurueck
app.post('/prepare', gate, async (req, res) => {
  const repo = String((req.body && req.body.repo) || '').trim();
  if (!repoOk(repo)) return res.status(400).json({ error: 'repo muss die Form owner/name haben' });
  if (!COOLIFY_TOKEN) return res.status(503).json({ error: 'Coolify nicht konfiguriert' });
  try {
    const deployId = crypto.randomBytes(9).toString('hex');
    const kp = '/tmp/dk-' + deployId;
    cp.execSync("ssh-keygen -t ed25519 -N '' -q -f " + kp + ' -C buildbar-deploy-' + deployId);
    const pub = fs.readFileSync(kp + '.pub', 'utf8').trim();
    const priv = fs.readFileSync(kp, 'utf8');
    try { fs.unlinkSync(kp); fs.unlinkSync(kp + '.pub'); } catch (e) {}
    const kr = await cf('/security/keys', {
      method: 'POST',
      body: JSON.stringify({ name: 'desktop-' + deployId, private_key: priv }),
    });
    const kj = await kr.json().catch(() => ({}));
    if (!kj || !kj.uuid) return res.status(502).json({ error: 'Key-Registrierung fehlgeschlagen' });
    store.set(deployId, { repo, keyUuid: kj.uuid });
    persist();
    res.json({
      deployId,
      public_key: pub,
      hint: 'Public Key als read-only Deploy-Key ans PRIVATE Repo haengen, dann /publish aufrufen.',
    });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// 2) App anlegen (oder redeploy) + Env + Build
app.post('/publish', gate, async (req, res) => {
  const deployId = String((req.body && req.body.deployId) || '').trim();
  // Coolify: Wurzel = leerer String (nicht "/"); Subdir = "/name".
  let baseDir = String((req.body && req.body.base_dir) || '').trim();
  if (baseDir === '/') baseDir = '';
  else if (baseDir && baseDir[0] !== '/') baseDir = '/' + baseDir;
  const rec = store.get(deployId);
  if (!rec) return res.status(404).json({ error: 'unbekannte deployId (erst /prepare aufrufen)' });
  try {
    if (!rec.appUuid) {
      const sub = 'app-' + deployId.slice(0, 8);
      const domain = 'https://' + sub + '.' + DEPLOY_DOMAIN_BASE;
      const cr = await cf('/applications/private-deploy-key', {
        method: 'POST',
        body: JSON.stringify({
          project_uuid: COOLIFY_PROJECT,
          server_uuid: COOLIFY_SERVER,
          environment_name: 'production',
          git_repository: 'git@github.com:' + rec.repo + '.git',
          git_branch: 'main',
          private_key_uuid: rec.keyUuid,
          build_pack: 'nixpacks',
          ports_exposes: '3000',
          base_directory: baseDir,
          name: sub,
          instant_deploy: false,
        }),
      });
      const created = await cr.json().catch(() => ({}));
      if (!created || !created.uuid)
        return res.status(502).json({ error: 'App-Erstellung fehlgeschlagen', detail: created });
      rec.appUuid = created.uuid;
      rec.appDomain = domain;
      rec.baseDir = baseDir;
      await cf('/applications/' + rec.appUuid, {
        method: 'PATCH',
        body: JSON.stringify({ domains: domain }),
      });
      const envRaw = String((req.body && req.body.env) || '');
      for (const line of envRaw.split(/\r?\n/)) {
        const i = line.indexOf('=');
        if (i < 1) continue;
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (!k) continue;
        try {
          await cf('/applications/' + rec.appUuid + '/envs', {
            method: 'POST',
            body: JSON.stringify({ key: k, value: v, is_preview: false, is_build_time: true }),
          });
        } catch (e) {}
      }
      store.set(deployId, rec);
      persist();
    }
    await cf('/deploy?uuid=' + rec.appUuid + '&force=false', { method: 'POST' });
    res.json({ url: rec.appDomain, app: rec.appUuid, status: 'deploying', hint: 'Erster Build dauert einige Minuten.' });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

app.listen(PORT, () => console.log('buildbar-deploy on :' + PORT));
