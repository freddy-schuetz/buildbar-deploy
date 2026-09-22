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
//   3) POST /update {repo | deployId, password}
//        -> baut die BESTEHENDE App neu, gleiche Adresse. Findet die App am Repo-Namen,
//           damit Aenderungen auch in einer neuen Sitzung ohne deployId rausgehen.
//           Optional liefern /publish und /update die fertige Zeile, mit der ein
//           GitHub-Webhook eingerichtet wird: danach veroeffentlicht jeder Push selbst.
//   4) POST /status {repo | deployId, password}
//        -> Ausgang des letzten Builds samt Fehlerzeilen. Ohne das raet der Assistent
//           bei einem 503 ins Blaue, denn das Protokoll liegt nur in Coolify.
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
// Oeffentliche Coolify-Adresse fuer GitHub-Webhooks (z.B. http://1.2.3.4:8000).
// Leer = kein Webhook-Angebot, der Update-Weg ueber /update bleibt davon unberuehrt.
const COOLIFY_WEBHOOK_BASE = process.env.COOLIFY_WEBHOOK_BASE || '';

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
  // Grosszuegig: beim Event sitzen alle hinter derselben IP (Hot-Patch vom 01.09. nach git uebernommen)
  if (w && e.n >= 300) return true;
  hits.set(ip, { n: (w ? e.n : 0) + 1, t: w ? e.t : now });
  return false;
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
}
function repoOk(repo) {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo || '');
}

// Juengste bereits veroeffentlichte App zu einem Repo finden (Map behaelt die Einfuegereihenfolge).
function findByRepo(repo) {
  let treffer = null;
  for (const [deployId, rec] of store) {
    if (rec.repo === repo && rec.appUuid) treffer = { deployId, rec };
  }
  return treffer;
}

// Fertige Anleitung fuer den GitHub-Webhook: danach veroeffentlicht jeder Push von selbst.
// Das Geheimnis gehoert zur App und erlaubt nur eines: einen Build dieser App anzustossen.
async function webhookInfo(rec) {
  if (!COOLIFY_WEBHOOK_BASE || !rec || !rec.appUuid) return null;
  try {
    const r = await cf('/applications/' + rec.appUuid);
    const j = await r.json().catch(() => ({}));
    const secret = j && j.manual_webhook_secret_github;
    if (!secret) return null;
    const url = COOLIFY_WEBHOOK_BASE.replace(/\/+$/, '') + '/webhooks/source/github/events/manual';
    return {
      url,
      secret,
      einmal_ausfuehren:
        'gh api repos/' + rec.repo + '/hooks -X POST -f name=web -F active=true -f "events[]=push"' +
        ' -f "config[url]=' + url + '" -f "config[content_type]=json" -f "config[secret]=' + secret + '"',
      hinweis: 'Einmal im Repo einrichten, danach loest jeder Push auf main die Veroeffentlichung aus.',
    };
  } catch (e) {
    return null;
  }
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

app.get('/healthz', (req, res) => res.type('text').send('ok'));
app.get('/', (req, res) =>
  res.type('text').send('buildbar-deploy: POST /prepare, dann /publish. Aenderungen: POST /update {repo, password}. Ausgang: POST /status. Event-Passwort noetig.'));

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
  // Gibt es zu diesem Repo schon eine Veroeffentlichung, ist ein neuer Schluessel fast nie gewollt:
  // ein zweites /publish legt eine ZWEITE App unter NEUER Adresse an, waehrend die alte weiterlaeuft.
  const schon = findByRepo(repo);
  if (schon && !(req.body && req.body.force)) {
    return res.json({
      existing: true,
      deployId: schon.deployId,
      url: schon.rec.appDomain,
      base_dir: schon.rec.baseDir || '',
      hinweis:
        'Fuer dieses Repo gibt es die Adresse schon. Aenderungen veroeffentlichen: POST /update {repo, password} ' +
        '- die Adresse bleibt dieselbe. Nur wenn bewusst eine ZWEITE, eigene Adresse gewuenscht ist: force=true mitschicken.',
      webhook: await webhookInfo(schon.rec),
    });
  }
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
  let envFailed = [];
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
      // ENV per Bulk-Upsert setzen. Frueher: Einzel-POST mit is_build_time -> Coolify 4.3.10
      // antwortete 422, der Fehler wurde verschluckt und jede Variable ging lautlos verloren.
      // Ohne das Feld gilt die Variable fuer Build UND Laufzeit.
      const envRaw = String((req.body && req.body.env) || '');
      const envData = [];
      for (const line of envRaw.split(/\r?\n/)) {
        const i = line.indexOf('=');
        if (i < 1) continue;
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (!k) continue;
        envData.push({ key: k, value: v, is_preview: false });
      }
      if (envData.length) {
        try {
          const er = await cf('/applications/' + rec.appUuid + '/envs/bulk', {
            method: 'PATCH',
            body: JSON.stringify({ data: envData }),
          });
          if (!er.ok) envFailed = envData.map((d) => d.key + ' (HTTP ' + er.status + ')');
        } catch (e) {
          envFailed = envData.map((d) => d.key);
        }
      }
      store.set(deployId, rec);
      persist();
    }
    await deployAnstossen(rec, deployId);
    const out = { url: rec.appDomain, app: rec.appUuid, deployId, status: 'deploying', hint: 'Erster Build dauert einige Minuten.' };
    out.update = 'Spaetere Aenderungen: erst pushen, dann POST /update {repo, password}. Die Adresse bleibt dieselbe. '
      + 'Ging etwas schief: POST /status {repo, password} zeigt Ausgang und Fehlerzeilen des letzten Builds.';
    out.webhook = await webhookInfo(rec);
    if (envFailed.length) {
      out.env_failed = envFailed;
      out.warning = 'Diese Umgebungsvariablen konnten nicht gesetzt werden. Die App startet ohne sie.';
    }
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// Merkt sich den zuletzt angestossenen Build, damit /status ihn nachschlagen kann.
async function deployAnstossen(rec, deployId) {
  const dr = await cf('/deploy?uuid=' + rec.appUuid + '&force=false', { method: 'POST' });
  const dj = await dr.json().catch(() => ({}));
  const du = dj && dj.deployments && dj.deployments[0] && dj.deployments[0].deployment_uuid;
  if (du) {
    rec.lastDeployment = du;
    store.set(deployId, rec);
    persist();
  }
  return { ok: dr.ok, status: dr.status, deploymentUuid: du || null };
}

// 4) Wie ist der letzte Build ausgegangen? Ohne diese Auskunft raet der Assistent
// bei einem 503 ins Blaue - das Protokoll liegt sonst nur in Coolify.
app.post('/status', gate, async (req, res) => {
  const deployId = String((req.body && req.body.deployId) || '').trim();
  const repo = String((req.body && req.body.repo) || '').trim();
  let rec = deployId ? store.get(deployId) : null;
  if (!rec || !rec.appUuid) {
    const treffer = repoOk(repo) ? findByRepo(repo) : null;
    if (!treffer) return res.status(404).json({ error: 'Keine Veroeffentlichung zu repo/deployId gefunden.' });
    rec = treffer.rec;
  }
  if (!rec.lastDeployment) {
    return res.json({ url: rec.appDomain, app: rec.appUuid, status: 'unbekannt',
      hinweis: 'Zu dieser App ist hier kein Build vermerkt. Nach dem naechsten /update steht er hier.' });
  }
  try {
    const r = await cf('/deployments/' + rec.lastDeployment);
    const j = await r.json().catch(() => ({}));
    let zeilen = [];
    try {
      zeilen = JSON.parse(j.logs || '[]')
        .map((e) => String(e.output || '').replace(/\s+$/, ''))
        .filter(Boolean);
    } catch (e) { zeilen = []; }
    // Nur bei echtem Fehlschlag: auch erfolgreiche Builds enthalten harmlose Zeilen
    // wie "No such container" aus dem Aufraeumen, die sonst falschen Alarm ausloesen.
    const fehler =
      j.status === 'failed'
        ? zeilen.filter((z) => /error|failed|not a directory|exit code/i.test(z)).slice(-8)
        : [];
    res.json({
      url: rec.appDomain,
      app: rec.appUuid,
      status: j.status || 'unbekannt',
      commit: (j.commit || '').slice(0, 7),
      fertig: j.finished_at || null,
      fehlerzeilen: fehler.map((z) => z.slice(0, 300)),
      letzte_zeilen: zeilen.slice(-20).map((z) => z.slice(0, 300)),
    });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// 3) Aenderungen veroeffentlichen: baut die BESTEHENDE App neu, gleiche Adresse.
// Findet die App am Repo-Namen, damit es auch in einer neuen Sitzung ohne deployId geht.
app.post('/update', gate, async (req, res) => {
  const deployId = String((req.body && req.body.deployId) || '').trim();
  const repo = String((req.body && req.body.repo) || '').trim();
  let id = deployId;
  let rec = id ? store.get(id) : null;
  if (!rec || !rec.appUuid) {
    if (!repoOk(repo)) {
      return res.status(400).json({ error: 'repo (owner/name) oder eine bekannte deployId noetig' });
    }
    const treffer = findByRepo(repo);
    if (!treffer) {
      return res.status(404).json({
        error: 'Zu diesem Repo gibt es noch keine Veroeffentlichung.',
        hinweis: 'Erst POST /prepare, Deploy-Key setzen, dann POST /publish.',
      });
    }
    id = treffer.deployId;
    rec = treffer.rec;
  }
  try {
    const an = await deployAnstossen(rec, id);
    if (!an.ok) {
      return res.status(502).json({ error: 'Coolify hat den Build abgelehnt (HTTP ' + an.status + ')' });
    }
    res.json({
      url: rec.appDomain,
      app: rec.appUuid,
      deployId: id,
      status: 'deploying',
      hint: 'Der Build laeuft. Nach ein bis drei Minuten antwortet die Adresse mit dem neuen Stand.',
      webhook: await webhookInfo(rec),
    });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

app.listen(PORT, () => console.log('buildbar-deploy on :' + PORT));
