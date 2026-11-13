const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const BOTS_DIR = path.join(DATA, 'bots');
const DB_FILE = path.join(DATA, 'db.json');
const MAX_BOTS_PER_USER = 3;
const MAX_LOG_LINES = 300;

fs.mkdirSync(BOTS_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA, 'tmp'), { recursive: true });

// ---------- "מסד נתונים" פשוט בקובץ JSON ----------
let db = { secret: crypto.randomBytes(32).toString('hex'), users: [], bots: [] };
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
save();

// ---------- הגדרות סוגי בוטים ----------
const RUNTIMES = {
  node:   { install: 'npm install --omit=dev --no-audit --no-fund', start: 'node index.js' },
  python: { install: 'pip install -r requirements.txt', start: 'python main.py' },
};

// ---------- ניהול תהליכים (הלב של ה-24/7) ----------
const procs = {}; // botId -> { child, logs, timer }

function log(id, text) {
  const p = (procs[id] = procs[id] || { logs: [] });
  text.toString().split('\n').filter(Boolean).forEach(l => p.logs.push(`[${new Date().toLocaleTimeString('he-IL')}] ${l}`));
  if (p.logs.length > MAX_LOG_LINES) p.logs.splice(0, p.logs.length - MAX_LOG_LINES);
}

function isRunning(id) { return !!(procs[id] && procs[id].child); }

function startBot(bot) {
  if (isRunning(bot.id)) return;
  const dir = path.join(BOTS_DIR, bot.id);
  const rt = RUNTIMES[bot.runtime];
  const cmd = fs.existsSync(path.join(dir, bot.runtime === 'node' ? 'package.json' : 'requirements.txt'))
    ? `${rt.install} && ${bot.startCmd}` : bot.startCmd;
  procs[bot.id] = procs[bot.id] || { logs: [] };
  log(bot.id, `▶ מפעיל: ${bot.startCmd}`);
  const child = spawn('sh', ['-c', cmd], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: dir, BOT_TOKEN: bot.token, TOKEN: bot.token, DISCORD_TOKEN: bot.token },
  });
  procs[bot.id].child = child;
  child.stdout.on('data', d => log(bot.id, d));
  child.stderr.on('data', d => log(bot.id, d));
  child.on('exit', code => {
    procs[bot.id].child = null;
    log(bot.id, `■ התהליך נעצר (קוד ${code})`);
    const current = db.bots.find(b => b.id === bot.id);
    if (current && current.desired === 'running') {   // קרס? מרימים מחדש אחרי 5 שניות
      log(bot.id, '↻ הפעלה מחדש אוטומטית בעוד 5 שניות...');
      procs[bot.id].timer = setTimeout(() => startBot(current), 5000);
    }
  });
}

function stopBot(bot) {
  const p = procs[bot.id];
  if (!p) return;
  clearTimeout(p.timer);
  if (p.child) {
    try { process.kill(p.child.pid, 'SIGTERM'); } catch {}
    const c = p.child;
    setTimeout(() => { try { c.kill('SIGKILL'); } catch {} }, 4000);
  }
}

// ---------- חילוץ ZIP בטוח ----------
function extractZip(zipPath, dir) {
  const zip = new AdmZip(zipPath);
  const root = path.resolve(dir) + path.sep;
  for (const e of zip.getEntries()) {                      // הגנה מפני Zip Slip
    if (!path.resolve(dir, e.entryName).startsWith(root)) throw new Error('קובץ ZIP לא תקין');
  }
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  zip.extractAllTo(dir, true);
  const items = fs.readdirSync(dir).filter(n => n !== '__MACOSX');
  if (items.length === 1 && fs.statSync(path.join(dir, items[0])).isDirectory()) { // תיקייה אחת בשורש? מעלים החוצה
    const inner = path.join(dir, items[0]);
    fs.readdirSync(inner).forEach(n => fs.renameSync(path.join(inner, n), path.join(dir, n)));
    fs.rmdirSync(inner);
  }
}

// ---------- Express ----------
const app = express();
const upload = multer({ dest: path.join(DATA, 'tmp'), limits: { fileSize: 50 * 1024 * 1024 } });
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  try { req.user = jwt.verify(req.cookies.session, db.secret); next(); }
  catch { res.status(401).json({ error: 'צריך להתחבר' }); }
};
const setSession = (res, user) =>
  res.cookie('session', jwt.sign({ id: user.id, name: user.name }, db.secret, { expiresIn: '7d' }),
    { httpOnly: true, sameSite: 'lax', maxAge: 7 * 864e5 });

app.post('/api/register', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password || password.length < 6) return res.status(400).json({ error: 'שם משתמש וסיסמה (לפחות 6 תווים) נדרשים' });
  if (db.users.find(u => u.name === name)) return res.status(409).json({ error: 'שם המשתמש תפוס' });
  const user = { id: crypto.randomUUID(), name, hash: bcrypt.hashSync(password, 10) };
  db.users.push(user); save(); setSession(res, user);
  res.json({ name });
});

app.post('/api/login', (req, res) => {
  const user = db.users.find(u => u.name === req.body.name);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.hash)) return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
  setSession(res, user); res.json({ name: user.name });
});

app.post('/api/logout', (req, res) => { res.clearCookie('session'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ name: req.user.name }));

const view = b => ({ id: b.id, name: b.name, runtime: b.runtime, startCmd: b.startCmd, running: isRunning(b.id), createdAt: b.createdAt });
const own = (req, res) => {
  const bot = db.bots.find(b => b.id === req.params.id && b.owner === req.user.id);
  if (!bot) res.status(404).json({ error: 'הבוט לא נמצא' });
  return bot;
};

app.get('/api/bots', auth, (req, res) => res.json(db.bots.filter(b => b.owner === req.user.id).map(view)));

app.post('/api/bots', auth, upload.single('file'), (req, res) => {
  try {
    const { name, token, runtime, startCmd } = req.body;
    if (db.bots.filter(b => b.owner === req.user.id).length >= MAX_BOTS_PER_USER) throw new Error(`אפשר ליצור עד ${MAX_BOTS_PER_USER} בוטים`);
    if (!name || !token || !RUNTIMES[runtime] || !req.file) throw new Error('חסרים שם, טוקן, סוג בוט או קובץ ZIP');
    const bot = { id: crypto.randomUUID(), owner: req.user.id, name, token, runtime,
      startCmd: startCmd || RUNTIMES[runtime].start, desired: 'stopped', createdAt: Date.now() };
    extractZip(req.file.path, path.join(BOTS_DIR, bot.id));
    db.bots.push(bot); save();
    res.json(view(bot));
  } catch (e) { res.status(400).json({ error: e.message }); }
  finally { if (req.file) fs.rm(req.file.path, { force: true }, () => {}); }
});

// עדכון טוקן / קובץ ZIP חדש / פקודת הפעלה
app.put('/api/bots/:id', auth, upload.single('file'), (req, res) => {
  const bot = own(req, res); if (!bot) return;
  try {
    const wasRunning = isRunning(bot.id);
    if (wasRunning) stopBot(bot);
    if (req.body.token) bot.token = req.body.token;
    if (req.body.startCmd) bot.startCmd = req.body.startCmd;
    if (req.file) extractZip(req.file.path, path.join(BOTS_DIR, bot.id));
    save();
    if (wasRunning) setTimeout(() => { bot.desired = 'running'; startBot(bot); }, 4500);
    res.json(view(bot));
  } catch (e) { res.status(400).json({ error: e.message }); }
  finally { if (req.file) fs.rm(req.file.path, { force: true }, () => {}); }
});

app.post('/api/bots/:id/start', auth, (req, res) => {
  const bot = own(req, res); if (!bot) return;
  bot.desired = 'running'; save(); startBot(bot); res.json(view(bot));
});
app.post('/api/bots/:id/stop', auth, (req, res) => {
  const bot = own(req, res); if (!bot) return;
  bot.desired = 'stopped'; save(); stopBot(bot); res.json({ ...view(bot), running: false });
});
app.post('/api/bots/:id/restart', auth, (req, res) => {
  const bot = own(req, res); if (!bot) return;
  bot.desired = 'running'; save(); stopBot(bot);
  setTimeout(() => startBot(bot), 4500); res.json(view(bot));
});
app.get('/api/bots/:id/logs', auth, (req, res) => {
  const bot = own(req, res); if (!bot) return;
  res.json({ running: isRunning(bot.id), logs: (procs[bot.id] && procs[bot.id].logs) || [] });
});
app.delete('/api/bots/:id', auth, (req, res) => {
  const bot = own(req, res); if (!bot) return;
  bot.desired = 'stopped'; stopBot(bot);
  db.bots = db.bots.filter(b => b.id !== bot.id); save();
  setTimeout(() => fs.rmSync(path.join(BOTS_DIR, bot.id), { recursive: true, force: true }), 5000);
  res.json({ ok: true });
});

// ---------- בעליית השרת: מרימים מחדש את כל הבוטים שהיו פעילים ----------
db.bots.filter(b => b.desired === 'running').forEach(startBot);
process.on('SIGTERM', () => { db.bots.forEach(stopBot); setTimeout(() => process.exit(0), 1000); });

app.listen(PORT, () => console.log(`BotCloud רץ על http://localhost:${PORT}`));
