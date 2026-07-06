/* ============================================================
   Çocuk Alerji Kliniği — Randevu Sunucusu
   Çalıştırma: node server.js
   - DATABASE_URL tanımlıysa  → PostgreSQL (bulut, kalıcı)
   - tanımlı değilse          → data.json dosyası (yerel test)
   ============================================================ */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({limit: '10mb'}));
app.use(express.static(path.join(__dirname, 'public')));

const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');

const DEFAULT_HOLIDAYS = [
  {date:'2026-01-01', name:'Yılbaşı'},
  {date:'2026-03-19', name:'Ramazan Bayramı Arifesi (yarım gün)'},
  {date:'2026-03-20', name:'Ramazan Bayramı 1. Gün'},
  {date:'2026-04-23', name:'Ulusal Egemenlik ve Çocuk Bayramı'},
  {date:'2026-05-01', name:'Emek ve Dayanışma Günü'},
  {date:'2026-05-19', name:"Atatürk'ü Anma, Gençlik ve Spor Bayramı"},
  {date:'2026-05-27', name:'Kurban Bayramı 1. Gün'},
  {date:'2026-05-28', name:'Kurban Bayramı 2. Gün'},
  {date:'2026-05-29', name:'Kurban Bayramı 3. Gün'},
  {date:'2026-07-15', name:'Demokrasi ve Milli Birlik Günü'},
  {date:'2026-08-30', name:'Zafer Bayramı'},
  {date:'2026-10-29', name:'Cumhuriyet Bayramı'},
  {date:'2027-01-01', name:'Yılbaşı'},
  {date:'2027-03-09', name:'Ramazan Bayramı 1. Gün'},
  {date:'2027-03-10', name:'Ramazan Bayramı 2. Gün'},
  {date:'2027-03-11', name:'Ramazan Bayramı 3. Gün'},
  {date:'2027-04-23', name:'Ulusal Egemenlik ve Çocuk Bayramı'},
  {date:'2027-05-17', name:'Kurban Bayramı 2. Gün'},
  {date:'2027-05-18', name:'Kurban Bayramı 3. Gün'},
  {date:'2027-05-19', name:'Kurban Bayramı 4. Gün / 19 Mayıs'},
  {date:'2027-07-15', name:'Demokrasi ve Milli Birlik Günü'},
  {date:'2027-10-29', name:'Cumhuriyet Bayramı'},
];

const DEFAULT_STATE = {
  version: 1,
  db: {
    users: [
      {id:'u1', name:'Yönetici', role:'admin', pin_sha256: sha('1234')},
      {id:'u2', name:'Sekreter', role:'staff', pin_sha256: sha('1234')},
    ],
    appointments: [], leaves: [], holidays: DEFAULT_HOLIDAYS, audit: [],
  },
};

/* ---------- Depolama katmanı ---------- */
let pool = null;
const DATA_FILE = path.join(__dirname, 'data.json');

if(process.env.DATABASE_URL){
  const {Pool} = require('pg');
  pool = new Pool({connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: false}});
}

async function init(){
  if(pool){
    await pool.query('CREATE TABLE IF NOT EXISTS klinik_state (id int PRIMARY KEY, version int NOT NULL, data jsonb NOT NULL)');
    const r = await pool.query('SELECT 1 FROM klinik_state WHERE id = 1');
    if(!r.rowCount)
      await pool.query('INSERT INTO klinik_state VALUES (1, $1, $2)', [DEFAULT_STATE.version, JSON.stringify(DEFAULT_STATE.db)]);
    console.log('Depolama: PostgreSQL');
  } else {
    if(!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(DEFAULT_STATE, null, 1));
    console.log('Depolama: data.json (yerel dosya — bulutta DATABASE_URL tanımlayın!)');
  }
}

async function load(){
  if(pool){
    const r = await pool.query('SELECT version, data FROM klinik_state WHERE id = 1');
    return {version: r.rows[0].version, db: r.rows[0].data};
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

/* İyimser eşzamanlılık: sürüm eşleşirse yaz, yoksa null (çakışma) */
async function save(expectedVersion, db){
  const nv = Number(expectedVersion) + 1;
  if(pool){
    const r = await pool.query('UPDATE klinik_state SET version = $1, data = $2 WHERE id = 1 AND version = $3',
      [nv, JSON.stringify(db), expectedVersion]);
    return r.rowCount ? nv : null;
  }
  const cur = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if(cur.version !== expectedVersion) return null;
  fs.writeFileSync(DATA_FILE, JSON.stringify({version: nv, db}, null, 1));
  return nv;
}

/* ---------- Kimlik doğrulama ---------- */
const TOKENS = new Map();  // token → {id, name, role} (sunucu yeniden başlarsa oturumlar düşer)

function auth(req, res, next){
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const u = TOKENS.get(t);
  if(!u) return res.status(401).json({error: 'Oturum geçersiz'});
  req.user = u;
  next();
}

/* ---------- API ---------- */
app.get('/api/users-public', async (req, res) => {
  try{
    const s = await load();
    res.json(s.db.users.map(u => ({id: u.id, name: u.name, role: u.role})));
  }catch(e){ res.status(500).json({error: 'Sunucu hatası'}); }
});

app.post('/api/login', async (req, res) => {
  try{
    const {userId, pin} = req.body || {};
    const s = await load();
    const u = s.db.users.find(x => x.id === userId);
    if(!u || u.pin_sha256 !== sha(pin || '')) return res.status(403).json({error: 'PIN hatalı'});
    const t = crypto.randomUUID();
    TOKENS.set(t, {id: u.id, name: u.name, role: u.role});
    res.json({token: t, user: {id: u.id, name: u.name, role: u.role}});
  }catch(e){ res.status(500).json({error: 'Sunucu hatası'}); }
});

app.get('/api/state', auth, async (req, res) => {
  try{ res.json(await load()); }
  catch(e){ res.status(500).json({error: 'Sunucu hatası'}); }
});

app.put('/api/state', auth, async (req, res) => {
  try{
    const {version, db} = req.body || {};
    if(!db || !Array.isArray(db.users) || !Array.isArray(db.appointments) ||
       !Array.isArray(db.leaves) || !Array.isArray(db.holidays) || !db.users.length)
      return res.status(400).json({error: 'Geçersiz veri yapısı'});
    const nv = await save(version, db);
    if(nv === null){
      const cur = await load();
      return res.status(409).json({conflict: true, version: cur.version, db: cur.db});
    }
    res.json({version: nv});
  }catch(e){ res.status(500).json({error: 'Sunucu hatası'}); }
});

app.get('/healthz', (req, res) => res.send('ok'));

const PORT = process.env.PORT || 3000;
init().then(() => app.listen(PORT, () =>
  console.log('Klinik randevu sunucusu hazır → http://localhost:' + PORT)
)).catch(e => { console.error('Başlatma hatası:', e.message); process.exit(1); });
