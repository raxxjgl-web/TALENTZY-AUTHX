const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const ADMIN_USER = process.env.ADMIN_USER || 'AffanKyu12';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Keysha';
const ADMIN_TOKEN = crypto
  .createHash('sha256')
  .update(`${ADMIN_USER}:${ADMIN_PASS}:TALENTZY_AUTH_SALT`)
  .digest('hex');

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC_DIR));

function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify({ licenses: [], banned_hwids: [] }, null, 2),
      'utf8'
    );
  }
}

function readDB() {
  initDB();
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      licenses: Array.isArray(data.licenses) ? data.licenses : [],
      banned_hwids: Array.isArray(data.banned_hwids) ? data.banned_hwids : []
    };
  } catch {
    const clean = { licenses: [], banned_hwids: [] };
    writeDB(clean);
    return clean;
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function generateKeyString(prefix = 'TLZ') {
  const clean = (prefix || 'TLZ').toUpperCase().replace(/[^A-Z0-9]/g, '') || 'TLZ';
  const block = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${clean}-${block()}-${block()}-${block()}`;
}

// Endpoint Login Admin
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (String(username || '').trim() === ADMIN_USER && String(password || '') === ADMIN_PASS) {
    return res.json({
      success: true,
      token: ADMIN_TOKEN,
      user: ADMIN_USER
    });
  }
  return res.status(401).json({
    success: false,
    message: 'Username atau password salah.'
  });
});

// Middleware Auth Admin
function requireAdmin(req, res, next) {
  const authHeader = req.headers['x-admin-token'];
  if (!authHeader || authHeader !== ADMIN_TOKEN) {
    return res.status(401).json({
      success: false,
      message: 'Sesi tidak valid. Silakan login ulang.'
    });
  }
  next();
}

// Endpoint Verifikasi untuk Aplikasi .NET (.exe)
app.post('/api/v1/verify', (req, res) => {
  const { key, hwid } = req.body || {};
  if (!key || !hwid) {
    return res.status(400).json({
      success: false,
      code: 'MISSING_DATA',
      message: 'License key dan HWID wajib dikirim.'
    });
  }

  const db = readDB();
  const cleanKey = String(key).trim().toUpperCase();
  const cleanHwid = String(hwid).trim();

  if (db.banned_hwids.some(item => item.hwid === cleanHwid)) {
    return res.status(403).json({
      success: false,
      code: 'HWID_BANNED',
      message: 'HWID perangkat ini diblokir permanen.'
    });
  }

  const lic = db.licenses.find(item => item.key === cleanKey);
  if (!lic) {
    return res.status(404).json({
      success: false,
      code: 'INVALID_KEY',
      message: 'License key tidak ditemukan.'
    });
  }

  if (lic.status === 'banned') {
    return res.status(403).json({
      success: false,
      code: 'KEY_BANNED',
      message: `Lisensi diblokir (${lic.ban_reason || 'Pelanggaran aturan'}).`
    });
  }

  const now = new Date();
  if (!lic.hwid) {
    lic.hwid = cleanHwid;
    lic.activated_at = now.toISOString();
    lic.expires_at =
      lic.duration_days === -1
        ? null
        : new Date(now.getTime() + lic.duration_days * 24 * 60 * 60 * 1000).toISOString();
    lic.status = 'active';
  } else if (lic.hwid !== cleanHwid) {
    return res.status(403).json({
      success: false,
      code: 'HWID_MISMATCH',
      message: 'Key sudah terikat ke HWID perangkat lain.'
    });
  }

  if (lic.expires_at && new Date(lic.expires_at) < now) {
    lic.status = 'expired';
    writeDB(db);
    return res.status(403).json({
      success: false,
      code: 'EXPIRED',
      message: 'Masa aktif lisensi sudah habis.'
    });
  }

  lic.last_login = now.toISOString();
  writeDB(db);

  return res.json({
    success: true,
    code: 'VALID',
    message: 'Autentikasi berhasil.',
    data: {
      key: lic.key,
      duration_label: lic.duration_label,
      expires_at: lic.expires_at || 'LIFETIME',
      hwid: lic.hwid
    }
  });
});

// Data Dashboard
app.get('/api/admin/data', requireAdmin, (req, res) => {
  const db = readDB();
  const now = new Date();
  let updated = false;

  db.licenses.forEach(item => {
    if (item.status === 'active' && item.expires_at && new Date(item.expires_at) < now) {
      item.status = 'expired';
      updated = true;
    }
  });

  if (updated) writeDB(db);
  res.json({
    success: true,
    licenses: db.licenses,
    banned_hwids: db.banned_hwids
  });
});

// Buat Key (Semua Durasi)
app.post('/api/admin/create-keys', requireAdmin, (req, res) => {
  const { prefix, duration_days, quantity, note } = req.body || {};
  const qty = Math.min(Math.max(parseInt(quantity, 10) || 1, 1), 100);
  const days = parseInt(duration_days, 10);

  const labelMap = {
    1: '1 Hari',
    3: '3 Hari',
    7: '7 Hari',
    14: '14 Hari',
    30: '30 Hari',
    90: '90 Hari',
    365: '1 Tahun',
    '-1': 'Lifetime'
  };

  const db = readDB();
  const created = [];

  for (let i = 0; i < qty; i++) {
    const entry = {
      id: crypto.randomUUID(),
      key: generateKeyString(prefix),
      duration_days: Number.isNaN(days) ? 30 : days,
      duration_label: labelMap[String(days)] || `${days} Hari`,
      status: 'unused',
      hwid: null,
      note: (note && String(note).trim()) || '-',
      created_at: new Date().toISOString(),
      activated_at: null,
      expires_at: null,
      last_login: null,
      ban_reason: null
    };
    db.licenses.unshift(entry);
    created.push(entry);
  }

  writeDB(db);
  res.json({ success: true, created });
});

app.post('/api/admin/reset-hwid', requireAdmin, (req, res) => {
  const { id } = req.body || {};
  const db = readDB();
  const lic = db.licenses.find(item => item.id === id);
  if (!lic) return res.status(404).json({ success: false, message: 'Key tidak ditemukan.' });

  lic.hwid = null;
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/admin/ban-key', requireAdmin, (req, res) => {
  const { id, reason, also_ban_hwid } = req.body || {};
  const db = readDB();
  const lic = db.licenses.find(item => item.id === id);
  if (!lic) return res.status(404).json({ success: false, message: 'Key tidak ditemukan.' });

  lic.status = 'banned';
  lic.ban_reason = (reason && String(reason).trim()) || 'Banned by Admin';

  if (also_ban_hwid && lic.hwid) {
    if (!db.banned_hwids.some(b => b.hwid === lic.hwid)) {
      db.banned_hwids.unshift({
        hwid: lic.hwid,
        reason: `Dari key ${lic.key}: ${lic.ban_reason}`,
        banned_at: new Date().toISOString()
      });
    }
  }

  writeDB(db);
  res.json({ success: true });
});

app.post('/api/admin/ban-hwid', requireAdmin, (req, res) => {
  const { hwid, reason } = req.body || {};
  const cleanHwid = String(hwid || '').trim();
  if (!cleanHwid) {
    return res.status(400).json({ success: false, message: 'HWID wajib diisi.' });
  }

  const db = readDB();
  if (!db.banned_hwids.some(b => b.hwid === cleanHwid)) {
    db.banned_hwids.unshift({
      hwid: cleanHwid,
      reason: (reason && String(reason).trim()) || 'Banned Manual',
      banned_at: new Date().toISOString()
    });
  }
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/admin/unban-hwid', requireAdmin, (req, res) => {
  const { hwid } = req.body || {};
  const db = readDB();
  db.banned_hwids = db.banned_hwids.filter(b => b.hwid !== hwid);
  writeDB(db);
  res.json({ success: true });
});

app.delete('/api/admin/delete-key/:id', requireAdmin, (req, res) => {
  const db = readDB();
  db.licenses = db.licenses.filter(item => item.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  initDB();
  console.log(`Talentzy Auth aktif di http://localhost:${PORT}`);
});
