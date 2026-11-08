// Relx Gamble - backend (Vercel Serverless Function) + Upstash Redis (REST)
// Semua akun, saldo, pengajuan, dan hasil game diproses di sini (server), bukan di browser.
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

const DEP_MIN = 5000000, DEP_MAX = 100000000;
const BASE_RTP = 0.85, TIER1 = 5000000, TIER2 = 10000000;
const MODES = ['mudah', 'sedang', 'sulit'];
const COIN = { mudah: { mult: 1.75, chance: 0.48 }, sedang: { mult: 2.1, chance: 0.40 }, sulit: { mult: 3, chance: 0.28 } };
const MINES = { mudah: { mines: 3, cap: 4 }, sedang: { mines: 5, cap: 8 }, sulit: { mines: 8, cap: 15 } };
const PLINKO = {
  1: { mudah: [2.5, 1.3, 1.1, 0.85, 0.5, 0.85, 1.1, 1.3, 2.5], sedang: [5, 2.4, 1.3, 0.6, 0.4, 0.6, 1.3, 2.4, 5], sulit: [9, 3.5, 1.3, 0.5, 0.2, 0.5, 1.3, 3.5, 9] },
  2: { mudah: [2.3, 1.3, 1.1, 0.7, 0.4, 0.7, 1.1, 1.3, 2.3], sedang: [4.5, 2.2, 1.2, 0.5, 0.35, 0.5, 1.2, 2.2, 4.5], sulit: [8, 3.1, 1.2, 0.4, 0.2, 0.4, 1.2, 3.1, 8] },
  3: { mudah: [2, 1.2, 1.05, 0.6, 0.3, 0.6, 1.05, 1.2, 2], sedang: [4, 2, 1.1, 0.45, 0.25, 0.45, 1.1, 2, 4], sulit: [7, 2.6, 1.1, 0.35, 0.15, 0.35, 1.1, 2.6, 7] }
};
const CASE_TABLE = [[0, 32], [0.5, 24], [1, 17], [1.5, 13], [2, 8], [3, 5], [5, 1]];
const CRASH_RATE = 0.11;

/* ---------- util ---------- */
const tierNo = b => (b > TIER2 ? 3 : b > TIER1 ? 2 : 1);
const tierRTP = b => (b > TIER2 ? 0.65 : b > TIER1 ? 0.75 : BASE_RTP);
const tierScale = b => tierRTP(b) / BASE_RTP;
const r2 = x => Math.round(x * 100) / 100;
const rnd = () => crypto.randomInt(0, 2 ** 47) / 2 ** 47;
const ri = n => crypto.randomInt(0, n);
const fail = (error, http = 400, extra = {}) => ({ error, http, ...extra });
const UNAUTH = () => fail('Sesi habis, silakan masuk lagi.', 401);
const ipOf = req => String((req.headers && req.headers['x-forwarded-for']) || '').split(',')[0].trim() || 'x';
const validName = s => typeof s === 'string' && /^[A-Za-z0-9_]{3,16}$/.test(s);
const parseBet = v => { const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= 1 && n <= 1e12 ? n : 0; };
function pickWeighted(t) { let r = rnd() * t.reduce((s, x) => s + x[1], 0); for (const x of t) { r -= x[1]; if (r < 0) return x[0]; } return t[0][0]; }

/* ---------- Redis (Upstash REST pipeline) ---------- */
async function db(cmds) {
  const r = await fetch(DB_URL + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + DB_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds)
  });
  const j = await r.json();
  if (!Array.isArray(j)) throw new Error('Redis error: ' + JSON.stringify(j));
  return j.map(x => { if (x && x.error) throw new Error('Redis: ' + x.error); return x.result; });
}
const one = async (...c) => (await db([c]))[0];

/* ---------- saldo ---------- */
async function getBalance(key) { return Number((await one('GET', 'bal:' + key)) || 0); }
async function spend(key, amt) {
  const [r] = await db([['DECRBY', 'bal:' + key, amt]]);
  if (r < 0) { await db([['INCRBY', 'bal:' + key, amt]]); return null; }
  await db([['INCR', 'ses:' + key], ['ZADD', 'lb', r, key]]);
  return r;
}
async function credit(key, amt) {
  if (amt > 0) {
    const [r] = await db([['INCRBY', 'bal:' + key, amt]]);
    await db([['ZADD', 'lb', r, key]]);
    return r;
  }
  return getBalance(key);
}
async function authed(b) {
  if (typeof b.token !== 'string' || !/^[a-f0-9]{64}$/.test(b.token)) return null;
  return (await one('GET', 'sess:' + b.token)) || null;
}

/* ---------- akun ---------- */
const H = {};
H.auth = async (b, req) => {
  const name = typeof b.username === 'string' ? b.username.trim() : '';
  const pw = typeof b.password === 'string' ? b.password : '';
  if (!validName(name)) return fail('Username 3–16 karakter: huruf, angka, underscore.');
  if (pw.length < 4 || pw.length > 100) return fail('Password minimal 4 karakter.');
  const ip = ipOf(req);
  const [n] = await db([['INCR', 'rl:auth:' + ip], ['EXPIRE', 'rl:auth:' + ip, 300]]);
  if (n > 40) return fail('Terlalu banyak percobaan. Coba lagi beberapa menit lagi.', 429);
  const key = name.toLowerCase();
  const raw = await one('GET', 'u:' + key);
  let created = false, display = name;
  if (!raw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scrypt(pw, salt, 32)).toString('hex');
    const ok = await one('SET', 'u:' + key, JSON.stringify({ name, salt, hash, created: Date.now() }), 'NX');
    if (!ok) return fail('Coba lagi sebentar.', 409);
    await db([['SET', 'bal:' + key, 0, 'NX'], ['ZADD', 'lb', 0, key]]);
    created = true;
  } else {
    const lf = Number((await one('GET', 'lf:' + key)) || 0);
    if (lf >= 8) return fail('Akun dikunci sementara karena terlalu banyak salah password. Coba lagi 10 menit.', 429);
    const u = JSON.parse(raw);
    const hash = await scrypt(pw, u.salt, 32);
    const ok = crypto.timingSafeEqual(hash, Buffer.from(u.hash, 'hex'));
    if (!ok) { await db([['INCR', 'lf:' + key], ['EXPIRE', 'lf:' + key, 600]]); return fail('Password salah.', 401); }
    await one('DEL', 'lf:' + key);
    display = u.name;
  }
  const token = crypto.randomBytes(32).toString('hex');
  await one('SET', 'sess:' + token, key, 'EX', 2592000);
  return { token, name: display, balance: await getBalance(key), created };
};

H.me = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const [raw, bal, ids] = await db([['GET', 'u:' + key], ['GET', 'bal:' + key], ['LRANGE', 'ureqs:' + key, 0, 9]]);
  if (!raw) return UNAUTH();
  let requests = [];
  if (ids && ids.length) {
    const rows = await one('MGET', ...ids.map(i => 'req:' + i));
    requests = rows.filter(Boolean).map(x => { const o = JSON.parse(x); return { type: o.type, amount: o.amount, status: o.status, time: o.time }; });
  }
  return { name: JSON.parse(raw).name, balance: Number(bal || 0), requests };
};

H.logout = async b => { if (typeof b.token === 'string' && /^[a-f0-9]{64}$/.test(b.token)) await one('DEL', 'sess:' + b.token); return { ok: true }; };

H.leaderboard = async () => {
  const flat = await one('ZRANGE', 'lb', 0, 4, 'REV', 'WITHSCORES');
  const keys = [], scores = [];
  for (let i = 0; i < flat.length; i += 2) { keys.push(flat[i]); scores.push(Number(flat[i + 1])); }
  if (!keys.length) return { top: [] };
  const rows = await one('MGET', ...keys.map(k => 'u:' + k));
  return { top: keys.map((k, i) => ({ name: rows[i] ? JSON.parse(rows[i]).name : k, balance: scores[i] })) };
};

/* ---------- game tanpa state ---------- */
H.play = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const bet = parseBet(b.bet); if (!bet) return fail('Taruhan tidak valid.');
  const mode = MODES.includes(b.mode) ? b.mode : 'mudah';
  const sc = tierScale(bet);
  let out, payout = 0;
  if (!['coinflip', 'dice', 'case', 'plinko'].includes(b.game)) return fail('Game tidak dikenal.');
  if (b.game === 'coinflip' && !['heads', 'tails'].includes(b.side)) return fail('Pilihan sisi tidak valid.');
  if (b.game === 'dice' && !['low', 'mid', 'high'].includes(b.guess)) return fail('Prediksi tidak valid.');
  const bal = await spend(key, bet);
  if (bal === null) return fail('Saldo tidak cukup. Silakan Deposit dulu.');
  if (b.game === 'coinflip') {
    const c = COIN[mode];
    const win = rnd() < c.chance * sc;
    const actual = win ? b.side : (b.side === 'heads' ? 'tails' : 'heads');
    payout = win ? Math.floor(bet * c.mult) : 0;
    out = { actual, win };
  } else if (b.game === 'dice') {
    const a = 1 + ri(6), c = 1 + ri(6), t = a + c;
    const ok = (b.guess === 'low' && t <= 6) || (b.guess === 'mid' && t === 7) || (b.guess === 'high' && t >= 8);
    const mult = r2((b.guess === 'mid' ? 5 : 2) * sc);
    payout = ok ? Math.floor(bet * mult) : 0;
    out = { a, b: c, total: t, ok, mult };
  } else if (b.game === 'case') {
    const mult = r2(pickWeighted(CASE_TABLE) * sc);
    payout = Math.floor(bet * mult);
    out = { mult };
  } else {
    const table = PLINKO[tierNo(bet)][mode];
    const dirs = []; let r = 0;
    for (let i = 0; i < 8; i++) { const right = rnd() < 0.5; dirs.push(right); if (right) r++; }
    payout = Math.floor(bet * table[r]);
    out = { dirs, r, mult: table[r], table };
  }
  const balance = await credit(key, payout);
  return { ...out, bet, payout, balance };
};

/* ---------- game dengan state ---------- */
const GKEY = k => 'game:' + k;
const crashM = o => Math.exp(CRASH_RATE * (Date.now() - o.t0) / 1000);
const GAME_NAME = { crash: 'Crash', mines: 'Mines', bj: 'Blackjack' };

async function startGuard(key) {
  const g = await one('GET', GKEY(key));
  if (!g) return null;
  const o = JSON.parse(g);
  if (o.type === 'crash' && crashM(o) >= o.crashAt) { await one('DEL', GKEY(key)); return null; }
  return fail('Selesaikan game ' + (GAME_NAME[o.type] || '') + ' yang sedang berjalan dulu.', 409, { active: o.type });
}
async function begin(key, bet, state, ttl) {
  const bal = await spend(key, bet);
  if (bal === null) return { err: fail('Saldo tidak cukup. Silakan Deposit dulu.') };
  const ok = await one('SET', GKEY(key), JSON.stringify(state), 'NX', 'EX', ttl);
  if (!ok) { await credit(key, bet); return { err: fail('Selesaikan game yang sedang berjalan dulu.', 409) }; }
  return { bal };
}
const claim = async key => { const g = await one('GETDEL', GKEY(key)); return g ? JSON.parse(g) : null; };
const keep = (key, o, ttl) => one('SET', GKEY(key), JSON.stringify(o), 'EX', ttl);

/* Crash */
H.crash_start = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const bet = parseBet(b.bet); if (!bet) return fail('Taruhan tidak valid.');
  const guard = await startGuard(key); if (guard) return guard;
  const crashAt = Math.min(100, Math.max(1, Math.floor(100 * tierRTP(bet) / (1 - rnd())) / 100));
  if (crashAt <= 1) {
    const bal = await spend(key, bet);
    if (bal === null) return fail('Saldo tidak cukup. Silakan Deposit dulu.');
    return { status: 'crashed', at: 1, payout: 0, balance: bal };
  }
  const r = await begin(key, bet, { type: 'crash', bet, crashAt, t0: Date.now() }, 900);
  if (r.err) return r.err;
  return { status: 'running', balance: r.bal };
};
H.crash_poll = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const g = await one('GET', GKEY(key));
  if (!g) return { status: 'none' };
  const o = JSON.parse(g);
  if (o.type !== 'crash') return { status: 'none' };
  if (crashM(o) >= o.crashAt) {
    const c = await claim(key);
    return c ? { status: 'crashed', at: o.crashAt } : { status: 'none' };
  }
  return { status: 'running' };
};
H.crash_cash = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const g = await one('GET', GKEY(key));
  if (!g || JSON.parse(g).type !== 'crash') return { status: 'none' };
  const o = await claim(key);
  if (!o) return { status: 'none' };
  const m = crashM(o);
  if (m >= o.crashAt) return { status: 'crashed', at: o.crashAt };
  const mult = Math.max(1, Math.floor(m * 100) / 100);
  const payout = Math.floor(o.bet * mult);
  return { status: 'cashed', mult, bet: o.bet, payout, balance: await credit(key, payout) };
};

/* Mines */
const minesMult = (o, k) => {
  const c = MINES[o.mode]; let p = 1;
  for (let i = 0; i < k; i++) p *= (25 - i) / (25 - c.mines - i);
  return Math.min(c.cap, p * tierRTP(o.bet));
};
H.mines_start = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const bet = parseBet(b.bet); if (!bet) return fail('Taruhan tidak valid.');
  const mode = MODES.includes(b.mode) ? b.mode : 'mudah';
  const guard = await startGuard(key); if (guard) return guard;
  const pool = Array.from({ length: 25 }, (_, i) => i);
  for (let i = pool.length - 1; i > 0; i--) { const j = ri(i + 1); [pool[i], pool[j]] = [pool[j], pool[i]]; }
  const o = { type: 'mines', mode, bet, mines: pool.slice(0, MINES[mode].mines), found: [] };
  const r = await begin(key, bet, o, 21600);
  if (r.err) return r.err;
  return { balance: r.bal, minesCount: MINES[mode].mines, cap: MINES[mode].cap };
};
H.mines_pick = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const cell = Number(b.cell);
  if (!Number.isInteger(cell) || cell < 0 || cell > 24) return fail('Kotak tidak valid.');
  const o = await claim(key);
  if (!o || o.type !== 'mines') { if (o) await keep(key, o, 21600); return fail('Tidak ada game Mines yang berjalan.', 409); }
  if (o.found.includes(cell)) { await keep(key, o, 21600); return fail('Kotak sudah dibuka.'); }
  if (o.mines.includes(cell)) return { result: 'mine', mines: o.mines, payout: 0, bet: o.bet, balance: await getBalance(key) };
  o.found.push(cell);
  const mult = minesMult(o, o.found.length);
  const c = MINES[o.mode];
  if (mult >= c.cap || o.found.length >= 25 - c.mines) {
    const payout = Math.floor(o.bet * mult);
    return { result: 'safe', cell, found: o.found, mult: r2(mult), auto: true, payout, bet: o.bet, mines: o.mines, balance: await credit(key, payout) };
  }
  await keep(key, o, 21600);
  return { result: 'safe', cell, found: o.found, mult: r2(mult) };
};
H.mines_cash = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const o = await claim(key);
  if (!o || o.type !== 'mines') { if (o) await keep(key, o, 21600); return fail('Tidak ada game Mines yang berjalan.', 409); }
  if (!o.found.length) { await keep(key, o, 21600); return fail('Buka minimal satu kotak dulu.'); }
  const mult = minesMult(o, o.found.length);
  const payout = Math.floor(o.bet * mult);
  return { mult: r2(mult), found: o.found.length, payout, bet: o.bet, mines: o.mines, balance: await credit(key, payout) };
};

/* Blackjack */
const RANKS = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'], SUITS = ['♠', '♥', '♦', '♣'];
const card = () => ({ r: RANKS[ri(13)], s: SUITS[ri(4)] });
const cval = c => (c.r === 'A' ? 11 : ['10', 'J', 'Q', 'K'].includes(c.r) ? 10 : Number(c.r));
const total = h => { let t = h.reduce((s, c) => s + cval(c), 0), a = h.filter(c => c.r === 'A').length; while (t > 21 && a > 0) { t -= 10; a--; } return t; };
async function bjResolve(key, o) {
  while (total(o.dealer) < 17) o.dealer.push(card());
  const p = total(o.player), d = total(o.dealer), sc = tierScale(o.bet);
  let payout = 0, detail;
  if (d > 21) { payout = Math.floor(o.bet * 2 * sc); detail = 'Dealer bust (' + d + ')'; }
  else if (p > d) { payout = Math.floor(o.bet * 2 * sc); detail = 'Kamu ' + p + ' vs Dealer ' + d; }
  else if (p === d) { detail = 'Seri ' + p + ' = dealer menang'; }
  else { detail = 'Kamu ' + p + ' vs Dealer ' + d; }
  return { status: 'done', player: o.player, dealer: o.dealer, pt: p, dt: d, payout, bet: o.bet, detail, balance: await credit(key, payout) };
}
H.bj_start = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const bet = parseBet(b.bet); if (!bet) return fail('Taruhan tidak valid.');
  const guard = await startGuard(key); if (guard) return guard;
  const o = { type: 'bj', bet, player: [card(), card()], dealer: [card(), card()] };
  if (total(o.player) === 21) {
    const bal = await spend(key, bet);
    if (bal === null) return fail('Saldo tidak cukup. Silakan Deposit dulu.');
    const dBJ = total(o.dealer) === 21;
    const payout = dBJ ? bet : Math.floor(bet * 2.2 * tierScale(bet));
    return { status: 'done', player: o.player, dealer: o.dealer, pt: 21, dt: total(o.dealer), payout, bet, detail: dBJ ? 'Blackjack seri' : 'Blackjack! (bayar 6:5)', balance: await credit(key, payout) };
  }
  const r = await begin(key, bet, o, 21600);
  if (r.err) return r.err;
  return { status: 'playing', player: o.player, dealerUp: o.dealer[0], pt: total(o.player), balance: r.bal };
};
H.bj_hit = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const o = await claim(key);
  if (!o || o.type !== 'bj') { if (o) await keep(key, o, 21600); return fail('Tidak ada game Blackjack yang berjalan.', 409); }
  o.player.push(card());
  const t = total(o.player);
  if (t > 21) return { status: 'done', player: o.player, dealer: o.dealer, pt: t, dt: total(o.dealer), payout: 0, bet: o.bet, detail: 'Bust! Total kamu ' + t, balance: await getBalance(key) };
  if (t === 21) return bjResolve(key, o);
  await keep(key, o, 21600);
  return { status: 'playing', player: o.player, dealerUp: o.dealer[0], pt: t };
};
H.bj_stand = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const o = await claim(key);
  if (!o || o.type !== 'bj') { if (o) await keep(key, o, 21600); return fail('Tidak ada game Blackjack yang berjalan.', 409); }
  return bjResolve(key, o);
};

/* Lanjutkan game yang sedang berjalan (misal halaman di-refresh) */
H.resume = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const g = await one('GET', GKEY(key));
  if (!g) return { game: null };
  const o = JSON.parse(g);
  if (o.type === 'mines') return { game: { type: 'mines', mode: o.mode, bet: o.bet, found: o.found, minesCount: MINES[o.mode].mines, cap: MINES[o.mode].cap, mult: r2(minesMult(o, o.found.length)) } };
  if (o.type === 'bj') return { game: { type: 'bj', bet: o.bet, player: o.player, dealerUp: o.dealer[0], pt: total(o.player) } };
  if (o.type === 'crash') {
    if (crashM(o) >= o.crashAt) { const c = await claim(key); return c ? { game: { type: 'crash', status: 'crashed', at: o.crashAt, bet: o.bet } } : { game: null }; }
    return { game: { type: 'crash', status: 'running', bet: o.bet, elapsed: Date.now() - o.t0 } };
  }
  return { game: null };
};

/* ---------- deposit & withdraw ---------- */
const newId = () => 'r' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
async function saveReq(key, o) {
  await db([['SET', 'req:' + o.id, JSON.stringify(o)], ['LPUSH', 'reqs', o.id], ['LTRIM', 'reqs', 0, 499], ['LPUSH', 'ureqs:' + key, o.id], ['LTRIM', 'ureqs:' + key, 0, 49]]);
}
async function accountName(key) { const raw = await one('GET', 'u:' + key); return raw ? JSON.parse(raw).name : key; }
H.deposit = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const user = typeof b.user === 'string' ? b.user.trim() : '';
  const amount = Number(b.amount);
  if (!validName(user)) return fail('Username tidak valid (3–16 karakter: huruf, angka, underscore).');
  if (!Number.isInteger(amount) || amount < DEP_MIN || amount > DEP_MAX) return fail('Jumlah deposit harus antara ' + DEP_MIN.toLocaleString('id-ID') + ' dan ' + DEP_MAX.toLocaleString('id-ID') + '.');
  const okRl = await one('SET', 'rl:dep:' + key, 1, 'NX', 'EX', 20);
  if (!okRl) return fail('Tunggu beberapa detik sebelum mengajukan lagi.', 429);
  const o = { id: newId(), type: 'deposit', user, account: key, accountName: await accountName(key), amount, status: 'pending', time: Date.now() };
  await saveReq(key, o);
  return { ok: true, id: o.id };
};
H.withdraw = async b => {
  const key = await authed(b); if (!key) return UNAUTH();
  const user = typeof b.user === 'string' ? b.user.trim() : '';
  const amount = Number(b.amount);
  if (!validName(user)) return fail('Username tidak valid (3–16 karakter: huruf, angka, underscore).');
  if (!Number.isInteger(amount) || amount < 1 || amount > 1e12) return fail('Masukkan jumlah withdraw yang valid.');
  const g = await one('GET', GKEY(key));
  if (g) return fail('Selesaikan game yang sedang berjalan dulu sebelum withdraw.', 409);
  const bal = await spend(key, amount);
  if (bal === null) return fail('Saldo tidak cukup.');
  const okRl = await one('SET', 'rl:wd:' + key, 1, 'NX', 'EX', 20);
  if (!okRl) { await credit(key, amount); return fail('Tunggu beberapa detik sebelum mengajukan lagi.', 429); }
  const o = { id: newId(), type: 'withdraw', user, account: key, accountName: await accountName(key), amount, status: 'pending', time: Date.now() };
  await saveReq(key, o);
  return { ok: true, id: o.id, balance: bal };
};

/* ---------- admin ---------- */
async function adminCheck(b, req) {
  const pass = process.env.ADMIN_PASSWORD;
  if (!pass) return fail('ADMIN_PASSWORD belum diatur di Vercel (Environment Variables).', 500);
  const ip = ipOf(req);
  const f = Number((await one('GET', 'adminfail:' + ip)) || 0);
  if (f >= 10) return fail('Terlalu banyak percobaan. Coba lagi 10 menit lagi.', 429);
  const a = crypto.createHash('sha256').update(String(b.adminPass || '')).digest();
  const c = crypto.createHash('sha256').update(pass).digest();
  if (!crypto.timingSafeEqual(a, c)) { await db([['INCR', 'adminfail:' + ip], ['EXPIRE', 'adminfail:' + ip, 600]]); return fail('Password admin salah.', 403); }
  return null;
}
H.admin_list = async (b, req) => {
  const bad = await adminCheck(b, req); if (bad) return bad;
  const ids = await one('LRANGE', 'reqs', 0, 199);
  let requests = [];
  if (ids.length) requests = (await one('MGET', ...ids.map(i => 'req:' + i))).filter(Boolean).map(x => JSON.parse(x));
  const flat = await one('ZRANGE', 'lb', 0, 199, 'REV', 'WITHSCORES');
  const keys = [], bals = [];
  for (let i = 0; i < flat.length; i += 2) { keys.push(flat[i]); bals.push(Number(flat[i + 1])); }
  let players = [];
  if (keys.length) {
    const names = await one('MGET', ...keys.map(k => 'u:' + k));
    const ses = await one('MGET', ...keys.map(k => 'ses:' + k));
    players = keys.map((k, i) => ({ name: names[i] ? JSON.parse(names[i]).name : k, balance: bals[i], sessions: Number(ses[i] || 0) }));
  }
  const users = await one('ZCARD', 'lb');
  return {
    requests, players,
    stats: { users, totalCoins: players.reduce((s, p) => s + p.balance, 0), sessions: players.reduce((s, p) => s + p.sessions, 0), pending: requests.filter(r => r.status === 'pending').length }
  };
};
H.admin_decide = async (b, req) => {
  const bad = await adminCheck(b, req); if (bad) return bad;
  const id = String(b.id || '');
  if (!/^r[a-z0-9]{4,40}$/.test(id)) return fail('ID tidak valid.');
  if (!['acc', 'rej'].includes(b.act)) return fail('Aksi tidak valid.');
  const raw = await one('GET', 'req:' + id);
  if (!raw) return fail('Pengajuan tidak ditemukan.', 404);
  const o = JSON.parse(raw);
  if (o.status !== 'pending') return fail('Pengajuan ini sudah diproses.', 409);
  const lock = await one('SET', 'lock:req:' + id, 1, 'NX', 'EX', 30);
  if (!lock) return fail('Pengajuan sedang diproses.', 409);
  if (b.act === 'acc') {
    if (o.type === 'deposit') {
      const exists = await one('EXISTS', 'u:' + o.account);
      if (!exists) { await one('DEL', 'lock:req:' + id); return fail('Akun pemain tidak ditemukan.', 404); }
      await credit(o.account, o.amount);
    }
    o.status = 'approved';
  } else {
    if (o.type === 'withdraw') await credit(o.account, o.amount);
    o.status = 'rejected';
  }
  o.decidedAt = Date.now();
  await one('SET', 'req:' + id, JSON.stringify(o));
  return { ok: true, status: o.status };
};

/* ---------- handler ---------- */
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!DB_URL || !DB_TOKEN) return res.status(500).json({ error: 'Database belum terhubung (cek Storage dan Environment Variables di Vercel).' });
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (_) { b = {}; } }
  if (!b || typeof b !== 'object') b = {};
  const fn = typeof b.action === 'string' && Object.prototype.hasOwnProperty.call(H, b.action) ? H[b.action] : null;
  if (!fn) return res.status(400).json({ error: 'Aksi tidak dikenal.' });
  try {
    const out = await fn(b, req);
    const { http, ...rest } = out;
    res.status(http || 200).json(rest);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Terjadi kesalahan server. Coba lagi.' });
  }
};
