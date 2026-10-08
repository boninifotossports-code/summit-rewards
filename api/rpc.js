'use strict';
/* =====================================================================
   SUMMIT REWARDS - servidor (função do Vercel)
   Um único endpoint: POST /api/rpc  { action, params }
   Banco: Postgres (Neon, conectado pelo painel do Vercel via DATABASE_URL)
   ===================================================================== */
const crypto = require('crypto');
const { Pool, types } = require('pg');
types.setTypeParser(1082, s => s); // colunas "date" voltam como texto 'AAAA-MM-DD'

const CONN = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_URL_NON_POOLING;
const SECRET = crypto.createHash('sha256').update('summit|' + (process.env.AUTH_SECRET || CONN || '')).digest();
const TZ = 'America/Sao_Paulo';

let pool;
const Q = async (text, params) => {
  pool = pool || new Pool({ connectionString: CONN, max: 3, idleTimeoutMillis: 5000 });
  return (await pool.query(text, params)).rows;
};

class Err extends Error { constructor(m, status) { super(m); this.status = status || 400; } }

/* ---------- banco: cria as tabelas sozinho no primeiro acesso ---------- */
const DDL = `
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  name text not null, email text not null, password_hash text,
  role text not null default 'professor' check (role in ('admin','professor')),
  active boolean not null default true,
  created_at timestamptz not null default now());
create unique index if not exists users_email_key on users (lower(email));
create table if not exists students (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  label text not null default 'PKZ' check (label in ('PKZ','ONE TO ONE')),
  teacher_id uuid not null references users(id),
  active boolean not null default true,
  created_at timestamptz not null default now());
create table if not exists tasks (
  id uuid primary key default gen_random_uuid(),
  name text not null, category text not null default 'Geral',
  points int not null, active boolean not null default true,
  created_at timestamptz not null default now());
create table if not exists rewards (
  id uuid primary key default gen_random_uuid(),
  name text not null, cost int not null check (cost > 0),
  stock int not null default 0 check (stock >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now());
create table if not exists launches (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references users(id),
  task_id uuid not null references tasks(id),
  student_id uuid references students(id) on delete set null,
  points int not null, occurred_on date not null, expires_on date not null,
  note text, created_by uuid,
  created_at timestamptz not null default now());
create index if not exists launches_teacher_idx on launches (teacher_id, occurred_on);
create table if not exists redemptions (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references users(id),
  reward_id uuid not null references rewards(id),
  reward_name text not null, cost int not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(), decided_at timestamptz);
create table if not exists closings (
  month date primary key, closed_by uuid,
  closed_at timestamptz not null default now());
`;
let ready;
const ensure = () => ready || (ready = Q(DDL).catch(e => { ready = null; throw e; }));

const SEED_TASKS = [
  ['Novo aluno matriculado', 'Captação', 10], ['Recuperação de aluno', 'Captação', 5], ['Upgrade de plano', 'Captação', 5],
  ['Avaliação no prazo', 'Acompanhamento', 3], ['Reavaliação no prazo', 'Acompanhamento', 3], ['Relatório 100% em dia', 'Acompanhamento', 5],
  ['Meta de presença', 'Carteira', 5], ['Meta de alunos do grupo', 'Carteira', 10], ['Feedback positivo', 'Carteira', 3], ['Iniciativa com resultado', 'Carteira', 5],
  ['Atraso', 'Disciplina', -2], ['Falta sem justificativa', 'Disciplina', -5], ['Tarefa não realizada', 'Disciplina', -3], ['Relatório atrasado', 'Disciplina', -3],
];
const SEED_REWARDS = [
  ['Voucher de almoço', 20, 10], ['Voucher de jantar', 30, 10], ['Recovery', 40, 10],
  ['Presente', 50, 10], ['Ingresso Maracanã', 70, 5], ['Bonificação financeira', 100, 5],
];

/* ---------- senhas e sessão ---------- */
const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const checkPw = (pw, h) => {
  if (!h || typeof pw !== 'string') return false;
  const [s, k] = h.split(':'); const a = Buffer.from(k, 'hex'), b = crypto.scryptSync(pw, s, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const mac = body => crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
const sign = uid => { const body = Buffer.from(JSON.stringify({ uid, exp: Date.now() + 30 * 864e5 })).toString('base64url'); return body + '.' + mac(body); };
const verify = t => {
  const [body, sig] = String(t || '').split('.');
  if (!body || !sig) return null;
  const good = Buffer.from(mac(body)), got = Buffer.from(sig);
  if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p.uid : null; } catch { return null; }
};

/* ---------- validações e datas ---------- */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = v => { if (!UUID.test(String(v || ''))) throw new Err('Registro inválido.'); return String(v); };
const text = (v, label) => { const s = String(v ?? '').trim(); if (!s) throw new Err(`Preencha: ${label}.`); return s.slice(0, 200); };
const int = (v, label) => { const n = Number(v); if (v === '' || v == null || !Number.isInteger(n) || Math.abs(n) > 1e6) throw new Err(`Valor inválido: ${label}.`); return n; };
const emailOf = v => { const e = String(v || '').trim().toLowerCase(); if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw new Err('E-mail inválido.'); return e; };
const passOf = v => { const s = String(v || ''); if (s.length < 6) throw new Err('A senha precisa ter pelo menos 6 caracteres.'); return s; };
const dateOf = v => {
  const s = String(v || '');
  const t = /^\d{4}-\d{2}-\d{2}$/.test(s) ? new Date(s + 'T00:00:00Z') : null;
  if (!t || isNaN(t) || t.toISOString().slice(0, 10) !== s) throw new Err('Data inválida.'); // recusa 31/09, 30/02 etc.
  return s;
};
const ymOf = v => { const s = String(v || ''); if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(s)) throw new Err('Mês inválido.'); return s; };
const todayBR = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ });
const nextMonth = ym => { const [y, m] = ym.split('-').map(Number); return m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`; };
// validade: último dia do mês da conquista + 60 dias
const expiryOf = d => { const [y, m] = d.split('-').map(Number); const t = new Date(Date.UTC(y, m, 0)); t.setUTCDate(t.getUTCDate() + 60); return t.toISOString().slice(0, 10); };
const isClosed = async d => (await Q('select 1 from closings where month = $1', [d.slice(0, 7) + '-01'])).length > 0;
const dup = e => { if (e && e.code === '23505') throw new Err('Já existe um usuário com este e-mail.'); throw e; };
const needAdmin = ctx => { if (ctx.me.role !== 'admin') throw new Err('Apenas o administrador pode fazer isso.', 403); };
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

/* ---------- carteira de MC$ (com validade; consome as moedas mais antigas primeiro) ---------- */
function computeLots(events, asof) {
  events.sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : ((a.amt < 0) - (b.amt < 0)) || (a.c < b.c ? -1 : a.c > b.c ? 1 : 0)));
  const lots = [];
  for (const ev of events) {
    if (ev.amt > 0) { lots.push({ amount: ev.amt, expires: ev.exp }); continue; }
    let need = -ev.amt;
    for (const l of lots) {
      if (need <= 0) break;
      if (l.amount > 0 && l.expires >= ev.d) { const t = Math.min(l.amount, need); l.amount -= t; need -= t; }
    }
  }
  return lots.filter(l => l.amount > 0 && l.expires >= asof);
}
async function lotsMap(asof, ids) {
  const w = ids ? 'and teacher_id = any($2::uuid[])' : '';
  const p = ids ? [asof, ids] : [asof];
  const ls = await Q(`select teacher_id, occurred_on as d, points as amt, expires_on as exp, created_at as c from launches where occurred_on <= $1 ${w}`, p);
  const rs = await Q(`select teacher_id, (created_at at time zone '${TZ}')::date as d, -cost as amt, null::date as exp, created_at as c
    from redemptions where status <> 'rejected' and (created_at at time zone '${TZ}')::date <= $1 ${w}`, p);
  const by = {};
  for (const e of ls.concat(rs)) (by[e.teacher_id] = by[e.teacher_id] || []).push(e);
  const out = new Map();
  for (const id of ids || Object.keys(by)) out.set(id, computeLots(by[id] || [], asof));
  return out;
}
const sumLots = l => (l || []).reduce((s, x) => s + x.amount, 0);
const outLots = l => (l || []).map(x => ({ lot_amount: x.amount, lot_expires: x.expires })).sort((a, b) => a.lot_expires.localeCompare(b.lot_expires));
const balanceOf = async id => sumLots((await lotsMap(todayBR(), [id])).get(id));

async function ranking(ym) {
  const from = ym + '-01', to = nextMonth(ym);
  const teachers = await Q("select id, name from users where role = 'professor' and active order by name");
  const lm = await lotsMap(todayBR(), teachers.map(t => t.id));
  const ls = await Q(`select l.teacher_id, l.points, t.category from launches l join tasks t on t.id = l.task_id
    where l.occurred_on >= $1 and l.occurred_on < $2`, [from, to]);
  const rows = teachers.map(t => {
    const mine = ls.filter(l => l.teacher_id === t.id), cat = {};
    mine.forEach(l => { cat[l.category] = (cat[l.category] || 0) + l.points; });
    return {
      teacher_id: t.id, name: t.name, balance: sumLots(lm.get(t.id)),
      earned: mine.filter(l => l.points > 0).reduce((s, l) => s + l.points, 0),
      penalties: mine.filter(l => l.points < 0).reduce((s, l) => s + l.points, 0),
      by_category: cat,
    };
  });
  return rows.sort((a, b) => b.balance - a.balance || a.name.localeCompare(b.name));
}

/* ---------- ações públicas ---------- */
const PUBLIC = {
  async status() { return { setup: (await Q('select count(*)::int as n from users'))[0].n === 0 }; },

  async setup(p) {
    if ((await Q('select count(*)::int as n from users'))[0].n > 0) throw new Err('O sistema já foi configurado.');
    const u = (await Q("insert into users (name, email, role, password_hash) values ($1,$2,'admin',$3) returning *",
      [text(p.name, 'nome'), emailOf(p.email), hashPw(passOf(p.password))]))[0];
    for (const t of SEED_TASKS) await Q('insert into tasks (name, category, points) values ($1,$2,$3)', t);
    for (const r of SEED_REWARDS) await Q('insert into rewards (name, cost, stock) values ($1,$2,$3)', r);
    return { token: sign(u.id), me: pub(u) };
  },

  async login(p) {
    const u = (await Q('select * from users where lower(email) = lower($1)', [String(p.email || '').trim()]))[0];
    if (!u || !u.active || !checkPw(p.password, u.password_hash)) throw new Err('E-mail ou senha incorretos.', 401);
    return { token: sign(u.id), me: pub(u) };
  },
};

/* ---------- ações com login ---------- */
const A = {
  async me(ctx) { return pub(ctx.me); },

  async change_password(ctx, p) {
    const u = (await Q('select password_hash from users where id = $1', [ctx.me.id]))[0];
    if (!checkPw(p.current, u.password_hash)) throw new Err('Senha atual incorreta.');
    await Q('update users set password_hash = $1 where id = $2', [hashPw(passOf(p.next)), ctx.me.id]);
    return true;
  },

  /* painel */
  async dashboard(ctx, p) {
    const ym = ymOf(p.ym), from = ym + '-01', to = nextMonth(ym), adm = ctx.me.role === 'admin';
    const own = adm ? '' : 'and l.teacher_id = $1';
    const [rank, tasks, rewards, recent, pending, students, monthCount] = await Promise.all([
      ranking(ym),
      Q('select * from tasks where active order by category, points desc'),
      Q('select * from rewards where active order by cost'),
      Q(`select l.points, l.occurred_on, json_build_object('name', u.name) as teacher, json_build_object('name', t.name) as task,
          case when s.id is null then null else json_build_object('name', s.name) end as student
         from launches l join users u on u.id = l.teacher_id join tasks t on t.id = l.task_id left join students s on s.id = l.student_id
         where true ${own} order by l.created_at desc limit 6`, adm ? [] : [ctx.me.id]),
      Q(`select count(*)::int as n from redemptions where status = 'pending' ${adm ? '' : 'and teacher_id = $1'}`, adm ? [] : [ctx.me.id]),
      Q(`select id, label from students where active ${adm ? '' : 'and teacher_id = $1'}`, adm ? [] : [ctx.me.id]),
      Q(`select count(*)::int as n from launches l where l.occurred_on >= $${adm ? 1 : 2} and l.occurred_on < $${adm ? 2 : 3} ${own}`,
        adm ? [from, to] : [ctx.me.id, from, to]),
    ]);
    const out = { rank, tasks, rewards, recent, pending: pending[0].n, students, monthCount: monthCount[0].n };
    if (!adm) out.lots = outLots((await lotsMap(todayBR(), [ctx.me.id])).get(ctx.me.id));
    return out;
  },

  /* professores e administradores */
  async users(ctx) {
    needAdmin(ctx);
    const users = await Q('select id, name, email, role, active from users order by name');
    const lm = await lotsMap(todayBR(), users.filter(u => u.role === 'professor').map(u => u.id));
    const balances = {}; lm.forEach((v, k) => { balances[k] = sumLots(v); });
    return { users, balances };
  },
  async teachers(ctx) { needAdmin(ctx); return Q("select id, name from users where role = 'professor' and active order by name"); },
  async user_save(ctx, p) {
    needAdmin(ctx);
    const name = text(p.name, 'nome'), email = emailOf(p.email);
    const role = p.role === 'admin' ? 'admin' : 'professor';
    try {
      if (!p.id) {
        await Q('insert into users (name, email, role, password_hash) values ($1,$2,$3,$4)', [name, email, role, hashPw(passOf(p.password))]);
      } else {
        const id = uuid(p.id);
        if (id === ctx.me.id && role !== 'admin') throw new Err('Você não pode remover o seu próprio acesso de administrador.');
        await Q('update users set name = $1, email = $2, role = $3 where id = $4', [name, email, role, id]);
        if (p.password) await Q('update users set password_hash = $1 where id = $2', [hashPw(passOf(p.password)), id]);
      }
    } catch (e) { dup(e); }
    return true;
  },
  async user_toggle(ctx, p) {
    needAdmin(ctx);
    if (uuid(p.id) === ctx.me.id) throw new Err('Você não pode desativar o próprio acesso.');
    await Q('update users set active = not active where id = $1', [p.id]);
    return true;
  },

  /* alunos */
  async students(ctx) {
    const adm = ctx.me.role === 'admin';
    return Q(`select s.id, s.name, s.label, s.active, s.teacher_id, json_build_object('name', u.name) as teacher
      from students s join users u on u.id = s.teacher_id ${adm ? '' : 'where s.teacher_id = $1'} order by s.name`, adm ? [] : [ctx.me.id]);
  },
  async student_save(ctx, p) {
    needAdmin(ctx);
    const name = text(p.name, 'nome do aluno'), label = p.label === 'ONE TO ONE' ? 'ONE TO ONE' : 'PKZ', tid = uuid(p.teacher_id);
    if (!(await Q("select 1 from users where id = $1 and role = 'professor'", [tid])).length) throw new Err('Professor inválido.');
    if (p.id) await Q('update students set name = $1, label = $2, teacher_id = $3 where id = $4', [name, label, tid, uuid(p.id)]);
    else await Q('insert into students (name, label, teacher_id) values ($1,$2,$3)', [name, label, tid]);
    return true;
  },
  async student_toggle(ctx, p) { needAdmin(ctx); await Q('update students set active = not active where id = $1', [uuid(p.id)]); return true; },

  /* tarefas */
  async tasks(ctx) { needAdmin(ctx); return Q('select * from tasks order by category, points desc'); },
  async task_save(ctx, p) {
    needAdmin(ctx);
    const v = [text(p.name, 'nome'), text(p.category, 'categoria'), int(p.points, 'pontuação')];
    if (p.id) await Q('update tasks set name = $1, category = $2, points = $3 where id = $4', [...v, uuid(p.id)]);
    else await Q('insert into tasks (name, category, points) values ($1,$2,$3)', v);
    return true;
  },
  async task_toggle(ctx, p) { needAdmin(ctx); await Q('update tasks set active = not active where id = $1', [uuid(p.id)]); return true; },

  /* lançamentos */
  async launch_options(ctx) {
    needAdmin(ctx);
    const [teachers, tasks, students] = await Promise.all([
      Q("select id, name from users where role = 'professor' and active order by name"),
      Q('select id, name, category, points from tasks where active order by category, name'),
      Q('select id, name, label, teacher_id from students where active order by name'),
    ]);
    return { teachers, tasks, students };
  },
  async launches(ctx, p) {
    needAdmin(ctx);
    const ym = ymOf(p.ym);
    return Q(`select l.id, l.points, l.occurred_on, l.expires_on, l.note, json_build_object('name', u.name) as teacher,
        json_build_object('name', t.name) as task, case when s.id is null then null else json_build_object('name', s.name) end as student
      from launches l join users u on u.id = l.teacher_id join tasks t on t.id = l.task_id left join students s on s.id = l.student_id
      where l.occurred_on >= $1 and l.occurred_on < $2 order by l.occurred_on desc, l.created_at desc`, [ym + '-01', nextMonth(ym)]);
  },
  async launch_create(ctx, p) {
    needAdmin(ctx);
    const tid = uuid(p.teacher_id), date = dateOf(p.occurred_on);
    if (await isClosed(date)) throw new Err(`O mês ${date.slice(5, 7)}/${date.slice(0, 4)} já foi fechado. Reabra o mês em Relatórios para lançar.`);
    if (!(await Q("select 1 from users where id = $1 and role = 'professor' and active", [tid])).length) throw new Err('Professor inválido.');
    const task = (await Q('select points from tasks where id = $1', [uuid(p.task_id)]))[0];
    if (!task) throw new Err('Tarefa inválida.');
    let sid = null;
    if (p.student_id) {
      sid = uuid(p.student_id);
      const s = (await Q('select teacher_id from students where id = $1', [sid]))[0];
      if (!s || s.teacher_id !== tid) throw new Err('Esse aluno não pertence ao professor escolhido.');
    }
    const points = p.points === '' || p.points == null ? task.points : int(p.points, 'MC$');
    await Q(`insert into launches (teacher_id, task_id, student_id, points, occurred_on, expires_on, note, created_by)
      values ($1,$2,$3,$4,$5,$6,$7,$8)`, [tid, p.task_id, sid, points, date, expiryOf(date), String(p.note || '').trim().slice(0, 500) || null, ctx.me.id]);
    return true;
  },
  async launch_delete(ctx, p) {
    needAdmin(ctx);
    const l = (await Q('select occurred_on from launches where id = $1', [uuid(p.id)]))[0];
    if (!l) throw new Err('Lançamento não encontrado.');
    if (await isClosed(l.occurred_on)) throw new Err('Esse mês já foi fechado. Reabra o mês para excluir.');
    await Q('delete from launches where id = $1', [p.id]);
    return true;
  },

  /* recompensas e resgates */
  async rewards(ctx) {
    const adm = ctx.me.role === 'admin';
    const [rewards, redemptions] = await Promise.all([
      Q('select * from rewards order by cost'),
      Q(`select r.id, r.reward_name, r.cost, r.status, (r.created_at at time zone '${TZ}')::date as created_at,
          json_build_object('name', u.name) as teacher from redemptions r join users u on u.id = r.teacher_id
         ${adm ? '' : 'where r.teacher_id = $1'} order by r.created_at desc limit 60`, adm ? [] : [ctx.me.id]),
    ]);
    return { rewards, redemptions, balance: adm ? 0 : await balanceOf(ctx.me.id) };
  },
  async reward_save(ctx, p) {
    needAdmin(ctx);
    const name = text(p.name, 'nome'), cost = int(p.cost, 'valor'), stock = int(p.stock, 'estoque');
    if (cost < 1) throw new Err('O valor precisa ser maior que zero.');
    if (stock < 0) throw new Err('O estoque não pode ser negativo.');
    if (p.id) await Q('update rewards set name = $1, cost = $2, stock = $3 where id = $4', [name, cost, stock, uuid(p.id)]);
    else await Q('insert into rewards (name, cost, stock) values ($1,$2,$3)', [name, cost, stock]);
    return true;
  },
  async reward_toggle(ctx, p) { needAdmin(ctx); await Q('update rewards set active = not active where id = $1', [uuid(p.id)]); return true; },
  async redeem(ctx, p) {
    if (ctx.me.role !== 'professor') throw new Err('Apenas professores pedem resgates.');
    const rw = (await Q('select * from rewards where id = $1 and active', [uuid(p.reward_id)]))[0];
    if (!rw) throw new Err('Recompensa indisponível.');
    const pend = (await Q("select count(*)::int as n from redemptions where reward_id = $1 and status = 'pending'", [rw.id]))[0].n;
    if (rw.stock - pend <= 0) throw new Err('Recompensa sem estoque.');
    if ((await balanceOf(ctx.me.id)) < rw.cost) throw new Err('Saldo de MC$ insuficiente.');
    await Q('insert into redemptions (teacher_id, reward_id, reward_name, cost) values ($1,$2,$3,$4)', [ctx.me.id, rw.id, rw.name, rw.cost]);
    return true;
  },
  async approve(ctx, p) {
    needAdmin(ctx);
    const r = await Q(`with r as (
        update redemptions x set status = 'approved', decided_at = now()
        where x.id = $1 and x.status = 'pending' and exists (select 1 from rewards w where w.id = x.reward_id and w.stock > 0)
        returning x.reward_id)
      update rewards set stock = stock - 1 where id in (select reward_id from r) returning id`, [uuid(p.id)]);
    if (!r.length) throw new Err('Resgate inválido ou recompensa sem estoque.');
    return true;
  },
  async reject(ctx, p) {
    needAdmin(ctx);
    await Q("update redemptions set status = 'rejected', decided_at = now() where id = $1 and status = 'pending'", [uuid(p.id)]);
    return true;
  },

  /* extrato */
  async wallet(ctx, p) {
    const tid = ctx.me.role === 'admin' ? uuid(p.teacher_id) : ctx.me.id;
    const [lm, launches, redemptions] = await Promise.all([
      lotsMap(todayBR(), [tid]),
      Q(`select l.id, l.points, l.occurred_on, l.expires_on, json_build_object('name', t.name) as task
         from launches l join tasks t on t.id = l.task_id where l.teacher_id = $1 order by l.occurred_on desc, l.created_at desc limit 40`, [tid]),
      Q(`select id, reward_name, cost, status, (created_at at time zone '${TZ}')::date as created_at
         from redemptions where teacher_id = $1 order by created_at desc limit 20`, [tid]),
    ]);
    return { lots: outLots(lm.get(tid)), launches, redemptions };
  },

  /* relatórios e fechamento de mês */
  async reports(ctx, p) {
    needAdmin(ctx);
    const [rank, closings] = await Promise.all([
      ranking(ymOf(p.ym)),
      Q(`select month, (closed_at at time zone '${TZ}')::date as closed_at from closings order by month desc`),
    ]);
    return { rank, closings };
  },
  async close_month(ctx, p) {
    needAdmin(ctx);
    await Q('insert into closings (month, closed_by) values ($1,$2) on conflict do nothing', [ymOf(p.ym) + '-01', ctx.me.id]);
    return true;
  },
  async reopen_month(ctx, p) { needAdmin(ctx); await Q('delete from closings where month = $1', [ymOf(p.ym) + '-01']); return true; },
  async pdf_data(ctx, p) {
    needAdmin(ctx);
    const ym = ymOf(p.ym), from = ym + '-01', to = nextMonth(ym);
    const [rank, launches, redemptions, students, closing] = await Promise.all([
      ranking(ym),
      Q(`select l.points, l.teacher_id, json_build_object('name', t.name, 'category', t.category) as task
         from launches l join tasks t on t.id = l.task_id where l.occurred_on >= $1 and l.occurred_on < $2`, [from, to]),
      Q(`select r.teacher_id, r.reward_name, r.cost, (r.decided_at at time zone '${TZ}')::date as decided_at, json_build_object('name', u.name) as teacher
         from redemptions r join users u on u.id = r.teacher_id
         where r.status = 'approved' and (r.decided_at at time zone '${TZ}')::date >= $1 and (r.decided_at at time zone '${TZ}')::date < $2
         order by r.decided_at`, [from, to]),
      Q('select label, teacher_id from students where active'),
      Q(`select (closed_at at time zone '${TZ}')::date as closed_at from closings where month = $1`, [from]),
    ]);
    return { rank, launches, redemptions, students, closing: closing[0] || null };
  },
};

/* ---------- entrada da função ---------- */
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método inválido.' });
  try {
    if (!CONN) throw new Err('Banco de dados não conectado. No Vercel: Storage → conecte o banco ao projeto e faça um novo deploy.', 500);
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const params = body.params || {};
    await ensure();
    if (PUBLIC[body.action]) return res.status(200).json({ data: await PUBLIC[body.action](params) });
    const uid = verify(String(req.headers.authorization || '').replace(/^Bearer /, ''));
    const me = uid && UUID.test(uid) ? (await Q('select id, name, email, role, active from users where id = $1', [uid]))[0] : null;
    if (!me || !me.active) throw new Err('Sessão expirada. Entre novamente.', 401);
    if (!Object.prototype.hasOwnProperty.call(A, body.action)) throw new Err('Ação desconhecida.', 404);
    return res.status(200).json({ data: await A[body.action]({ me }, params) });
  } catch (e) {
    if (e instanceof Err) return res.status(e.status).json({ error: e.message });
    console.error(e);
    return res.status(500).json({ error: 'Erro no servidor: ' + e.message });
  }
};
