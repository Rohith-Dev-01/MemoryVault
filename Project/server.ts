import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import express, { type Request, type Response, type NextFunction } from 'express';
import { Pool } from 'pg';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);
const MEMORY_VAULT_FRONTEND = path.resolve(__dirname, 'MEMORY-VAULT', 'frontend');

// ============================================================================
// Supabase PostgreSQL Pool (via DATABASE_URL secret)
// ============================================================================
const rawDatabaseUrl = (process.env.DATABASE_URL || '').trim();

const pool = rawDatabaseUrl
  ? new Pool({
      connectionString: rawDatabaseUrl,
      ssl: { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    })
  : null;

function requirePool(res: Response): Pool | null {
  if (!pool) {
    res.status(500).json({
      success: false,
      error: 'DATABASE_URL is not configured. Add your Supabase Session Pooler URI in Settings → Secrets.',
    });
    return null;
  }
  return pool;
}

// ============================================================================
// Bcrypt Helpers (Compatible with pgcrypto $2a$, PHP $2y$, and bcryptjs $2a$)
// ============================================================================
function hashPassword(plain: string): string {
  return bcrypt.hashSync(plain, 10);
}

function verifyPassword(plain: string, storedHash: string): boolean {
  if (!storedHash) return false;
  // Normalize PHP's $2y$ prefix to $2a$ for bcryptjs compatibility
  const normalized = storedHash.replace(/^\$2y\$/, '$2a$');
  return bcrypt.compareSync(plain, normalized);
}

function cleanStr(val: unknown, maxLen = 500): string {
  const s = String(val ?? '').trim();
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ============================================================================
// Secure Cookie Sessions & CSRF Middleware
// ============================================================================
interface SessionData {
  id: string;
  role: 'user' | 'admin' | null;
  userId: number | null;
  adminId: number | null;
  csrfToken: string;
}

const sessions = new Map<string, SessionData>();

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function attachSession(req: Request, res: Response, next: NextFunction) {
  const cookies = parseCookies(req.headers.cookie);
  let sid = cookies['MV_SESSION'];
  let sess = sid ? sessions.get(sid) : undefined;

  if (!sess) {
    sid = crypto.randomBytes(24).toString('hex');
    sess = {
      id: sid,
      role: null,
      userId: null,
      adminId: null,
      csrfToken: crypto.randomBytes(32).toString('hex'),
    };
    sessions.set(sid, sess);
    res.setHeader(
      'Set-Cookie',
      `MV_SESSION=${sid}; Path=/; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=21600`
    );
  }

  (req as Request & { mvSession: SessionData }).mvSession = sess;
  next();
}

function getSession(req: Request): SessionData {
  return (req as Request & { mvSession: SessionData }).mvSession;
}

function verifyCsrf(req: Request, res: Response): boolean {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
  const sess = getSession(req);
  const headerToken = String(req.headers['x-csrf-token'] || '');
  if (!headerToken || !sess.csrfToken || headerToken.length !== sess.csrfToken.length) {
    res.status(401).json({
      success: false,
      code: 'CSRF_INVALID',
      error: 'Invalid or missing CSRF security token. Please refresh and try again.',
    });
    return false;
  }
  if (!crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(sess.csrfToken))) {
    res.status(401).json({ success: false, code: 'CSRF_INVALID', error: 'Invalid CSRF security token.' });
    return false;
  }
  return true;
}

function requireUserId(req: Request, res: Response): number | null {
  const sess = getSession(req);
  if (sess.role === 'admin' && sess.adminId) {
    res.status(401).json({
      success: false,
      code: 'ROLE_FORBIDDEN',
      error: 'Administrators cannot access Vault User endpoints. Use the Administrator Dashboard.',
      redirect: 'admin.html',
    });
    return null;
  }
  if (sess.role !== 'user' || !sess.userId) {
    res.status(401).json({
      success: false,
      code: 'UNAUTHENTICATED',
      error: 'Authentication required. Please sign in as a Vault User.',
      redirect: 'login.html',
    });
    return null;
  }
  return sess.userId;
}

function requireAdminId(req: Request, res: Response): number | null {
  const sess = getSession(req);
  if (sess.role === 'user' && sess.userId) {
    res.status(401).json({
      success: false,
      code: 'ROLE_FORBIDDEN',
      error: 'Access denied. Administrator role is required for this endpoint.',
      redirect: 'dashboard.html',
    });
    return null;
  }
  if (sess.role !== 'admin' || !sess.adminId) {
    res.status(401).json({
      success: false,
      code: 'UNAUTHENTICATED',
      error: 'Administrator authentication required. Please sign in as an Administrator.',
      redirect: 'login.html?role=admin',
    });
    return null;
  }
  return sess.adminId;
}

// ============================================================================
// Notification Logger & 4-Stage Inactivity Engine (Supabase PostgreSQL)
// ============================================================================
async function sendAndLogNotification(
  db: Pool,
  userId: number | null,
  recipientEmail: string,
  recipientRole: string,
  notificationType: string,
  subject: string,
  body: string,
  cycleId = '',
  preventDuplicate = false
): Promise<boolean> {
  const email = recipientEmail.trim().toLowerCase();

  if (preventDuplicate && userId !== null && cycleId !== '') {
    const dup = await db.query(
      `SELECT id FROM notification_logs
       WHERE user_id = $1 AND cycle_id = $2 AND notification_type = $3 AND LOWER(recipient_email) = $4
       LIMIT 1`,
      [userId, cycleId, notificationType, email]
    );
    if (dup.rowCount && dup.rowCount > 0) return false;
  }

  await db.query(
    `INSERT INTO notification_logs
       (user_id, recipient_email, recipient_role, notification_type, cycle_id, subject, body, delivery_status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [userId, email, recipientRole, notificationType, cycleId, subject, body, 'logged_demo_fallback']
  );

  return true;
}

async function evaluateInactivityForUser(db: Pool, userId: number) {
  const { rows } = await db.query(
    `SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in,
            u.escalation_stage, u.inactivity_cycle_id,
            FLOOR(EXTRACT(EPOCH FROM (NOW() - u.last_check_in)) / 86400)::INT AS days_inactive,
            COALESCE(lp.first_reminder_days, 30) AS first_days,
            COALESCE(lp.second_reminder_days, 35) AS second_days,
            COALESCE(lp.final_reminder_days, 40) AS final_days,
            COALESCE(lp.trusted_alert_days, 45) AS alert_days
     FROM users u
     LEFT JOIN legacy_plans lp ON lp.user_id = u.id
     WHERE u.id = $1
     LIMIT 1`,
    [userId]
  );

  const user = rows[0];
  if (!user) return { evaluated: false, triggered: [] };

  const daysInactive = Math.max(0, Number(user.days_inactive || 0));
  const currentStage = Number(user.escalation_stage || 0);
  const cycleId = String(user.inactivity_cycle_id || 'cycle_initial');
  let newStage = currentStage;
  const triggered: Array<{ stage: number; type: string; recipient: string; summary: string }> = [];

  if (daysInactive >= Number(user.first_days) && currentStage < 1) {
    const logged = await sendAndLogNotification(
      db,
      userId,
      user.email,
      'user',
      'day_30_reminder',
      'Memory Vault — First Activity Check-In Reminder (Day 30)',
      `Hello ${user.full_name},\n\nIt has been ${daysInactive} days since your last check-in on Memory Vault. Please sign in or click 'Check In Now' to confirm you are active.`,
      cycleId,
      true
    );
    newStage = Math.max(newStage, 1);
    if (logged) {
      triggered.push({
        stage: 1,
        type: 'day_30_reminder',
        recipient: user.email,
        summary: 'Day 30 first reminder sent to vault owner.',
      });
    }
  }

  if (daysInactive >= Number(user.second_days) && currentStage < 2) {
    const logged = await sendAndLogNotification(
      db,
      userId,
      user.email,
      'user',
      'day_35_reminder',
      'Memory Vault — Second Activity Check-In Reminder (Day 35)',
      `Hello ${user.full_name},\n\nThis is your second reminder (${daysInactive} days inactive). Please sign in to Memory Vault to reset your inactivity timer.`,
      cycleId,
      true
    );
    newStage = Math.max(newStage, 2);
    if (logged) {
      triggered.push({
        stage: 2,
        type: 'day_35_reminder',
        recipient: user.email,
        summary: 'Day 35 second reminder sent to vault owner.',
      });
    }
  }

  if (daysInactive >= Number(user.final_days) && currentStage < 3) {
    const logged = await sendAndLogNotification(
      db,
      userId,
      user.email,
      'user',
      'day_40_reminder',
      'Memory Vault — Final Activity Check-In Reminder (Day 40)',
      `Hello ${user.full_name},\n\nFinal reminder: your account has been inactive for ${daysInactive} days. At Day ${user.alert_days}, your trusted contacts will be asked to check on you.`,
      cycleId,
      true
    );
    newStage = Math.max(newStage, 3);
    if (logged) {
      triggered.push({
        stage: 3,
        type: 'day_40_reminder',
        recipient: user.email,
        summary: 'Day 40 final reminder sent to vault owner.',
      });
    }
  }

  if (daysInactive >= Number(user.alert_days) && currentStage < 4) {
    const { rows: contacts } = await db.query(
      `SELECT id, name, email, invitation_status
       FROM trusted_contacts
       WHERE user_id = $1 AND invitation_status != 'declined'`,
      [userId]
    );

    for (const contact of contacts) {
      const logged = await sendAndLogNotification(
        db,
        userId,
        contact.email,
        'trusted_contact',
        'day_45_trusted_alert',
        `Memory Vault Wellness Check — Please Check on ${user.full_name}`,
        `Hello ${contact.name},\n\n${user.full_name} listed you as a Trusted Contact on Memory Vault and has not checked in for ${daysInactive} days.\n\nIMPORTANT: Inactivity is NOT proof of death and no private vault records have been released.`,
        cycleId,
        true
      );
      if (logged) {
        triggered.push({
          stage: 4,
          type: 'day_45_trusted_alert',
          recipient: contact.email,
          summary: `Day 45 wellness alert sent to trusted contact ${contact.name} (${contact.email}).`,
        });
      }
    }

    if (contacts.length === 0) {
      const logged = await sendAndLogNotification(
        db,
        userId,
        user.email,
        'system',
        'day_45_no_contacts',
        'Memory Vault — Day 45 Escalation Reached (No Active Trusted Contacts)',
        `Account for ${user.full_name} reached Day ${daysInactive} of inactivity, but no active trusted contacts were configured.`,
        cycleId,
        true
      );
      if (logged) {
        triggered.push({
          stage: 4,
          type: 'day_45_no_contacts',
          recipient: user.email,
          summary: 'Day 45 reached; no active trusted contacts configured.',
        });
      }
    }

    newStage = Math.max(newStage, 4);
  }

  if (newStage !== currentStage) {
    await db.query(
      'UPDATE users SET escalation_stage = $1, updated_at = NOW() WHERE id = $2',
      [newStage, userId]
    );
  }

  return { evaluated: true, user_id: userId, days_inactive: daysInactive, stage: newStage, triggered };
}

async function buildDashboardPayload(db: Pool, userId: number) {
  const { rows: userRows } = await db.query(
    `SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in,
            u.escalation_stage, u.inactivity_cycle_id, u.created_at,
            FLOOR(EXTRACT(EPOCH FROM (NOW() - u.last_check_in)) / 86400)::INT AS days_inactive,
            COALESCE(lp.first_reminder_days, 30) AS first_reminder_days,
            COALESCE(lp.second_reminder_days, 35) AS second_reminder_days,
            COALESCE(lp.final_reminder_days, 40) AS final_reminder_days,
            COALESCE(lp.trusted_alert_days, 45) AS trusted_alert_days,
            COALESCE(lp.general_guidance, '') AS general_guidance
     FROM users u
     LEFT JOIN legacy_plans lp ON lp.user_id = u.id
     WHERE u.id = $1
     LIMIT 1`,
    [userId]
  );

  const user = userRows[0];
  if (!user) return null;

  const [aCnt, wCnt, cCnt, acCnt, mCnt, logsRes] = await Promise.all([
    db.query('SELECT COUNT(*)::INT AS c FROM digital_assets WHERE user_id = $1', [userId]),
    db.query('SELECT COUNT(*)::INT AS c FROM final_wishes WHERE user_id = $1', [userId]),
    db.query('SELECT COUNT(*)::INT AS c FROM trusted_contacts WHERE user_id = $1', [userId]),
    db.query("SELECT COUNT(*)::INT AS c FROM trusted_contacts WHERE user_id = $1 AND invitation_status = 'accepted'", [userId]),
    db.query('SELECT COUNT(*)::INT AS c FROM memories WHERE user_id = $1', [userId]),
    db.query(
      `SELECT id, recipient_email, recipient_role, notification_type, cycle_id, subject, body, delivery_status, created_at
       FROM notification_logs
       WHERE user_id = $1
       ORDER BY created_at DESC, id DESC
       LIMIT 15`,
      [userId]
    ),
  ]);

  const totalAssets = Number(aCnt.rows[0].c);
  const totalWishes = Number(wCnt.rows[0].c);
  const totalContacts = Number(cCnt.rows[0].c);
  const acceptedContacts = Number(acCnt.rows[0].c);
  const totalMemories = Number(mCnt.rows[0].c);

  const scoreAssets = totalAssets > 0 ? 25 : 0;
  const scoreWishes =
    totalAssets > 0 && totalWishes > 0
      ? Math.round(25 * Math.min(1, totalWishes / totalAssets))
      : 0;
  const scoreContacts = acceptedContacts > 0 ? 25 : totalContacts > 0 ? 15 : 0;
  const scoreMemories = totalMemories > 0 ? 25 : 0;
  const completionPct = Math.min(100, scoreAssets + scoreWishes + scoreContacts + scoreMemories);

  const daysInactive = Math.max(0, Number(user.days_inactive || 0));
  const stage = Number(user.escalation_stage || 0);
  const statusMap: Record<number, { label: string; tone: string }> = {
    0: { label: 'Active', tone: 'success' },
    1: { label: 'Day 30 — First Reminder Sent', tone: 'warning' },
    2: { label: 'Day 35 — Second Reminder Sent', tone: 'warning' },
    3: { label: 'Day 40 — Final Reminder Sent', tone: 'warning' },
    4: { label: 'Day 45+ — Trusted Contacts Notified', tone: 'error' },
  };
  const st = statusMap[stage] || statusMap[0];

  const nextOffsetDays =
    stage === 1
      ? Number(user.second_reminder_days)
      : stage === 2
      ? Number(user.final_reminder_days)
      : stage >= 3
      ? Number(user.trusted_alert_days)
      : Number(user.first_reminder_days);

  const nextReminderIso = new Date(
    new Date(user.last_check_in).getTime() + nextOffsetDays * 86400000
  ).toISOString();

  return {
    user: {
      id: Number(user.id),
      user_handle: user.user_handle,
      full_name: user.full_name,
      email: user.email,
      last_check_in: user.last_check_in,
      escalation_stage: stage,
    },
    metrics: {
      total_assets: totalAssets,
      total_wishes: totalWishes,
      total_contacts: totalContacts,
      accepted_contacts: acceptedContacts,
      total_memories: totalMemories,
      completion_percent: completionPct,
      days_inactive: daysInactive,
      last_check_in: user.last_check_in,
      next_reminder_date: nextReminderIso,
      status_label: st.label,
      status_tone: st.tone,
      escalation_stage: stage,
    },
    plan: {
      first_reminder_days: Number(user.first_reminder_days),
      second_reminder_days: Number(user.second_reminder_days),
      final_reminder_days: Number(user.final_reminder_days),
      trusted_alert_days: Number(user.trusted_alert_days),
      general_guidance: user.general_guidance,
    },
    recent_notifications: logsRes.rows,
  };
}

// ============================================================================
// Express Server & API Router
// ============================================================================
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(attachSession);

const apiRouter = express.Router();

// Health check endpoint (verifies live Supabase PostgreSQL connectivity)
apiRouter.get('/health', async (_req, res) => {
  const db = requirePool(res);
  if (!db) return;
  try {
    const r = await db.query('SELECT COUNT(*)::INT AS user_count FROM users');
    return res.json({
      success: true,
      database: 'supabase_postgresql_connected',
      users_in_db: r.rows[0].user_count,
    });
  } catch (err) {
    console.error('Supabase health check failed:', (err as Error).message);
    return res.status(500).json({
      success: false,
      error: 'Could not query Supabase tables. Verify DATABASE_URL and that supabase_schema.sql has been executed.',
    });
  }
});

// 1. auth / auth.php
apiRouter.all(['/auth.php', '/auth'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const action = String(req.query.action || '');
  const sess = getSession(req);

  try {
    if (req.method === 'GET' && (action === 'me' || action === '')) {
      let user = null;
      let admin = null;
      let role: 'user' | 'admin' | null = sess.role;

      if (role === 'user' && sess.userId) {
        const { rows } = await db.query(
          'SELECT id, user_handle, full_name, email, last_check_in, escalation_stage, created_at FROM users WHERE id = $1 LIMIT 1',
          [sess.userId]
        );
        user = rows[0] || null;
        if (!user) {
          sess.userId = null;
          sess.role = null;
          role = null;
        }
      } else if (role === 'admin' && sess.adminId) {
        const { rows } = await db.query(
          'SELECT id, full_name, email, role, created_at FROM admin_users WHERE id = $1 LIMIT 1',
          [sess.adminId]
        );
        admin = rows[0] || null;
        if (!admin) {
          sess.adminId = null;
          sess.role = null;
          role = null;
        }
      } else {
        role = null;
      }

      return res.json({
        success: true,
        role,
        authenticated: role === 'user' && Boolean(user),
        admin_authenticated: role === 'admin' && Boolean(admin),
        user,
        admin,
        csrf_token: sess.csrfToken,
      });
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ success: false, error: 'Method not allowed.' });
    }
    if (!verifyCsrf(req, res)) return;
    const body = req.body || {};

    if (action === 'register') {
      const requestedRole = cleanStr(body.role || 'user', 20).toLowerCase();
      if (requestedRole !== 'user') {
        return res.status(422).json({
          success: false,
          code: 'ROLE_RESTRICTED',
          error: 'Public registration is restricted to Vault User accounts. Administrators must sign in with provisioned credentials.',
        });
      }

      const userHandle = cleanStr(body.user_handle, 60);
      const fullName = cleanStr(body.full_name, 120);
      const email = cleanStr(body.email, 180).toLowerCase();
      const password = String(body.password || '');

      if (!/^[a-zA-Z0-9._-]{3,40}$/.test(userHandle)) {
        return res.status(422).json({
          success: false,
          error: 'User ID must be 3–40 characters (letters, numbers, dots, underscores, or hyphens).',
        });
      }
      if (fullName.length < 2) {
        return res.status(422).json({ success: false, error: 'Please enter your full name.' });
      }
      if (!isValidEmail(email)) {
        return res.status(422).json({ success: false, error: 'Please enter a valid email address.' });
      }
      if (password.length < 8) {
        return res.status(422).json({ success: false, error: 'Password must be at least 8 characters long.' });
      }

      const dup = await db.query(
        'SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($2) LIMIT 1',
        [email, userHandle]
      );
      if (dup.rowCount && dup.rowCount > 0) {
        return res.status(409).json({
          success: false,
          error: 'An account with that email or User ID already exists.',
        });
      }

      const dupAdmin = await db.query(
        'SELECT id FROM admin_users WHERE LOWER(email) = LOWER($1) LIMIT 1',
        [email]
      );
      if (dupAdmin.rowCount && dupAdmin.rowCount > 0) {
        return res.status(409).json({
          success: false,
          error: 'That email is reserved for an Administrator account.',
        });
      }

      const passwordHash = hashPassword(password);
      const cycleId = 'cycle_' + crypto.randomBytes(8).toString('hex');

      const client = await db.connect();
      let newUser;
      try {
        await client.query('BEGIN');
        const ins = await client.query(
          `INSERT INTO users (user_handle, full_name, email, password_hash, last_check_in, escalation_stage, inactivity_cycle_id)
           VALUES ($1, $2, $3, $4, NOW(), 0, $5)
           RETURNING id, user_handle, full_name, email, last_check_in, escalation_stage, created_at`,
          [userHandle, fullName, email, passwordHash, cycleId]
        );
        newUser = ins.rows[0];
        await client.query(
          `INSERT INTO legacy_plans (user_id, first_reminder_days, second_reminder_days, final_reminder_days, trusted_alert_days)
           VALUES ($1, 30, 35, 40, 45)`,
          [newUser.id]
        );
        await client.query('COMMIT');
      } catch (txErr) {
        await client.query('ROLLBACK');
        throw txErr;
      } finally {
        client.release();
      }

      sess.adminId = null;
      sess.role = 'user';
      sess.userId = Number(newUser.id);
      sess.csrfToken = crypto.randomBytes(32).toString('hex');

      return res.status(201).json({
        success: true,
        role: 'user',
        redirect: 'dashboard.html',
        message: 'Your Memory Vault account has been created in Supabase.',
        user: newUser,
        csrf_token: sess.csrfToken,
      });
    }

    if (action === 'login' || action === 'admin_login') {
      const role =
        action === 'admin_login'
          ? 'admin'
          : cleanStr(body.role || 'user', 20).toLowerCase();

      if (role !== 'user' && role !== 'admin') {
        return res.status(422).json({
          success: false,
          error: 'Please select a valid account role (Vault User or Administrator).',
        });
      }

      const identifier = cleanStr(body.identifier || body.email, 180);
      const password = String(body.password || '');
      if (!identifier || !password) {
        return res.status(422).json({
          success: false,
          error: 'Please enter both your account identifier and password.',
        });
      }

      // Role === 'admin': Strictly authenticate against admin_users
      if (role === 'admin') {
        const { rows } = await db.query(
          'SELECT id, full_name, email, password_hash, role, created_at FROM admin_users WHERE LOWER(email) = LOWER($1) LIMIT 1',
          [identifier]
        );
        const admin = rows[0];
        if (!admin) {
          const crossCheck = await db.query(
            'SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1) LIMIT 1',
            [identifier]
          );
          if (crossCheck.rowCount && crossCheck.rowCount > 0) {
            return res.status(401).json({
              success: false,
              code: 'ROLE_MISMATCH',
              error: 'This account is a Vault User, not an Administrator. Please switch the role selector to "Vault User" to sign in.',
            });
          }
          return res.status(401).json({ success: false, error: 'Invalid administrator email or password.' });
        }

        if (!verifyPassword(password, admin.password_hash)) {
          return res.status(401).json({ success: false, error: 'Invalid administrator email or password.' });
        }

        sess.userId = null;
        sess.role = 'admin';
        sess.adminId = Number(admin.id);
        sess.csrfToken = crypto.randomBytes(32).toString('hex');
        return res.json({
          success: true,
          role: 'admin',
          redirect: 'admin.html',
          message: 'Signed in as Administrator. Opening Verification Console…',
          admin: { id: admin.id, full_name: admin.full_name, email: admin.email, role: admin.role },
          csrf_token: sess.csrfToken,
        });
      }

      // Role === 'user': Strictly authenticate against users
      const { rows } = await db.query(
        `SELECT id, user_handle, full_name, email, password_hash, last_check_in, escalation_stage, created_at
         FROM users
         WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1)
         LIMIT 1`,
        [identifier]
      );
      const user = rows[0];
      if (!user) {
        const crossCheck = await db.query(
          'SELECT id FROM admin_users WHERE LOWER(email) = LOWER($1) LIMIT 1',
          [identifier]
        );
        if (crossCheck.rowCount && crossCheck.rowCount > 0) {
          return res.status(401).json({
            success: false,
            code: 'ROLE_MISMATCH',
            error: 'This account is an Administrator, not a Vault User. Please switch the role selector to "Administrator" to sign in.',
          });
        }
        return res.status(401).json({ success: false, error: 'Invalid email/User ID or password.' });
      }

      if (!verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ success: false, error: 'Invalid email/User ID or password.' });
      }

      const newCycle = 'cycle_' + crypto.randomBytes(8).toString('hex');
      const { rows: updatedRows } = await db.query(
        `UPDATE users
         SET last_check_in = NOW(), escalation_stage = 0, inactivity_cycle_id = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, user_handle, full_name, email, last_check_in, escalation_stage, created_at`,
        [newCycle, user.id]
      );

      sess.adminId = null;
      sess.role = 'user';
      sess.userId = Number(user.id);
      sess.csrfToken = crypto.randomBytes(32).toString('hex');

      return res.json({
        success: true,
        role: 'user',
        redirect: 'dashboard.html',
        message: 'Welcome back. Your activity check-in timer has been refreshed.',
        user: updatedRows[0],
        csrf_token: sess.csrfToken,
      });
    }

    if (action === 'logout' || action === 'admin_logout') {
      sess.userId = null;
      sess.adminId = null;
      sess.role = null;
      sess.csrfToken = crypto.randomBytes(32).toString('hex');
      return res.json({ success: true, message: 'Signed out safely.', csrf_token: sess.csrfToken });
    }

    return res.status(400).json({ success: false, error: 'Unknown authentication action.' });
  } catch (err) {
    console.error('Auth API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while processing authentication.' });
  }
});

// 2. dashboard / dashboard.php
apiRouter.all(['/dashboard.php', '/dashboard'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const userId = requireUserId(req, res);
  if (!userId) return;
  const action = String(req.query.action || '');

  try {
    if (req.method === 'GET') {
      const data = await buildDashboardPayload(db, userId);
      if (!data) return res.status(404).json({ success: false, error: 'User account not found.' });
      return res.json({ success: true, data });
    }

    if (req.method === 'POST') {
      if (!verifyCsrf(req, res)) return;

      if (action === 'checkin') {
        const newCycle = 'cycle_' + crypto.randomBytes(8).toString('hex');
        const { rows } = await db.query(
          `UPDATE users
           SET last_check_in = NOW(), escalation_stage = 0, inactivity_cycle_id = $1, updated_at = NOW()
           WHERE id = $2
           RETURNING email, full_name`,
          [newCycle, userId]
        );
        if (rows[0]) {
          await sendAndLogNotification(
            db,
            userId,
            rows[0].email,
            'user',
            'check_in_reset',
            'Memory Vault — Manual Check-In Confirmed',
            `Hello ${rows[0].full_name}, your manual check-in succeeded and reset your inactivity timer to Day 0.`,
            newCycle,
            false
          );
        }
        return res.json({
          success: true,
          message: 'Check-in confirmed. Your inactivity timer is reset to Active (Day 0).',
          data: await buildDashboardPayload(db, userId),
        });
      }

      if (action === 'simulate_inactivity') {
        const days = Number(req.body?.days || 0);
        if (![0, 30, 35, 40, 45, 46].includes(days)) {
          return res.status(422).json({ success: false, error: 'Allowed simulation values are 0, 30, 35, 40, or 45+ days.' });
        }

        if (days === 0) {
          const newCycle = 'cycle_' + crypto.randomBytes(8).toString('hex');
          await db.query(
            'UPDATE users SET last_check_in = NOW(), escalation_stage = 0, inactivity_cycle_id = $1, updated_at = NOW() WHERE id = $2',
            [newCycle, userId]
          );
          return res.json({
            success: true,
            message: 'Demo simulation reset to 0 days (Active).',
            triggered: [],
            data: await buildDashboardPayload(db, userId),
          });
        }

        const { rows: curRows } = await db.query(
          'SELECT escalation_stage, inactivity_cycle_id FROM users WHERE id = $1 LIMIT 1',
          [userId]
        );
        const cur = curRows[0];
        const targetStage = days >= 45 ? 4 : days >= 40 ? 3 : days >= 35 ? 2 : 1;
        let resetStage = Number(cur?.escalation_stage || 0);
        let cycleId = String(cur?.inactivity_cycle_id || 'cycle_initial');

        if (targetStage <= resetStage) {
          resetStage = 0;
          cycleId = 'sim_' + crypto.randomBytes(6).toString('hex');
        }

        await db.query(
          `UPDATE users
           SET last_check_in = NOW() - ($1::TEXT || ' days')::INTERVAL,
               escalation_stage = $2,
               inactivity_cycle_id = $3,
               updated_at = NOW()
           WHERE id = $4`,
          [days, resetStage, cycleId, userId]
        );

        const evalRes = await evaluateInactivityForUser(db, userId);
        return res.json({
          success: true,
          message: `Simulated ${days} days of inactivity and executed inactivity monitoring.`,
          triggered: evalRes.triggered,
          data: await buildDashboardPayload(db, userId),
        });
      }
    }

    return res.status(405).json({ success: false, error: 'Unsupported request.' });
  } catch (err) {
    console.error('Dashboard API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while loading dashboard.' });
  }
});

// 3. assets / assets.php
apiRouter.all(['/assets.php', '/assets'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const userId = requireUserId(req, res);
  if (!userId) return;

  try {
    if (req.method === 'GET') {
      const { rows } = await db.query(
        `SELECT a.id, a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                a.created_at, a.updated_at,
                w.id AS wish_id, w.action_type AS wish_action_type
         FROM digital_assets a
         LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
         WHERE a.user_id = $1
         ORDER BY a.created_at DESC, a.id DESC`,
        [userId]
      );
      return res.json({ success: true, assets: rows });
    }

    if (!verifyCsrf(req, res)) return;
    const body = req.body || {};

    if (body.password !== undefined || body.account_password !== undefined) {
      return res.status(422).json({
        success: false,
        error: 'Security Policy: Memory Vault never collects or stores third-party account passwords.',
      });
    }

    if (req.method === 'POST') {
      const assetName = cleanStr(body.asset_name, 140);
      const platform = cleanStr(body.platform, 100);
      const category = cleanStr(body.category, 80);
      const identifier = cleanStr(body.account_identifier, 180);
      const notes = cleanStr(body.notes, 1500);

      if (!assetName || !platform || !category || !identifier) {
        return res.status(422).json({ success: false, error: 'Asset name, platform, category, and account identifier are required.' });
      }

      const { rows } = await db.query(
        `INSERT INTO digital_assets (user_id, asset_name, platform, category, account_identifier, notes)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, asset_name, platform, category, account_identifier, notes, created_at, updated_at`,
        [userId, assetName, platform, category, identifier, notes]
      );
      return res.status(201).json({ success: true, message: 'Digital asset saved to Supabase.', asset: rows[0] });
    }

    if (req.method === 'PUT') {
      const id = Number(body.id || 0);
      const assetName = cleanStr(body.asset_name, 140);
      const platform = cleanStr(body.platform, 100);
      const category = cleanStr(body.category, 80);
      const identifier = cleanStr(body.account_identifier, 180);
      const notes = cleanStr(body.notes, 1500);

      if (id <= 0 || !assetName || !platform || !category || !identifier) {
        return res.status(422).json({ success: false, error: 'Valid asset ID and all required fields must be provided.' });
      }

      const { rows } = await db.query(
        `UPDATE digital_assets
         SET asset_name = $1, platform = $2, category = $3, account_identifier = $4, notes = $5, updated_at = NOW()
         WHERE id = $6 AND user_id = $7
         RETURNING id, asset_name, platform, category, account_identifier, notes, created_at, updated_at`,
        [assetName, platform, category, identifier, notes, id, userId]
      );
      if (!rows[0]) return res.status(404).json({ success: false, error: 'Digital asset not found.' });
      return res.json({ success: true, message: 'Digital asset updated.', asset: rows[0] });
    }

    if (req.method === 'DELETE') {
      const id = Number(req.query.id || body.id || 0);
      if (id <= 0) return res.status(422).json({ success: false, error: 'Valid asset ID is required.' });
      const result = await db.query('DELETE FROM digital_assets WHERE id = $1 AND user_id = $2', [id, userId]);
      if (!result.rowCount) return res.status(404).json({ success: false, error: 'Digital asset not found.' });
      return res.json({ success: true, message: 'Digital asset removed from your vault.' });
    }

    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  } catch (err) {
    console.error('Assets API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while managing digital assets.' });
  }
});

// 4. wishes / wishes.php
apiRouter.all(['/wishes.php', '/wishes'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const userId = requireUserId(req, res);
  if (!userId) return;

  const allowedActions = [
    'preserve_account',
    'preserve_memories',
    'share_information',
    'request_memorialization',
    'request_deletion',
  ];

  try {
    if (req.method === 'GET') {
      const [itemsRes, contactsRes] = await Promise.all([
        db.query(
          `SELECT a.id AS asset_id, a.asset_name, a.platform, a.category, a.account_identifier,
                  w.id AS wish_id, w.action_type, w.custom_instructions, w.assigned_contact_id,
                  w.updated_at AS wish_updated_at, tc.name AS assigned_contact_name
           FROM digital_assets a
           LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
           LEFT JOIN trusted_contacts tc ON tc.id = w.assigned_contact_id AND tc.user_id = a.user_id
           WHERE a.user_id = $1
           ORDER BY a.created_at DESC, a.id DESC`,
          [userId]
        ),
        db.query(
          'SELECT id, name, email, relationship, invitation_status FROM trusted_contacts WHERE user_id = $1 ORDER BY name ASC',
          [userId]
        ),
      ]);
      return res.json({ success: true, items: itemsRes.rows, contacts: contactsRes.rows });
    }

    if (!verifyCsrf(req, res)) return;
    const body = req.body || {};

    if (req.method === 'POST' || req.method === 'PUT') {
      const assetId = Number(body.asset_id || 0);
      const actionType = cleanStr(body.action_type, 60);
      const customInstr = cleanStr(body.custom_instructions, 2500);
      const assignedContactId = body.assigned_contact_id ? Number(body.assigned_contact_id) : null;

      if (assetId <= 0 || !allowedActions.includes(actionType)) {
        return res.status(422).json({ success: false, error: 'Please select a valid digital asset and final wish.' });
      }

      const ownAsset = await db.query('SELECT id FROM digital_assets WHERE id = $1 AND user_id = $2 LIMIT 1', [assetId, userId]);
      if (!ownAsset.rowCount) return res.status(404).json({ success: false, error: 'Digital asset not found.' });

      if (assignedContactId !== null) {
        const ownContact = await db.query('SELECT id FROM trusted_contacts WHERE id = $1 AND user_id = $2 LIMIT 1', [assignedContactId, userId]);
        if (!ownContact.rowCount) return res.status(422).json({ success: false, error: 'Selected trusted contact was not found.' });
      }

      const { rows } = await db.query(
        `INSERT INTO final_wishes (user_id, asset_id, assigned_contact_id, action_type, custom_instructions)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (asset_id) DO UPDATE
         SET assigned_contact_id = EXCLUDED.assigned_contact_id,
             action_type = EXCLUDED.action_type,
             custom_instructions = EXCLUDED.custom_instructions,
             updated_at = NOW()
         WHERE final_wishes.user_id = $1
         RETURNING id, asset_id, assigned_contact_id, action_type, custom_instructions, updated_at`,
        [userId, assetId, assignedContactId, actionType, customInstr]
      );
      return res.json({ success: true, message: 'Final wish instructions saved.', wish: rows[0] });
    }

    if (req.method === 'DELETE') {
      const id = Number(req.query.id || body.id || 0);
      if (id <= 0) return res.status(422).json({ success: false, error: 'Valid wish ID is required.' });
      const r = await db.query('DELETE FROM final_wishes WHERE id = $1 AND user_id = $2', [id, userId]);
      if (!r.rowCount) return res.status(404).json({ success: false, error: 'Final wish not found.' });
      return res.json({ success: true, message: 'Final wish removed.' });
    }

    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  } catch (err) {
    console.error('Wishes API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while saving final wishes.' });
  }
});

// 5. contacts / contacts.php
apiRouter.all(['/contacts.php', '/contacts'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const action = String(req.query.action || '');

  try {
    // Public Invitation Lookup
    if (req.method === 'GET' && action === 'invitation') {
      const token = cleanStr(req.query.token, 80);
      if (!token) return res.status(422).json({ success: false, error: 'Invitation token is required.' });

      const { rows } = await db.query(
        `SELECT tc.id, tc.name, tc.email, tc.relationship, tc.invitation_status, tc.responded_at,
                u.full_name AS owner_name, u.user_handle AS owner_handle
         FROM trusted_contacts tc
         JOIN users u ON u.id = tc.user_id
         WHERE tc.invitation_token = $1
         LIMIT 1`,
        [token]
      );
      if (!rows[0]) return res.status(404).json({ success: false, error: 'Invitation link is invalid or expired.' });
      return res.json({ success: true, invitation: rows[0] });
    }

    // Public Invitation Response
    if (req.method === 'POST' && action === 'respond_invitation') {
      if (!verifyCsrf(req, res)) return;
      const token = cleanStr(req.body?.token, 80);
      const decision = cleanStr(req.body?.decision, 20);
      if (!token || !['accepted', 'declined'].includes(decision)) {
        return res.status(422).json({ success: false, error: 'Valid token and decision are required.' });
      }

      const { rows } = await db.query(
        `UPDATE trusted_contacts
         SET invitation_status = $1, responded_at = NOW(), updated_at = NOW()
         WHERE invitation_token = $2
         RETURNING id, user_id, name, email, invitation_status, responded_at`,
        [decision, token]
      );
      const updated = rows[0];
      if (!updated) return res.status(404).json({ success: false, error: 'Invitation not found.' });

      const ownerRes = await db.query('SELECT email, full_name FROM users WHERE id = $1 LIMIT 1', [updated.user_id]);
      if (ownerRes.rows[0]) {
        await sendAndLogNotification(
          db,
          Number(updated.user_id),
          ownerRes.rows[0].email,
          'user',
          `invitation_${decision}`,
          `Trusted Contact ${updated.name} ${decision} your invitation`,
          `Hello ${ownerRes.rows[0].full_name}, ${updated.name} (${updated.email}) has ${decision} your Trusted Contact invitation.`,
          '',
          false
        );
      }
      return res.json({
        success: true,
        message: `Invitation marked as ${decision}. Private vault data remains protected.`,
        invitation: updated,
      });
    }

    const userId = requireUserId(req, res);
    if (!userId) return;

    if (req.method === 'GET') {
      const { rows } = await db.query(
        `SELECT id, name, email, phone, relationship, invitation_token, invitation_status,
                responded_at, created_at, updated_at
         FROM trusted_contacts
         WHERE user_id = $1
         ORDER BY created_at DESC, id DESC`,
        [userId]
      );
      return res.json({ success: true, contacts: rows });
    }

    if (!verifyCsrf(req, res)) return;
    const body = req.body || {};

    if (req.method === 'POST') {
      const name = cleanStr(body.name, 120);
      const email = cleanStr(body.email, 180).toLowerCase();
      const phone = cleanStr(body.phone, 40);
      const relationship = cleanStr(body.relationship, 80);

      if (!name || !isValidEmail(email) || !relationship) {
        return res.status(422).json({ success: false, error: 'Name, valid email address, and relationship are required.' });
      }

      const dup = await db.query(
        'SELECT id FROM trusted_contacts WHERE user_id = $1 AND LOWER(email) = LOWER($2) LIMIT 1',
        [userId, email]
      );
      if (dup.rowCount && dup.rowCount > 0) {
        return res.status(409).json({ success: false, error: 'This email is already registered among your trusted contacts.' });
      }

      const token = 'mv_inv_' + crypto.randomBytes(12).toString('hex');
      const { rows } = await db.query(
        `INSERT INTO trusted_contacts (user_id, name, email, phone, relationship, invitation_token, invitation_status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending')
         RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at, created_at`,
        [userId, name, email, phone, relationship, token]
      );

      const ownerRes = await db.query('SELECT full_name FROM users WHERE id = $1 LIMIT 1', [userId]);
      const ownerName = ownerRes.rows[0]?.full_name || 'A Memory Vault user';
      await sendAndLogNotification(
        db,
        userId,
        email,
        'trusted_contact',
        'contact_invitation',
        `${ownerName} invited you as a Trusted Contact on Memory Vault`,
        `Hello ${name}, ${ownerName} has designated you as a Trusted Contact (${relationship}). Invitation token: ${token}.`,
        '',
        false
      );

      return res.status(201).json({ success: true, message: 'Trusted contact invited.', contact: rows[0] });
    }

    if (req.method === 'PUT') {
      const id = Number(body.id || 0);
      if (id <= 0) return res.status(422).json({ success: false, error: 'Valid contact ID is required.' });

      if (body.action === 'simulate_status') {
        const status = cleanStr(body.invitation_status, 20);
        if (!['pending', 'accepted', 'declined'].includes(status)) {
          return res.status(422).json({ success: false, error: 'Status must be pending, accepted, or declined.' });
        }
        const { rows } = await db.query(
          `UPDATE trusted_contacts
           SET invitation_status = $1,
               responded_at = CASE WHEN $1 = 'pending' THEN NULL ELSE NOW() END,
               updated_at = NOW()
           WHERE id = $2 AND user_id = $3
           RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at`,
          [status, id, userId]
        );
        if (!rows[0]) return res.status(404).json({ success: false, error: 'Trusted contact not found.' });
        return res.json({
          success: true,
          message: `Invitation status updated to ${status}. Private vault data remains protected.`,
          contact: rows[0],
        });
      }

      const name = cleanStr(body.name, 120);
      const email = cleanStr(body.email, 180).toLowerCase();
      const phone = cleanStr(body.phone, 40);
      const relationship = cleanStr(body.relationship, 80);
      if (!name || !isValidEmail(email) || !relationship) {
        return res.status(422).json({ success: false, error: 'Name, valid email address, and relationship are required.' });
      }

      const { rows } = await db.query(
        `UPDATE trusted_contacts
         SET name = $1, email = $2, phone = $3, relationship = $4, updated_at = NOW()
         WHERE id = $5 AND user_id = $6
         RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at`,
        [name, email, phone, relationship, id, userId]
      );
      if (!rows[0]) return res.status(404).json({ success: false, error: 'Trusted contact not found.' });
      return res.json({ success: true, message: 'Trusted contact updated.', contact: rows[0] });
    }

    if (req.method === 'DELETE') {
      const id = Number(req.query.id || body.id || 0);
      if (id <= 0) return res.status(422).json({ success: false, error: 'Valid contact ID is required.' });
      const r = await db.query('DELETE FROM trusted_contacts WHERE id = $1 AND user_id = $2', [id, userId]);
      if (!r.rowCount) return res.status(404).json({ success: false, error: 'Trusted contact not found.' });
      return res.json({ success: true, message: 'Trusted contact removed.' });
    }

    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  } catch (err) {
    console.error('Contacts API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while managing trusted contacts.' });
  }
});

// 6. memories / memories.php
apiRouter.all(['/memories.php', '/memories'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const userId = requireUserId(req, res);
  if (!userId) return;

  try {
    if (req.method === 'GET') {
      const [memRes, contactsRes] = await Promise.all([
        db.query(
          `SELECT m.id, m.title, m.message_body, m.trusted_contact_id, m.custom_recipient,
                  m.release_condition, m.created_at, m.updated_at,
                  tc.name AS contact_name, tc.email AS contact_email, tc.relationship AS contact_relationship
           FROM memories m
           LEFT JOIN trusted_contacts tc ON tc.id = m.trusted_contact_id AND tc.user_id = m.user_id
           WHERE m.user_id = $1
           ORDER BY m.created_at DESC, m.id DESC`,
          [userId]
        ),
        db.query(
          'SELECT id, name, email, relationship, invitation_status FROM trusted_contacts WHERE user_id = $1 ORDER BY name ASC',
          [userId]
        ),
      ]);
      return res.json({ success: true, memories: memRes.rows, contacts: contactsRes.rows });
    }

    if (!verifyCsrf(req, res)) return;
    const body = req.body || {};

    if (req.method === 'POST') {
      const title = cleanStr(body.title, 180);
      const msgBody = cleanStr(body.message_body, 10000);
      const contactId = body.trusted_contact_id ? Number(body.trusted_contact_id) : null;
      const customRecipient = cleanStr(body.custom_recipient, 140);
      const releaseCond = cleanStr(body.release_condition || 'Upon verified admin approval', 120);

      if (!title || !msgBody || (contactId === null && !customRecipient)) {
        return res.status(422).json({ success: false, error: 'Title, message body, and a recipient are required.' });
      }

      if (contactId !== null) {
        const chk = await db.query('SELECT id FROM trusted_contacts WHERE id = $1 AND user_id = $2 LIMIT 1', [contactId, userId]);
        if (!chk.rowCount) return res.status(422).json({ success: false, error: 'Selected trusted contact was not found.' });
      }

      const { rows } = await db.query(
        `INSERT INTO memories (user_id, trusted_contact_id, custom_recipient, title, message_body, release_condition)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, trusted_contact_id, custom_recipient, title, message_body, release_condition, created_at, updated_at`,
        [userId, contactId, customRecipient, title, msgBody, releaseCond]
      );
      return res.status(201).json({ success: true, message: 'Letter preserved in your vault.', memory: rows[0] });
    }

    if (req.method === 'PUT') {
      const id = Number(body.id || 0);
      const title = cleanStr(body.title, 180);
      const msgBody = cleanStr(body.message_body, 10000);
      const contactId = body.trusted_contact_id ? Number(body.trusted_contact_id) : null;
      const customRecipient = cleanStr(body.custom_recipient, 140);
      const releaseCond = cleanStr(body.release_condition || 'Upon verified admin approval', 120);

      if (id <= 0 || !title || !msgBody || (contactId === null && !customRecipient)) {
        return res.status(422).json({ success: false, error: 'Valid memory ID, title, message body, and recipient are required.' });
      }

      if (contactId !== null) {
        const chk = await db.query('SELECT id FROM trusted_contacts WHERE id = $1 AND user_id = $2 LIMIT 1', [contactId, userId]);
        if (!chk.rowCount) return res.status(422).json({ success: false, error: 'Selected trusted contact was not found.' });
      }

      const { rows } = await db.query(
        `UPDATE memories
         SET trusted_contact_id = $1, custom_recipient = $2, title = $3, message_body = $4, release_condition = $5, updated_at = NOW()
         WHERE id = $6 AND user_id = $7
         RETURNING id, trusted_contact_id, custom_recipient, title, message_body, release_condition, created_at, updated_at`,
        [contactId, customRecipient, title, msgBody, releaseCond, id, userId]
      );
      if (!rows[0]) return res.status(404).json({ success: false, error: 'Memory not found.' });
      return res.json({ success: true, message: 'Letter updated.', memory: rows[0] });
    }

    if (req.method === 'DELETE') {
      const id = Number(req.query.id || body.id || 0);
      if (id <= 0) return res.status(422).json({ success: false, error: 'Valid memory ID is required.' });
      const r = await db.query('DELETE FROM memories WHERE id = $1 AND user_id = $2', [id, userId]);
      if (!r.rowCount) return res.status(404).json({ success: false, error: 'Memory not found.' });
      return res.json({ success: true, message: 'Letter deleted from vault.' });
    }

    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  } catch (err) {
    console.error('Memories API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while managing memories.' });
  }
});

// 7. legacy_requests / legacy_requests.php
apiRouter.all(['/legacy_requests.php', '/legacy_requests'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const action = String(req.query.action || '');

  try {
    if (req.method === 'GET' && action === 'summary') {
      const userId = requireUserId(req, res);
      if (!userId) return;

      const [uRes, aRes, cRes, mRes] = await Promise.all([
        db.query(
          `SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in, u.escalation_stage, u.created_at,
                  COALESCE(lp.first_reminder_days, 30) AS first_reminder_days,
                  COALESCE(lp.second_reminder_days, 35) AS second_reminder_days,
                  COALESCE(lp.final_reminder_days, 40) AS final_reminder_days,
                  COALESCE(lp.trusted_alert_days, 45) AS trusted_alert_days,
                  COALESCE(lp.general_guidance, '') AS general_guidance
           FROM users u
           LEFT JOIN legacy_plans lp ON lp.user_id = u.id
           WHERE u.id = $1 LIMIT 1`,
          [userId]
        ),
        db.query(
          `SELECT a.id, a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                  w.action_type, w.custom_instructions, tc.name AS assigned_contact_name
           FROM digital_assets a
           LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
           LEFT JOIN trusted_contacts tc ON tc.id = w.assigned_contact_id AND tc.user_id = a.user_id
           WHERE a.user_id = $1 ORDER BY a.id ASC`,
          [userId]
        ),
        db.query(
          'SELECT id, name, email, phone, relationship, invitation_status, responded_at FROM trusted_contacts WHERE user_id = $1 ORDER BY id ASC',
          [userId]
        ),
        db.query(
          `SELECT m.id, m.title, m.message_body, m.custom_recipient, m.release_condition, m.created_at,
                  tc.name AS contact_name, tc.relationship AS contact_relationship
           FROM memories m
           LEFT JOIN trusted_contacts tc ON tc.id = m.trusted_contact_id AND tc.user_id = m.user_id
           WHERE m.user_id = $1 ORDER BY m.id ASC`,
          [userId]
        ),
      ]);

      return res.json({
        success: true,
        summary: {
          generated_at: new Date().toISOString(),
          user: uRes.rows[0],
          assets: aRes.rows,
          contacts: cRes.rows,
          memories: mRes.rows,
        },
      });
    }

    if (req.method === 'GET' && action === 'lookup') {
      const contactEmail = cleanStr(req.query.contact_email, 180).toLowerCase();
      const ownerIdentifier = cleanStr(req.query.owner_identifier, 180);
      if (!isValidEmail(contactEmail) || !ownerIdentifier) {
        return res.status(422).json({ success: false, error: 'Please enter your trusted contact email and the vault owner email or User ID.' });
      }

      const ownerRes = await db.query(
        'SELECT id, full_name, user_handle, email FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1) LIMIT 1',
        [ownerIdentifier]
      );
      const owner = ownerRes.rows[0];
      if (!owner) return res.status(404).json({ success: false, error: 'No matching request records found for those details.' });

      const { rows: requests } = await db.query(
        `SELECT lr.id, lr.request_code, lr.status, lr.reason, lr.verification_note,
                lr.admin_remarks, lr.created_at, lr.reviewed_at, lr.trusted_contact_id,
                tc.name AS contact_name, tc.relationship
         FROM legacy_requests lr
         JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id
         WHERE lr.user_id = $1 AND LOWER(lr.requester_email) = LOWER($2)
         ORDER BY lr.created_at DESC, lr.id DESC`,
        [owner.id, contactEmail]
      );

      const enriched = [];
      for (const reqRow of requests) {
        let authorizedMemories: unknown[] = [];
        let authorizedWishes: unknown[] = [];
        if (reqRow.status === 'approved') {
          const [mRes, wRes] = await Promise.all([
            db.query(
              `SELECT id, title, message_body, custom_recipient, release_condition, created_at
               FROM memories WHERE user_id = $1 AND trusted_contact_id = $2 ORDER BY id ASC`,
              [owner.id, reqRow.trusted_contact_id]
            ),
            db.query(
              `SELECT a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                      w.action_type, w.custom_instructions
               FROM final_wishes w
               JOIN digital_assets a ON a.id = w.asset_id
               WHERE w.user_id = $1 AND w.assigned_contact_id = $2 ORDER BY a.id ASC`,
              [owner.id, reqRow.trusted_contact_id]
            ),
          ]);
          authorizedMemories = mRes.rows;
          authorizedWishes = wRes.rows;
        }
        enriched.push({
          ...reqRow,
          authorized_memories: authorizedMemories,
          authorized_wishes: authorizedWishes,
        });
      }

      return res.json({
        success: true,
        owner: { full_name: owner.full_name, user_handle: owner.user_handle },
        requests: enriched,
      });
    }

    if (req.method === 'POST' && action === 'submit') {
      if (!verifyCsrf(req, res)) return;
      const body = req.body || {};
      const contactEmail = cleanStr(body.contact_email, 180).toLowerCase();
      const ownerIdentifier = cleanStr(body.owner_identifier, 180);
      const reason = cleanStr(body.reason, 200);
      const verificationNote = cleanStr(body.verification_note, 2500);

      if (!isValidEmail(contactEmail) || !ownerIdentifier || !reason || verificationNote.length < 10) {
        return res.status(422).json({
          success: false,
          error: 'Please enter all fields and a verification note of at least 10 characters.',
        });
      }

      const ownerRes = await db.query(
        'SELECT id, full_name, email FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1) LIMIT 1',
        [ownerIdentifier]
      );
      const owner = ownerRes.rows[0];
      if (!owner) return res.status(404).json({ success: false, error: 'We could not verify that vault owner and trusted contact combination.' });

      const tcRes = await db.query(
        'SELECT id, name, email, invitation_status FROM trusted_contacts WHERE user_id = $1 AND LOWER(email) = LOWER($2) LIMIT 1',
        [owner.id, contactEmail]
      );
      const contact = tcRes.rows[0];
      if (!contact) {
        return res.status(422).json({
          success: false,
          error: 'Only registered Trusted Contacts of the vault owner may submit a legacy access request.',
        });
      }
      if (contact.invitation_status === 'declined') {
        return res.status(422).json({ success: false, error: 'Declined contacts cannot submit access requests.' });
      }

      const pendingRes = await db.query(
        "SELECT id, request_code FROM legacy_requests WHERE user_id = $1 AND trusted_contact_id = $2 AND status = 'pending' LIMIT 1",
        [owner.id, contact.id]
      );
      if (pendingRes.rows[0]) {
        return res.status(409).json({
          success: false,
          error: `A pending request (${pendingRes.rows[0].request_code}) is already awaiting administrative review.`,
        });
      }

      const requestCode = `REQ-${new Date().getUTCFullYear()}-${crypto.randomInt(1000, 9999)}`;
      const ins = await db.query(
        `INSERT INTO legacy_requests (request_code, user_id, trusted_contact_id, requester_email, reason, verification_note, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending')
         RETURNING id, request_code, status, reason, verification_note, created_at`,
        [requestCode, owner.id, contact.id, contactEmail, reason, verificationNote]
      );

      await sendAndLogNotification(
        db,
        Number(owner.id),
        contactEmail,
        'trusted_contact',
        'legacy_request_submitted',
        `Legacy Access Request Received (${requestCode})`,
        `Hello ${contact.name}, your Legacy Access Request (${requestCode}) for ${owner.full_name}'s vault is PENDING administrative review.`,
        '',
        false
      );

      return res.status(201).json({
        success: true,
        message: `Request ${requestCode} submitted for administrative verification. Private data remains locked until explicit admin approval.`,
        request: ins.rows[0],
      });
    }

    return res.status(400).json({ success: false, error: 'Unsupported request.' });
  } catch (err) {
    console.error('Legacy requests API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while processing legacy request.' });
  }
});

// 8. admin / admin.php
apiRouter.all(['/admin.php', '/admin'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const adminId = requireAdminId(req, res);
  if (!adminId) return;
  const action = String(req.query.action || '');

  try {
    if (req.method === 'GET') {
      const statusFilter = ['all', 'pending', 'approved', 'rejected'].includes(String(req.query.status || 'all'))
        ? String(req.query.status || 'all')
        : 'all';

      const [adminRes, countsRes, usersRes, notifsCntRes, auditRes, notifsRes] = await Promise.all([
        db.query('SELECT id, full_name, email, role FROM admin_users WHERE id = $1 LIMIT 1', [adminId]),
        db.query('SELECT status, COUNT(*)::INT AS cnt FROM legacy_requests GROUP BY status'),
        db.query('SELECT COUNT(*)::INT AS cnt FROM users'),
        db.query('SELECT COUNT(*)::INT AS cnt FROM notification_logs'),
        db.query(
          `SELECT al.id, al.action, al.remarks, al.created_at,
                  au.full_name AS admin_name, au.email AS admin_email, lr.request_code
           FROM admin_action_logs al
           JOIN admin_users au ON au.id = al.admin_id
           LEFT JOIN legacy_requests lr ON lr.id = al.legacy_request_id
           ORDER BY al.created_at DESC, al.id DESC
           LIMIT 20`
        ),
        db.query(
          `SELECT id, recipient_email, recipient_role, notification_type, subject, delivery_status, created_at
           FROM notification_logs
           ORDER BY created_at DESC, id DESC
           LIMIT 15`
        ),
      ]);

      const counts: Record<string, number> = { pending: 0, approved: 0, rejected: 0 };
      for (const row of countsRes.rows) counts[row.status] = Number(row.cnt);

      let sql = `SELECT lr.id, lr.request_code, lr.status, lr.reason, lr.verification_note,
                        lr.admin_remarks, lr.created_at, lr.reviewed_at,
                        u.full_name AS owner_name, u.email AS owner_email, u.user_handle AS owner_handle,
                        u.last_check_in AS owner_last_check_in, u.escalation_stage AS owner_escalation_stage,
                        FLOOR(EXTRACT(EPOCH FROM (NOW() - u.last_check_in)) / 86400)::INT AS owner_days_inactive,
                        tc.name AS contact_name, tc.email AS contact_email, tc.phone AS contact_phone,
                        tc.relationship AS contact_relationship, tc.invitation_status AS contact_invitation_status,
                        au.full_name AS reviewer_name,
                        (SELECT COUNT(*)::INT FROM memories m WHERE m.user_id = lr.user_id AND m.trusted_contact_id = lr.trusted_contact_id) AS authorized_memories_count,
                        (SELECT COUNT(*)::INT FROM final_wishes fw WHERE fw.user_id = lr.user_id AND fw.assigned_contact_id = lr.trusted_contact_id) AS authorized_wishes_count
                 FROM legacy_requests lr
                 JOIN users u ON u.id = lr.user_id
                 JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id
                 LEFT JOIN admin_users au ON au.id = lr.reviewed_by`;
      const params: unknown[] = [];
      if (statusFilter !== 'all') {
        sql += ' WHERE lr.status = $1';
        params.push(statusFilter);
      }
      sql += " ORDER BY CASE WHEN lr.status = 'pending' THEN 0 ELSE 1 END, lr.created_at DESC, lr.id DESC";

      const reqsRes = await db.query(sql, params);

      return res.json({
        success: true,
        admin: adminRes.rows[0],
        stats: {
          pending: counts.pending,
          approved: counts.approved,
          rejected: counts.rejected,
          total_users: Number(usersRes.rows[0].cnt),
          total_notifications: Number(notifsCntRes.rows[0].cnt),
        },
        requests: reqsRes.rows,
        audit_logs: auditRes.rows,
        notifications: notifsRes.rows,
      });
    }

    if (req.method === 'POST' && action === 'review') {
      if (!verifyCsrf(req, res)) return;
      const requestId = Number(req.body?.request_id || 0);
      const decision = cleanStr(req.body?.decision, 20);
      const remarks = cleanStr(req.body?.admin_remarks, 2000);

      if (requestId <= 0 || !['approved', 'rejected'].includes(decision) || remarks.length < 4) {
        return res.status(422).json({
          success: false,
          error: 'Valid request ID, decision (approved/rejected), and remarks (minimum 4 characters) are required.',
        });
      }

      const fetchRes = await db.query(
        `SELECT lr.id, lr.request_code, lr.user_id, lr.requester_email,
                tc.name AS contact_name, u.full_name AS owner_name
         FROM legacy_requests lr
         JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id
         JOIN users u ON u.id = lr.user_id
         WHERE lr.id = $1 LIMIT 1`,
        [requestId]
      );
      const reqRow = fetchRes.rows[0];
      if (!reqRow) return res.status(404).json({ success: false, error: 'Legacy access request not found.' });

      const client = await db.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `UPDATE legacy_requests
           SET status = $1, admin_remarks = $2, reviewed_by = $3, reviewed_at = NOW(), updated_at = NOW()
           WHERE id = $4`,
          [decision, remarks, adminId, requestId]
        );
        await client.query(
          'INSERT INTO admin_action_logs (admin_id, legacy_request_id, action, remarks) VALUES ($1, $2, $3, $4)',
          [adminId, requestId, `request_${decision}`, remarks]
        );
        await client.query('COMMIT');
      } catch (txErr) {
        await client.query('ROLLBACK');
        throw txErr;
      } finally {
        client.release();
      }

      const subject =
        decision === 'approved'
          ? `Legacy Access Request Approved (${reqRow.request_code})`
          : `Legacy Access Request Reviewed — Not Approved (${reqRow.request_code})`;

      await sendAndLogNotification(
        db,
        Number(reqRow.user_id),
        reqRow.requester_email,
        'trusted_contact',
        `legacy_request_${decision}`,
        subject,
        `Hello ${reqRow.contact_name}, your request (${reqRow.request_code}) for ${reqRow.owner_name}'s vault was ${decision}. Remarks: ${remarks}`,
        '',
        false
      );

      return res.json({
        success: true,
        message: `Request ${reqRow.request_code} marked as ${decision} and recorded in the audit log.`,
      });
    }

    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  } catch (err) {
    console.error('Admin API error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error in admin panel.' });
  }
});

// Mount API routes under both /api (clean HTTPS preview routes) and /MEMORY-VAULT/backend/api
app.use('/api', apiRouter);
app.use('/MEMORY-VAULT/backend/api', apiRouter);

// Cron endpoint
app.all(['/api/cron/check_inactivity', '/MEMORY-VAULT/backend/cron/check_inactivity.php'], async (req, res) => {
  const db = requirePool(res);
  if (!db) return;
  const sess = getSession(req);
  if (!sess.userId && !sess.adminId) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  try {
    const { rows } = await db.query('SELECT id FROM users ORDER BY id ASC');
    const results = [];
    for (const row of rows) {
      results.push(await evaluateInactivityForUser(db, Number(row.id)));
    }
    return res.json({ success: true, evaluated_at: new Date().toISOString(), results });
  } catch (err) {
    console.error('Cron error:', (err as Error).message);
    return res.status(500).json({ success: false, error: 'Database error while running inactivity check.' });
  }
});

// Serve the pure HTML/CSS/Vanilla JS Memory Vault frontend directly
app.use('/MEMORY-VAULT/frontend', express.static(MEMORY_VAULT_FRONTEND));
app.use('/src/assets', express.static(path.resolve(__dirname, 'src', 'assets')));

app.get('/', (_req, res) => {
  res.redirect('/MEMORY-VAULT/frontend/index.html');
});

app.get('/:page.html', (req, res, next) => {
  const candidate = path.resolve(MEMORY_VAULT_FRONTEND, `${req.params.page}.html`);
  if (candidate.startsWith(MEMORY_VAULT_FRONTEND + path.sep) && fs.existsSync(candidate)) {
    return res.redirect(`/MEMORY-VAULT/frontend/${req.params.page}.html`);
  }
  return next();
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Memory Vault server running at http://0.0.0.0:${PORT} (Database: ${pool ? 'Supabase PostgreSQL via DATABASE_URL' : 'NOT CONFIGURED'})`
  );
});
