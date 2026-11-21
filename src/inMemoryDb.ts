import bcrypt from 'bcryptjs';

export interface QueryResult<T = Record<string, any>> {
  rows: T[];
  rowCount: number;
}

export interface DbClient {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
  release(): void;
}

export interface DbPool {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
  connect(): Promise<DbClient>;
}

interface UserRow {
  id: number;
  user_handle: string;
  full_name: string;
  email: string;
  password_hash: string;
  last_check_in: string;
  escalation_stage: number;
  inactivity_cycle_id: string;
  created_at: string;
  updated_at: string;
}

interface AdminUserRow {
  id: number;
  full_name: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: string;
  updated_at: string;
}

interface DigitalAssetRow {
  id: number;
  user_id: number;
  asset_name: string;
  platform: string;
  category: string;
  account_identifier: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

interface TrustedContactRow {
  id: number;
  user_id: number;
  name: string;
  email: string;
  phone: string;
  relationship: string;
  invitation_token: string;
  invitation_status: 'pending' | 'accepted' | 'declined';
  responded_at: string | null;
  created_at: string;
  updated_at: string;
}

interface FinalWishRow {
  id: number;
  user_id: number;
  asset_id: number;
  assigned_contact_id: number | null;
  action_type: string;
  custom_instructions: string;
  created_at: string;
  updated_at: string;
}

interface MemoryRow {
  id: number;
  user_id: number;
  trusted_contact_id: number | null;
  custom_recipient: string;
  title: string;
  message_body: string;
  release_condition: string;
  created_at: string;
  updated_at: string;
}

interface LegacyPlanRow {
  id: number;
  user_id: number;
  first_reminder_days: number;
  second_reminder_days: number;
  final_reminder_days: number;
  trusted_alert_days: number;
  general_guidance: string;
  created_at: string;
  updated_at: string;
}

interface LegacyRequestRow {
  id: number;
  request_code: string;
  user_id: number;
  trusted_contact_id: number;
  requester_email: string;
  reason: string;
  verification_note: string;
  status: 'pending' | 'approved' | 'rejected';
  admin_remarks: string;
  reviewed_by: number | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface NotificationLogRow {
  id: number;
  user_id: number | null;
  recipient_email: string;
  recipient_role: string;
  notification_type: string;
  cycle_id: string;
  subject: string;
  body: string;
  delivery_status: string;
  created_at: string;
}

interface AdminActionLogRow {
  id: number;
  admin_id: number;
  legacy_request_id: number | null;
  action: string;
  remarks: string;
  created_at: string;
}

function daysAgoIso(days: number): string {
  return new Date(Date.now() - days * 86400000).toISOString();
}

function calcDaysInactive(lastCheckIn: string): number {
  const diffMs = Date.now() - new Date(lastCheckIn).getTime();
  return Math.max(0, Math.floor(diffMs / 86400000));
}

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim();
}

function ok<T = Record<string, any>>(rows: T[], rowCount?: number): QueryResult<T> {
  return { rows, rowCount: rowCount ?? rows.length };
}

/**
 * In-memory PostgreSQL-compatible database seeded with the exact demo records
 * from MEMORY-VAULT/backend/database/supabase_schema.sql.
 * Used automatically when DATABASE_URL is not configured or unreachable.
 */
export function createInMemoryPool(): DbPool {
  const nowIso = new Date().toISOString();

  const users: UserRow[] = [
    {
      id: 1,
      user_handle: 'aarav_mehta',
      full_name: 'Aarav Mehta',
      email: 'demo@memoryvault.com',
      password_hash: bcrypt.hashSync('Demo@1234', 10),
      last_check_in: daysAgoIso(4),
      escalation_stage: 0,
      inactivity_cycle_id: 'cycle_demo_2026',
      created_at: daysAgoIso(30),
      updated_at: daysAgoIso(4),
    },
  ];

  const adminUsers: AdminUserRow[] = [
    {
      id: 1,
      full_name: 'Dr. Kavita Rao',
      email: 'admin@memoryvault.com',
      password_hash: bcrypt.hashSync('Admin@1234', 10),
      role: 'chief_verifier',
      created_at: daysAgoIso(60),
      updated_at: daysAgoIso(60),
    },
  ];

  const legacyPlans: LegacyPlanRow[] = [
    {
      id: 1,
      user_id: 1,
      first_reminder_days: 30,
      second_reminder_days: 35,
      final_reminder_days: 40,
      trusted_alert_days: 45,
      general_guidance:
        'Please handle all accounts with care and follow official provider legacy processes. Never attempt unauthorized sign-ins; preserve family photographs first.',
      created_at: daysAgoIso(30),
      updated_at: daysAgoIso(30),
    },
  ];

  const trustedContacts: TrustedContactRow[] = [
    {
      id: 1,
      user_id: 1,
      name: 'Meera Mehta',
      email: 'meera.mehta@example.com',
      phone: '+91 98201 44120',
      relationship: 'Sister',
      invitation_token: 'mv_inv_meera_8f3a91c2d4b0e711',
      invitation_status: 'accepted',
      responded_at: daysAgoIso(18),
      created_at: daysAgoIso(25),
      updated_at: daysAgoIso(18),
    },
    {
      id: 2,
      user_id: 1,
      name: 'Rohan Kulkarni',
      email: 'rohan.kulkarni@example.com',
      phone: '+91 98450 77312',
      relationship: 'Close Friend & Executor',
      invitation_token: 'mv_inv_rohan_5b2c19a8e6f3d420',
      invitation_status: 'accepted',
      responded_at: daysAgoIso(12),
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(12),
    },
    {
      id: 3,
      user_id: 1,
      name: 'Ananya Deshmukh',
      email: 'ananya.d@example.com',
      phone: '+91 97654 21890',
      relationship: 'Cousin',
      invitation_token: 'mv_inv_ananya_1c9e44b7a2d5f803',
      invitation_status: 'pending',
      responded_at: null,
      created_at: daysAgoIso(10),
      updated_at: daysAgoIso(10),
    },
  ];

  const digitalAssets: DigitalAssetRow[] = [
    {
      id: 1,
      user_id: 1,
      asset_name: 'Family Photo Archive',
      platform: 'Google Photos',
      category: 'Cloud Photos',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Contains albums from 2014–2026 including Ladakh trip, graduation, and family gatherings.',
      created_at: daysAgoIso(24),
      updated_at: daysAgoIso(24),
    },
    {
      id: 2,
      user_id: 1,
      asset_name: 'Personal Instagram Journal',
      platform: 'Instagram',
      category: 'Social Media',
      account_identifier: '@aarav.frames',
      notes: 'Film photography visual diary and travel captions.',
      created_at: daysAgoIso(22),
      updated_at: daysAgoIso(22),
    },
    {
      id: 3,
      user_id: 1,
      asset_name: 'Primary Email Account',
      platform: 'Gmail',
      category: 'Email',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Linked to academic certificates, tax receipts, and Google Inactive Account Manager.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(20),
    },
    {
      id: 4,
      user_id: 1,
      asset_name: 'Creative Writing & Research Drive',
      platform: 'Google Drive',
      category: 'Cloud Storage',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Folder titled "Essays & Drafts" holds unpublished short stories and project archives.',
      created_at: daysAgoIso(18),
      updated_at: daysAgoIso(18),
    },
    {
      id: 5,
      user_id: 1,
      asset_name: 'Streaming & Cloud Subscriptions',
      platform: 'Spotify & Adobe Creative Cloud',
      category: 'Subscriptions',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Monthly recurring billing linked to primary debit card; cancel via official support.',
      created_at: daysAgoIso(15),
      updated_at: daysAgoIso(15),
    },
  ];

  const finalWishes: FinalWishRow[] = [
    {
      id: 1,
      user_id: 1,
      asset_id: 1,
      assigned_contact_id: 1,
      action_type: 'preserve_memories',
      custom_instructions:
        'Export the "Family Years" and "Himalayan Trails" albums via Google Takeout through official next-of-kin channels and share copies with our parents.',
      created_at: daysAgoIso(24),
      updated_at: daysAgoIso(24),
    },
    {
      id: 2,
      user_id: 1,
      asset_id: 2,
      assigned_contact_id: 1,
      action_type: 'request_memorialization',
      custom_instructions:
        'Submit an official Instagram memorialization request so the photography grid remains viewable to friends without new posts.',
      created_at: daysAgoIso(22),
      updated_at: daysAgoIso(22),
    },
    {
      id: 3,
      user_id: 1,
      asset_id: 3,
      assigned_contact_id: 2,
      action_type: 'share_information',
      custom_instructions:
        'Coordinate with Google Inactive Account Manager to download tax and academic records, then close the inbox respectfully.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(20),
    },
    {
      id: 4,
      user_id: 1,
      asset_id: 4,
      assigned_contact_id: 2,
      action_type: 'preserve_account',
      custom_instructions:
        'Archive the "Essays & Drafts" folder to an external drive and keep the literary notebooks safe for family reading.',
      created_at: daysAgoIso(18),
      updated_at: daysAgoIso(18),
    },
    {
      id: 5,
      user_id: 1,
      asset_id: 5,
      assigned_contact_id: 2,
      action_type: 'request_deletion',
      custom_instructions:
        'Contact Spotify and Adobe customer support with official documentation to cancel recurring subscriptions and close billing profiles.',
      created_at: daysAgoIso(15),
      updated_at: daysAgoIso(15),
    },
  ];

  const memories: MemoryRow[] = [
    {
      id: 1,
      user_id: 1,
      trusted_contact_id: 1,
      custom_recipient: '',
      title: 'For Meera — Keep the Cameras Rolling',
      message_body:
        'Dearest Meera,\n\nIf you are reading this letter, I hope you are sitting somewhere quiet with a warm cup of filter coffee. Every photograph in our shared archive carries a story only the two of us remember—from rainy monsoon evenings on the balcony to our long bus ride through Himachal.\n\nPlease keep my old 35mm camera on your bookshelf, and whenever life feels hurried, flip through the family albums and remember how deeply loved you have always been.\n\nWith all my warmth,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(20),
    },
    {
      id: 2,
      user_id: 1,
      trusted_contact_id: 2,
      custom_recipient: '',
      title: 'To Rohan — Notes on My Notebooks & Playlists',
      message_body:
        'Hey Rohan,\n\nThank you for being the steadying voice in every chapter since our first semester. I have left instructions for the Creative Writing Drive so you can archive my unfinished essays and keep the acoustic road-trip playlist alive.\n\nTake care of yourself, keep building things that matter, and never lose your curiosity.\n\nAlways grateful,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(18),
      updated_at: daysAgoIso(18),
    },
    {
      id: 3,
      user_id: 1,
      trusted_contact_id: 1,
      custom_recipient: 'Mom & Dad',
      title: 'A Quiet Letter for Mom and Dad',
      message_body:
        'Dear Mom and Dad,\n\nEverything gentle and resilient in me came directly from watching the two of you. Thank you for giving me roots deep enough to weather storms and wings wide enough to explore the world.\n\nMeera has the list of family photo albums I curated especially for you. Please know my life was filled with gratitude because of our home.\n\nLove always,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(14),
      updated_at: daysAgoIso(14),
    },
  ];

  const legacyRequests: LegacyRequestRow[] = [
    {
      id: 1,
      request_code: 'REQ-2026-8412',
      user_id: 1,
      trusted_contact_id: 1,
      requester_email: 'meera.mehta@example.com',
      reason: 'Family stewardship & photo archive preservation',
      verification_note:
        'Sister listed as primary trusted contact. Submitting formal family verification reference #FAM-2026-09 for administrative review.',
      status: 'pending',
      admin_remarks: '',
      reviewed_by: null,
      reviewed_at: null,
      created_at: daysAgoIso(3),
      updated_at: daysAgoIso(3),
    },
  ];

  const notificationLogs: NotificationLogRow[] = [
    {
      id: 1,
      user_id: 1,
      recipient_email: 'meera.mehta@example.com',
      recipient_role: 'trusted_contact',
      notification_type: 'contact_invitation',
      cycle_id: 'cycle_demo_2026',
      subject: 'You were named a Trusted Contact on Memory Vault',
      body: 'Aarav Mehta has invited you as a Trusted Contact on Memory Vault. Accepting does not automatically grant access to private vault data.',
      delivery_status: 'logged',
      created_at: daysAgoIso(25),
    },
    {
      id: 2,
      user_id: 1,
      recipient_email: 'demo@memoryvault.com',
      recipient_role: 'user',
      notification_type: 'check_in_reset',
      cycle_id: 'cycle_demo_2026',
      subject: 'Memory Vault Check-In Confirmed',
      body: 'Your activity timer was confirmed active. Next inactivity reminder is scheduled in 30 days.',
      delivery_status: 'logged',
      created_at: daysAgoIso(4),
    },
  ];

  const adminActionLogs: AdminActionLogRow[] = [];

  const nextId = {
    users: 2,
    admin_users: 2,
    legacy_plans: 2,
    trusted_contacts: 4,
    digital_assets: 6,
    final_wishes: 6,
    memories: 4,
    legacy_requests: 2,
    notification_logs: 3,
    admin_action_logs: 1,
  };

  async function query(rawSql: string, params: unknown[] = []): Promise<QueryResult> {
    const sql = normalizeSql(rawSql);
    const upper = sql.toUpperCase();

    if (upper === 'BEGIN' || upper === 'COMMIT' || upper === 'ROLLBACK') {
      return ok([]);
    }

    // -------------------------------------------------------------------------
    // Health & Cron
    // -------------------------------------------------------------------------
    if (sql === 'SELECT COUNT(*)::INT AS user_count FROM users') {
      return ok([{ user_count: users.length }]);
    }

    if (sql === 'SELECT id FROM users ORDER BY id ASC') {
      return ok([...users].sort((a, b) => a.id - b.id).map((u) => ({ id: u.id })));
    }

    // -------------------------------------------------------------------------
    // Users & Admin Users Queries
    // -------------------------------------------------------------------------
    if (sql.startsWith('SELECT id, user_handle, full_name, email, last_check_in, escalation_stage, created_at FROM users WHERE id = $1')) {
      const uid = Number(params[0]);
      const u = users.find((x) => x.id === uid);
      return ok(
        u
          ? [
              {
                id: u.id,
                user_handle: u.user_handle,
                full_name: u.full_name,
                email: u.email,
                last_check_in: u.last_check_in,
                escalation_stage: u.escalation_stage,
                created_at: u.created_at,
              },
            ]
          : []
      );
    }

    if (sql.startsWith('SELECT id, full_name, email, role, created_at FROM admin_users WHERE id = $1')) {
      const aid = Number(params[0]);
      const a = adminUsers.find((x) => x.id === aid);
      return ok(
        a ? [{ id: a.id, full_name: a.full_name, email: a.email, role: a.role, created_at: a.created_at }] : []
      );
    }

    if (sql.startsWith('SELECT id, full_name, email, role FROM admin_users WHERE id = $1')) {
      const aid = Number(params[0]);
      const a = adminUsers.find((x) => x.id === aid);
      return ok(a ? [{ id: a.id, full_name: a.full_name, email: a.email, role: a.role }] : []);
    }

    if (sql.startsWith('SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($2)')) {
      const email = String(params[0] || '').toLowerCase();
      const handle = String(params[1] || '').toLowerCase();
      const found = users.find((u) => u.email.toLowerCase() === email || u.user_handle.toLowerCase() === handle);
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1)')) {
      const ident = String(params[0] || '').toLowerCase();
      const found = users.find((u) => u.email.toLowerCase() === ident || u.user_handle.toLowerCase() === ident);
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('SELECT id FROM admin_users WHERE LOWER(email) = LOWER($1)')) {
      const email = String(params[0] || '').toLowerCase();
      const found = adminUsers.find((a) => a.email.toLowerCase() === email);
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('SELECT id, full_name, email, password_hash, role, created_at FROM admin_users WHERE LOWER(email) = LOWER($1)')) {
      const email = String(params[0] || '').toLowerCase();
      const found = adminUsers.find((a) => a.email.toLowerCase() === email);
      return ok(found ? [{ ...found }] : []);
    }

    if (sql.startsWith('SELECT id, user_handle, full_name, email, password_hash, last_check_in, escalation_stage, created_at FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1)')) {
      const ident = String(params[0] || '').toLowerCase();
      const found = users.find((u) => u.email.toLowerCase() === ident || u.user_handle.toLowerCase() === ident);
      return ok(found ? [{ ...found }] : []);
    }

    if (sql.startsWith('SELECT id, full_name, user_handle, email FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1)')) {
      const ident = String(params[0] || '').toLowerCase();
      const found = users.find((u) => u.email.toLowerCase() === ident || u.user_handle.toLowerCase() === ident);
      return ok(
        found
          ? [{ id: found.id, full_name: found.full_name, user_handle: found.user_handle, email: found.email }]
          : []
      );
    }

    if (sql.startsWith('SELECT id, full_name, email FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(user_handle) = LOWER($1)')) {
      const ident = String(params[0] || '').toLowerCase();
      const found = users.find((u) => u.email.toLowerCase() === ident || u.user_handle.toLowerCase() === ident);
      return ok(found ? [{ id: found.id, full_name: found.full_name, email: found.email }] : []);
    }

    if (sql.startsWith('SELECT email, full_name FROM users WHERE id = $1')) {
      const u = users.find((x) => x.id === Number(params[0]));
      return ok(u ? [{ email: u.email, full_name: u.full_name }] : []);
    }

    if (sql.startsWith('SELECT full_name FROM users WHERE id = $1')) {
      const u = users.find((x) => x.id === Number(params[0]));
      return ok(u ? [{ full_name: u.full_name }] : []);
    }

    if (sql.startsWith('SELECT escalation_stage, inactivity_cycle_id FROM users WHERE id = $1')) {
      const u = users.find((x) => x.id === Number(params[0]));
      return ok(
        u ? [{ escalation_stage: u.escalation_stage, inactivity_cycle_id: u.inactivity_cycle_id }] : []
      );
    }

    if (sql.startsWith('INSERT INTO users (')) {
      const ts = new Date().toISOString();
      const row: UserRow = {
        id: nextId.users++,
        user_handle: String(params[0]),
        full_name: String(params[1]),
        email: String(params[2]),
        password_hash: String(params[3]),
        last_check_in: ts,
        escalation_stage: 0,
        inactivity_cycle_id: String(params[4]),
        created_at: ts,
        updated_at: ts,
      };
      users.push(row);
      return ok([
        {
          id: row.id,
          user_handle: row.user_handle,
          full_name: row.full_name,
          email: row.email,
          last_check_in: row.last_check_in,
          escalation_stage: row.escalation_stage,
          created_at: row.created_at,
        },
      ]);
    }

    if (sql.startsWith('INSERT INTO legacy_plans (')) {
      const ts = new Date().toISOString();
      legacyPlans.push({
        id: nextId.legacy_plans++,
        user_id: Number(params[0]),
        first_reminder_days: 30,
        second_reminder_days: 35,
        final_reminder_days: 40,
        trusted_alert_days: 45,
        general_guidance: '',
        created_at: ts,
        updated_at: ts,
      });
      return ok([], 1);
    }

    if (sql.startsWith('UPDATE users SET last_check_in = NOW(), escalation_stage = 0, inactivity_cycle_id = $1, updated_at = NOW() WHERE id = $2')) {
      const cycle = String(params[0]);
      const uid = Number(params[1]);
      const u = users.find((x) => x.id === uid);
      if (!u) return ok([], 0);
      const ts = new Date().toISOString();
      u.last_check_in = ts;
      u.escalation_stage = 0;
      u.inactivity_cycle_id = cycle;
      u.updated_at = ts;
      return ok([
        {
          id: u.id,
          user_handle: u.user_handle,
          full_name: u.full_name,
          email: u.email,
          last_check_in: u.last_check_in,
          escalation_stage: u.escalation_stage,
          created_at: u.created_at,
        },
      ]);
    }

    if (sql.startsWith('UPDATE users SET escalation_stage = $1, updated_at = NOW() WHERE id = $2')) {
      const stage = Number(params[0]);
      const uid = Number(params[1]);
      const u = users.find((x) => x.id === uid);
      if (!u) return ok([], 0);
      u.escalation_stage = stage;
      u.updated_at = new Date().toISOString();
      return ok([], 1);
    }

    if (sql.startsWith("UPDATE users SET last_check_in = NOW() - ($1::TEXT || ' days')::INTERVAL")) {
      const days = Number(params[0]);
      const stage = Number(params[1]);
      const cycle = String(params[2]);
      const uid = Number(params[3]);
      const u = users.find((x) => x.id === uid);
      if (!u) return ok([], 0);
      u.last_check_in = daysAgoIso(days);
      u.escalation_stage = stage;
      u.inactivity_cycle_id = cycle;
      u.updated_at = new Date().toISOString();
      return ok([], 1);
    }

    // User + Legacy Plan join (evaluateInactivity, dashboard, summary)
    if (sql.includes('FROM users u LEFT JOIN legacy_plans lp ON lp.user_id = u.id WHERE u.id = $1')) {
      const uid = Number(params[0]);
      const u = users.find((x) => x.id === uid);
      if (!u) return ok([]);
      const lp = legacyPlans.find((x) => x.user_id === uid);
      const first = lp?.first_reminder_days ?? 30;
      const second = lp?.second_reminder_days ?? 35;
      const finalD = lp?.final_reminder_days ?? 40;
      const alertD = lp?.trusted_alert_days ?? 45;
      return ok([
        {
          id: u.id,
          user_handle: u.user_handle,
          full_name: u.full_name,
          email: u.email,
          last_check_in: u.last_check_in,
          escalation_stage: u.escalation_stage,
          inactivity_cycle_id: u.inactivity_cycle_id,
          created_at: u.created_at,
          days_inactive: calcDaysInactive(u.last_check_in),
          first_days: first,
          second_days: second,
          final_days: finalD,
          alert_days: alertD,
          first_reminder_days: first,
          second_reminder_days: second,
          final_reminder_days: finalD,
          trusted_alert_days: alertD,
          general_guidance: lp?.general_guidance ?? '',
        },
      ]);
    }

    // -------------------------------------------------------------------------
    // Notification Logs
    // -------------------------------------------------------------------------
    if (sql.startsWith('SELECT id FROM notification_logs WHERE user_id = $1 AND cycle_id = $2')) {
      const uid = Number(params[0]);
      const cycle = String(params[1]);
      const ntype = String(params[2]);
      const email = String(params[3]).toLowerCase();
      const dup = notificationLogs.find(
        (n) =>
          n.user_id === uid &&
          n.cycle_id === cycle &&
          n.notification_type === ntype &&
          n.recipient_email.toLowerCase() === email
      );
      return ok(dup ? [{ id: dup.id }] : []);
    }

    if (sql.startsWith('INSERT INTO notification_logs (')) {
      const row: NotificationLogRow = {
        id: nextId.notification_logs++,
        user_id: params[0] === null ? null : Number(params[0]),
        recipient_email: String(params[1]),
        recipient_role: String(params[2]),
        notification_type: String(params[3]),
        cycle_id: String(params[4] ?? ''),
        subject: String(params[5]),
        body: String(params[6]),
        delivery_status: String(params[7] ?? 'logged_demo_fallback'),
        created_at: new Date().toISOString(),
      };
      notificationLogs.push(row);
      return ok([{ id: row.id }], 1);
    }

    if (sql.includes('FROM notification_logs WHERE user_id = $1 ORDER BY created_at DESC')) {
      const uid = Number(params[0]);
      const rows = notificationLogs
        .filter((n) => n.user_id === uid)
        .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id)
        .slice(0, 15);
      return ok(rows);
    }

    if (sql.includes('FROM notification_logs ORDER BY created_at DESC')) {
      const rows = [...notificationLogs]
        .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id)
        .slice(0, 15);
      return ok(rows);
    }

    // -------------------------------------------------------------------------
    // Counts (Dashboard & Admin)
    // -------------------------------------------------------------------------
    if (sql === 'SELECT COUNT(*)::INT AS c FROM digital_assets WHERE user_id = $1') {
      return ok([{ c: digitalAssets.filter((a) => a.user_id === Number(params[0])).length }]);
    }
    if (sql === 'SELECT COUNT(*)::INT AS c FROM final_wishes WHERE user_id = $1') {
      return ok([{ c: finalWishes.filter((w) => w.user_id === Number(params[0])).length }]);
    }
    if (sql === 'SELECT COUNT(*)::INT AS c FROM trusted_contacts WHERE user_id = $1') {
      return ok([{ c: trustedContacts.filter((c) => c.user_id === Number(params[0])).length }]);
    }
    if (sql === "SELECT COUNT(*)::INT AS c FROM trusted_contacts WHERE user_id = $1 AND invitation_status = 'accepted'") {
      return ok([
        {
          c: trustedContacts.filter(
            (c) => c.user_id === Number(params[0]) && c.invitation_status === 'accepted'
          ).length,
        },
      ]);
    }
    if (sql === 'SELECT COUNT(*)::INT AS c FROM memories WHERE user_id = $1') {
      return ok([{ c: memories.filter((m) => m.user_id === Number(params[0])).length }]);
    }
    if (sql === 'SELECT COUNT(*)::INT AS cnt FROM users') {
      return ok([{ cnt: users.length }]);
    }
    if (sql === 'SELECT COUNT(*)::INT AS cnt FROM notification_logs') {
      return ok([{ cnt: notificationLogs.length }]);
    }
    if (sql === 'SELECT status, COUNT(*)::INT AS cnt FROM legacy_requests GROUP BY status') {
      const map = new Map<string, number>();
      for (const r of legacyRequests) {
        map.set(r.status, (map.get(r.status) || 0) + 1);
      }
      return ok(Array.from(map.entries()).map(([status, cnt]) => ({ status, cnt })));
    }

    // -------------------------------------------------------------------------
    // Digital Assets
    // -------------------------------------------------------------------------
    if (sql.includes('FROM digital_assets a LEFT JOIN final_wishes w ON w.asset_id = a.id') && !sql.includes('LEFT JOIN trusted_contacts tc')) {
      const uid = Number(params[0]);
      const rows = digitalAssets
        .filter((a) => a.user_id === uid)
        .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id)
        .map((a) => {
          const w = finalWishes.find((fw) => fw.asset_id === a.id && fw.user_id === uid);
          return {
            ...a,
            wish_id: w?.id ?? null,
            wish_action_type: w?.action_type ?? null,
          };
        });
      return ok(rows);
    }

    if (sql.startsWith('SELECT id FROM digital_assets WHERE id = $1 AND user_id = $2')) {
      const found = digitalAssets.find((a) => a.id === Number(params[0]) && a.user_id === Number(params[1]));
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('INSERT INTO digital_assets (')) {
      const ts = new Date().toISOString();
      const row: DigitalAssetRow = {
        id: nextId.digital_assets++,
        user_id: Number(params[0]),
        asset_name: String(params[1]),
        platform: String(params[2]),
        category: String(params[3]),
        account_identifier: String(params[4]),
        notes: String(params[5] ?? ''),
        created_at: ts,
        updated_at: ts,
      };
      digitalAssets.push(row);
      return ok([{ ...row }]);
    }

    if (sql.startsWith('UPDATE digital_assets SET asset_name = $1')) {
      const id = Number(params[5]);
      const uid = Number(params[6]);
      const a = digitalAssets.find((x) => x.id === id && x.user_id === uid);
      if (!a) return ok([], 0);
      a.asset_name = String(params[0]);
      a.platform = String(params[1]);
      a.category = String(params[2]);
      a.account_identifier = String(params[3]);
      a.notes = String(params[4] ?? '');
      a.updated_at = new Date().toISOString();
      return ok([{ ...a }]);
    }

    if (sql.startsWith('DELETE FROM digital_assets WHERE id = $1 AND user_id = $2')) {
      const id = Number(params[0]);
      const uid = Number(params[1]);
      const idx = digitalAssets.findIndex((a) => a.id === id && a.user_id === uid);
      if (idx === -1) return ok([], 0);
      digitalAssets.splice(idx, 1);
      for (let i = finalWishes.length - 1; i >= 0; i--) {
        if (finalWishes[i].asset_id === id) finalWishes.splice(i, 1);
      }
      return ok([], 1);
    }

    // -------------------------------------------------------------------------
    // Final Wishes (including Summary & Lookup variants)
    // -------------------------------------------------------------------------
    if (sql.includes('FROM digital_assets a LEFT JOIN final_wishes w') && sql.includes('LEFT JOIN trusted_contacts tc')) {
      const uid = Number(params[0]);
      const asc = sql.includes('ORDER BY a.id ASC');
      const sorted = digitalAssets
        .filter((a) => a.user_id === uid)
        .sort((a, b) =>
          asc ? a.id - b.id : b.created_at.localeCompare(a.created_at) || b.id - a.id
        );
      const rows = sorted.map((a) => {
        const w = finalWishes.find((fw) => fw.asset_id === a.id && fw.user_id === uid);
        const tc =
          w?.assigned_contact_id != null
            ? trustedContacts.find((c) => c.id === w.assigned_contact_id && c.user_id === uid)
            : undefined;
        return {
          id: a.id,
          asset_id: a.id,
          asset_name: a.asset_name,
          platform: a.platform,
          category: a.category,
          account_identifier: a.account_identifier,
          notes: a.notes,
          wish_id: w?.id ?? null,
          action_type: w?.action_type ?? null,
          custom_instructions: w?.custom_instructions ?? null,
          assigned_contact_id: w?.assigned_contact_id ?? null,
          wish_updated_at: w?.updated_at ?? null,
          assigned_contact_name: tc?.name ?? null,
        };
      });
      return ok(rows);
    }

    if (sql.includes('FROM final_wishes w JOIN digital_assets a ON a.id = w.asset_id')) {
      const uid = Number(params[0]);
      const cid = Number(params[1]);
      const rows = finalWishes
        .filter((w) => w.user_id === uid && w.assigned_contact_id === cid)
        .map((w) => {
          const a = digitalAssets.find((x) => x.id === w.asset_id);
          if (!a) return null;
          return {
            asset_id: a.id,
            asset_name: a.asset_name,
            platform: a.platform,
            category: a.category,
            account_identifier: a.account_identifier,
            notes: a.notes,
            action_type: w.action_type,
            custom_instructions: w.custom_instructions,
          };
        })
        .filter((x): x is NonNullable<typeof x> => x !== null)
        .sort((a, b) => a.asset_id - b.asset_id);
      return ok(rows);
    }

    if (sql.startsWith('INSERT INTO final_wishes (')) {
      const uid = Number(params[0]);
      const assetId = Number(params[1]);
      const contactId = params[2] === null ? null : Number(params[2]);
      const actionType = String(params[3]);
      const customInstr = String(params[4] ?? '');
      const ts = new Date().toISOString();

      const existing = finalWishes.find((w) => w.asset_id === assetId && w.user_id === uid);
      if (existing) {
        existing.assigned_contact_id = contactId;
        existing.action_type = actionType;
        existing.custom_instructions = customInstr;
        existing.updated_at = ts;
        return ok([{ ...existing }]);
      }
      const row: FinalWishRow = {
        id: nextId.final_wishes++,
        user_id: uid,
        asset_id: assetId,
        assigned_contact_id: contactId,
        action_type: actionType,
        custom_instructions: customInstr,
        created_at: ts,
        updated_at: ts,
      };
      finalWishes.push(row);
      return ok([{ ...row }]);
    }

    if (sql.startsWith('DELETE FROM final_wishes WHERE id = $1 AND user_id = $2')) {
      const id = Number(params[0]);
      const uid = Number(params[1]);
      const idx = finalWishes.findIndex((w) => w.id === id && w.user_id === uid);
      if (idx === -1) return ok([], 0);
      finalWishes.splice(idx, 1);
      return ok([], 1);
    }

    // -------------------------------------------------------------------------
    // Trusted Contacts
    // -------------------------------------------------------------------------
    if (sql.includes('FROM trusted_contacts tc JOIN users u ON u.id = tc.user_id WHERE tc.invitation_token = $1')) {
      const token = String(params[0]);
      const tc = trustedContacts.find((c) => c.invitation_token === token);
      if (!tc) return ok([]);
      const u = users.find((x) => x.id === tc.user_id);
      if (!u) return ok([]);
      return ok([
        {
          id: tc.id,
          name: tc.name,
          email: tc.email,
          relationship: tc.relationship,
          invitation_status: tc.invitation_status,
          responded_at: tc.responded_at,
          owner_name: u.full_name,
          owner_handle: u.user_handle,
        },
      ]);
    }

    if (sql.startsWith('UPDATE trusted_contacts SET invitation_status = $1, responded_at = NOW(), updated_at = NOW() WHERE invitation_token = $2')) {
      const decision = String(params[0]) as 'pending' | 'accepted' | 'declined';
      const token = String(params[1]);
      const tc = trustedContacts.find((c) => c.invitation_token === token);
      if (!tc) return ok([], 0);
      const ts = new Date().toISOString();
      tc.invitation_status = decision;
      tc.responded_at = ts;
      tc.updated_at = ts;
      return ok([
        {
          id: tc.id,
          user_id: tc.user_id,
          name: tc.name,
          email: tc.email,
          invitation_status: tc.invitation_status,
          responded_at: tc.responded_at,
        },
      ]);
    }

    if (sql.includes("FROM trusted_contacts WHERE user_id = $1 AND invitation_status != 'declined'")) {
      const uid = Number(params[0]);
      return ok(
        trustedContacts
          .filter((c) => c.user_id === uid && c.invitation_status !== 'declined')
          .map((c) => ({ id: c.id, name: c.name, email: c.email, invitation_status: c.invitation_status }))
      );
    }

    if (sql.startsWith('SELECT id FROM trusted_contacts WHERE id = $1 AND user_id = $2')) {
      const found = trustedContacts.find((c) => c.id === Number(params[0]) && c.user_id === Number(params[1]));
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('SELECT id FROM trusted_contacts WHERE user_id = $1 AND LOWER(email) = LOWER($2)')) {
      const uid = Number(params[0]);
      const email = String(params[1]).toLowerCase();
      const found = trustedContacts.find((c) => c.user_id === uid && c.email.toLowerCase() === email);
      return ok(found ? [{ id: found.id }] : []);
    }

    if (sql.startsWith('SELECT id, name, email, invitation_status FROM trusted_contacts WHERE user_id = $1 AND LOWER(email) = LOWER($2)')) {
      const uid = Number(params[0]);
      const email = String(params[1]).toLowerCase();
      const found = trustedContacts.find((c) => c.user_id === uid && c.email.toLowerCase() === email);
      return ok(
        found
          ? [{ id: found.id, name: found.name, email: found.email, invitation_status: found.invitation_status }]
          : []
      );
    }

    if (sql.includes('FROM trusted_contacts WHERE user_id = $1 ORDER BY')) {
      const uid = Number(params[0]);
      const list = trustedContacts.filter((c) => c.user_id === uid);
      if (sql.includes('ORDER BY name ASC')) {
        list.sort((a, b) => a.name.localeCompare(b.name));
      } else if (sql.includes('ORDER BY id ASC')) {
        list.sort((a, b) => a.id - b.id);
      } else {
        list.sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id);
      }
      return ok(list.map((c) => ({ ...c })));
    }

    if (sql.startsWith('INSERT INTO trusted_contacts (')) {
      const ts = new Date().toISOString();
      const row: TrustedContactRow = {
        id: nextId.trusted_contacts++,
        user_id: Number(params[0]),
        name: String(params[1]),
        email: String(params[2]),
        phone: String(params[3] ?? ''),
        relationship: String(params[4]),
        invitation_token: String(params[5]),
        invitation_status: 'pending',
        responded_at: null,
        created_at: ts,
        updated_at: ts,
      };
      trustedContacts.push(row);
      return ok([{ ...row }]);
    }

    if (sql.startsWith('ALTER TABLE trusted_contacts')) {
      return ok([]);
    }

    if (
      sql.startsWith('UPDATE trusted_contacts SET invitation_status = $1, responded_at = ') &&
      sql.includes('WHERE id = $2 AND user_id = $3')
    ) {
      const status = String(params[0]) as 'pending' | 'accepted' | 'declined';
      const id = Number(params[1]);
      const uid = Number(params[2]);
      const tc = trustedContacts.find((c) => c.id === id && c.user_id === uid);
      if (!tc) return ok([], 0);
      const ts = new Date().toISOString();
      tc.invitation_status = status;
      tc.responded_at = status === 'pending' ? null : ts;
      tc.updated_at = ts;
      return ok([{ ...tc }]);
    }

    if (sql.startsWith('UPDATE trusted_contacts SET name = $1')) {
      const id = Number(params[4]);
      const uid = Number(params[5]);
      const tc = trustedContacts.find((c) => c.id === id && c.user_id === uid);
      if (!tc) return ok([], 0);
      tc.name = String(params[0]);
      tc.email = String(params[1]);
      tc.phone = String(params[2] ?? '');
      tc.relationship = String(params[3]);
      tc.updated_at = new Date().toISOString();
      return ok([{ ...tc }]);
    }

    if (sql.startsWith('DELETE FROM trusted_contacts WHERE id = $1 AND user_id = $2')) {
      const id = Number(params[0]);
      const uid = Number(params[1]);
      const idx = trustedContacts.findIndex((c) => c.id === id && c.user_id === uid);
      if (idx === -1) return ok([], 0);
      trustedContacts.splice(idx, 1);
      for (const w of finalWishes) {
        if (w.assigned_contact_id === id) w.assigned_contact_id = null;
      }
      for (const m of memories) {
        if (m.trusted_contact_id === id) m.trusted_contact_id = null;
      }
      for (let i = legacyRequests.length - 1; i >= 0; i--) {
        if (legacyRequests[i].trusted_contact_id === id) legacyRequests.splice(i, 1);
      }
      return ok([], 1);
    }

    // -------------------------------------------------------------------------
    // Memories & Farewell Letters
    // -------------------------------------------------------------------------
    if (sql.includes('FROM memories m LEFT JOIN trusted_contacts tc ON tc.id = m.trusted_contact_id')) {
      const uid = Number(params[0]);
      const asc = sql.includes('ORDER BY m.id ASC');
      const rows = memories
        .filter((m) => m.user_id === uid)
        .sort((a, b) =>
          asc ? a.id - b.id : b.created_at.localeCompare(a.created_at) || b.id - a.id
        )
        .map((m) => {
          const tc =
            m.trusted_contact_id != null
              ? trustedContacts.find((c) => c.id === m.trusted_contact_id && c.user_id === uid)
              : undefined;
          return {
            ...m,
            contact_name: tc?.name ?? null,
            contact_email: tc?.email ?? null,
            contact_relationship: tc?.relationship ?? null,
          };
        });
      return ok(rows);
    }

    if (sql.includes('FROM memories WHERE user_id = $1 AND trusted_contact_id = $2')) {
      const uid = Number(params[0]);
      const cid = Number(params[1]);
      const rows = memories
        .filter((m) => m.user_id === uid && m.trusted_contact_id === cid)
        .sort((a, b) => a.id - b.id)
        .map((m) => ({
          id: m.id,
          title: m.title,
          message_body: m.message_body,
          custom_recipient: m.custom_recipient,
          release_condition: m.release_condition,
          created_at: m.created_at,
        }));
      return ok(rows);
    }

    if (sql.startsWith('INSERT INTO memories (')) {
      const ts = new Date().toISOString();
      const row: MemoryRow = {
        id: nextId.memories++,
        user_id: Number(params[0]),
        trusted_contact_id: params[1] === null ? null : Number(params[1]),
        custom_recipient: String(params[2] ?? ''),
        title: String(params[3]),
        message_body: String(params[4]),
        release_condition: String(params[5] ?? 'Upon verified admin approval'),
        created_at: ts,
        updated_at: ts,
      };
      memories.push(row);
      return ok([{ ...row }]);
    }

    if (sql.startsWith('UPDATE memories SET trusted_contact_id = $1')) {
      const id = Number(params[5]);
      const uid = Number(params[6]);
      const m = memories.find((x) => x.id === id && x.user_id === uid);
      if (!m) return ok([], 0);
      m.trusted_contact_id = params[0] === null ? null : Number(params[0]);
      m.custom_recipient = String(params[1] ?? '');
      m.title = String(params[2]);
      m.message_body = String(params[3]);
      m.release_condition = String(params[4] ?? 'Upon verified admin approval');
      m.updated_at = new Date().toISOString();
      return ok([{ ...m }]);
    }

    if (sql.startsWith('DELETE FROM memories WHERE id = $1 AND user_id = $2')) {
      const id = Number(params[0]);
      const uid = Number(params[1]);
      const idx = memories.findIndex((m) => m.id === id && m.user_id === uid);
      if (idx === -1) return ok([], 0);
      memories.splice(idx, 1);
      return ok([], 1);
    }

    // -------------------------------------------------------------------------
    // Legacy Requests
    // -------------------------------------------------------------------------
    if (sql.includes('FROM legacy_requests lr JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id WHERE lr.user_id = $1 AND LOWER(lr.requester_email) = LOWER($2)')) {
      const uid = Number(params[0]);
      const email = String(params[1]).toLowerCase();
      const rows = legacyRequests
        .filter((r) => r.user_id === uid && r.requester_email.toLowerCase() === email)
        .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id)
        .map((r) => {
          const tc = trustedContacts.find((c) => c.id === r.trusted_contact_id);
          return {
            id: r.id,
            request_code: r.request_code,
            status: r.status,
            reason: r.reason,
            verification_note: r.verification_note,
            admin_remarks: r.admin_remarks,
            created_at: r.created_at,
            reviewed_at: r.reviewed_at,
            trusted_contact_id: r.trusted_contact_id,
            contact_name: tc?.name ?? '',
            relationship: tc?.relationship ?? '',
          };
        });
      return ok(rows);
    }

    if (sql.startsWith("SELECT id, request_code FROM legacy_requests WHERE user_id = $1 AND trusted_contact_id = $2 AND status = 'pending'")) {
      const uid = Number(params[0]);
      const cid = Number(params[1]);
      const found = legacyRequests.find(
        (r) => r.user_id === uid && r.trusted_contact_id === cid && r.status === 'pending'
      );
      return ok(found ? [{ id: found.id, request_code: found.request_code }] : []);
    }

    if (sql.startsWith('INSERT INTO legacy_requests (')) {
      const ts = new Date().toISOString();
      const row: LegacyRequestRow = {
        id: nextId.legacy_requests++,
        request_code: String(params[0]),
        user_id: Number(params[1]),
        trusted_contact_id: Number(params[2]),
        requester_email: String(params[3]),
        reason: String(params[4]),
        verification_note: String(params[5]),
        status: 'pending',
        admin_remarks: '',
        reviewed_by: null,
        reviewed_at: null,
        created_at: ts,
        updated_at: ts,
      };
      legacyRequests.push(row);
      return ok([
        {
          id: row.id,
          request_code: row.request_code,
          status: row.status,
          reason: row.reason,
          verification_note: row.verification_note,
          created_at: row.created_at,
        },
      ]);
    }

    // Admin review fetch single request
    if (sql.includes('FROM legacy_requests lr JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id JOIN users u ON u.id = lr.user_id WHERE lr.id = $1')) {
      const rid = Number(params[0]);
      const r = legacyRequests.find((x) => x.id === rid);
      if (!r) return ok([]);
      const tc = trustedContacts.find((c) => c.id === r.trusted_contact_id);
      const u = users.find((x) => x.id === r.user_id);
      return ok([
        {
          id: r.id,
          request_code: r.request_code,
          user_id: r.user_id,
          requester_email: r.requester_email,
          contact_name: tc?.name ?? '',
          owner_name: u?.full_name ?? '',
        },
      ]);
    }

    // Admin list requests (all or filtered by status)
    if (sql.includes('FROM legacy_requests lr JOIN users u ON u.id = lr.user_id JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id')) {
      const statusFilter = params.length > 0 ? String(params[0]) : null;
      const rows = legacyRequests
        .filter((r) => (!statusFilter ? true : r.status === statusFilter))
        .sort((a, b) => {
          const ap = a.status === 'pending' ? 0 : 1;
          const bp = b.status === 'pending' ? 0 : 1;
          if (ap !== bp) return ap - bp;
          return b.created_at.localeCompare(a.created_at) || b.id - a.id;
        })
        .map((r) => {
          const u = users.find((x) => x.id === r.user_id);
          const tc = trustedContacts.find((c) => c.id === r.trusted_contact_id);
          const reviewer = r.reviewed_by != null ? adminUsers.find((a) => a.id === r.reviewed_by) : null;
          return {
            id: r.id,
            request_code: r.request_code,
            status: r.status,
            reason: r.reason,
            verification_note: r.verification_note,
            admin_remarks: r.admin_remarks,
            created_at: r.created_at,
            reviewed_at: r.reviewed_at,
            owner_name: u?.full_name ?? '',
            owner_email: u?.email ?? '',
            owner_handle: u?.user_handle ?? '',
            owner_last_check_in: u?.last_check_in ?? nowIso,
            owner_escalation_stage: u?.escalation_stage ?? 0,
            owner_days_inactive: u ? calcDaysInactive(u.last_check_in) : 0,
            contact_name: tc?.name ?? '',
            contact_email: tc?.email ?? '',
            contact_phone: tc?.phone ?? '',
            contact_relationship: tc?.relationship ?? '',
            contact_invitation_status: tc?.invitation_status ?? 'pending',
            reviewer_name: reviewer?.full_name ?? null,
            authorized_memories_count: memories.filter(
              (m) => m.user_id === r.user_id && m.trusted_contact_id === r.trusted_contact_id
            ).length,
            authorized_wishes_count: finalWishes.filter(
              (w) => w.user_id === r.user_id && w.assigned_contact_id === r.trusted_contact_id
            ).length,
          };
        });
      return ok(rows);
    }

    if (sql.startsWith('UPDATE legacy_requests SET status = $1, admin_remarks = $2, reviewed_by = $3')) {
      const decision = String(params[0]) as 'approved' | 'rejected';
      const remarks = String(params[1]);
      const adminId = Number(params[2]);
      const reqId = Number(params[3]);
      const r = legacyRequests.find((x) => x.id === reqId);
      if (!r) return ok([], 0);
      const ts = new Date().toISOString();
      r.status = decision;
      r.admin_remarks = remarks;
      r.reviewed_by = adminId;
      r.reviewed_at = ts;
      r.updated_at = ts;
      return ok([], 1);
    }

    // -------------------------------------------------------------------------
    // Admin Action Logs
    // -------------------------------------------------------------------------
    if (sql.includes('FROM admin_action_logs al JOIN admin_users au ON au.id = al.admin_id')) {
      const rows = [...adminActionLogs]
        .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id)
        .slice(0, 20)
        .map((al) => {
          const au = adminUsers.find((a) => a.id === al.admin_id);
          const lr = al.legacy_request_id != null ? legacyRequests.find((r) => r.id === al.legacy_request_id) : null;
          return {
            id: al.id,
            action: al.action,
            remarks: al.remarks,
            created_at: al.created_at,
            admin_name: au?.full_name ?? '',
            admin_email: au?.email ?? '',
            request_code: lr?.request_code ?? null,
          };
        });
      return ok(rows);
    }

    if (sql.startsWith('INSERT INTO admin_action_logs (')) {
      adminActionLogs.push({
        id: nextId.admin_action_logs++,
        admin_id: Number(params[0]),
        legacy_request_id: params[1] === null ? null : Number(params[1]),
        action: String(params[2]),
        remarks: String(params[3] ?? ''),
        created_at: new Date().toISOString(),
      });
      return ok([], 1);
    }

    console.warn('[MemoryVault InMemoryDB] Unhandled query:', sql);
    return ok([]);
  }

  return {
    query,
    async connect(): Promise<DbClient> {
      return {
        query,
        release() {
          // No-op for in-memory pool
        },
      };
    },
  };
}
