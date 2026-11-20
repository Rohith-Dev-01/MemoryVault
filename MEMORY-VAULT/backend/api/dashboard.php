<?php
/**
 * MEMORY VAULT – Dashboard, Check-In & Faculty Demo Inactivity Simulator API
 *
 * Endpoints:
 *   GET  (default)                  -> Dashboard metrics, completion %, status, notification logs
 *   POST ?action=checkin            -> Reset last_check_in to NOW() and clear escalation stage
 *   POST ?action=simulate_inactivity -> Shift last_check_in by 0|30|35|40|45 days & run monitoring engine
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';
require_once __DIR__ . '/../includes/mailer.php';
require_once __DIR__ . '/../cron/check_inactivity.php';

$userId = requireUserAuth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? '';
$pdo    = getDbConnection();

/**
 * Assemble live dashboard metrics and notification logs for the signed-in user.
 */
function buildDashboardPayload(PDO $pdo, int $userId): array
{
    $userStmt = $pdo->prepare(
        'SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in,
                u.escalation_stage, u.inactivity_cycle_id, u.created_at,
                FLOOR(EXTRACT(EPOCH FROM (NOW() - u.last_check_in)) / 86400)::INT AS days_inactive,
                COALESCE(lp.first_reminder_days, 30) AS first_reminder_days,
                COALESCE(lp.second_reminder_days, 35) AS second_reminder_days,
                COALESCE(lp.final_reminder_days, 40) AS final_reminder_days,
                COALESCE(lp.trusted_alert_days, 45) AS trusted_alert_days,
                COALESCE(lp.general_guidance, \'\') AS general_guidance
         FROM users u
         LEFT JOIN legacy_plans lp ON lp.user_id = u.id
         WHERE u.id = :uid
         LIMIT 1'
    );
    $userStmt->execute([':uid' => $userId]);
    $user = $userStmt->fetch();

    $countFor = static function (string $sql) use ($pdo, $userId): int {
        $s = $pdo->prepare($sql);
        $s->execute([':uid' => $userId]);
        return (int) $s->fetchColumn();
    };

    $assetsCount      = $countFor('SELECT COUNT(*) FROM digital_assets WHERE user_id = :uid');
    $wishesCount      = $countFor('SELECT COUNT(*) FROM final_wishes WHERE user_id = :uid');
    $contactsCount    = $countFor('SELECT COUNT(*) FROM trusted_contacts WHERE user_id = :uid');
    $acceptedContacts = $countFor("SELECT COUNT(*) FROM trusted_contacts WHERE user_id = :uid AND invitation_status = 'accepted'");
    $memoriesCount    = $countFor('SELECT COUNT(*) FROM memories WHERE user_id = :uid');

    // Calculate dynamic plan completion percentage (25% per pillar)
    $scoreAssets   = $assetsCount > 0 ? 25 : 0;
    $scoreWishes   = ($assetsCount > 0 && $wishesCount > 0)
        ? (int) round(25 * min(1, $wishesCount / $assetsCount))
        : 0;
    $scoreContacts = $acceptedContacts > 0 ? 25 : ($contactsCount > 0 ? 15 : 0);
    $scoreMemories = $memoriesCount > 0 ? 25 : 0;
    $completionPct = min(100, $scoreAssets + $scoreWishes + $scoreContacts + $scoreMemories);

    $daysInactive = max(0, (int) $user['days_inactive']);
    $stage        = (int) $user['escalation_stage'];

    $statusMap = [
        0 => ['label' => 'Active', 'tone' => 'success'],
        1 => ['label' => 'Day 30 — First Reminder Sent', 'tone' => 'warning'],
        2 => ['label' => 'Day 35 — Second Reminder Sent', 'tone' => 'warning'],
        3 => ['label' => 'Day 40 — Final Reminder Sent', 'tone' => 'warning'],
        4 => ['label' => 'Day 45+ — Trusted Contacts Notified', 'tone' => 'error'],
    ];
    $statusInfo = $statusMap[$stage] ?? $statusMap[0];

    // Compute next reminder date based on current escalation stage
    $lastCheckInTs = strtotime((string) $user['last_check_in']);
    $nextOffsetDays = (int) $user['first_reminder_days'];
    if ($stage === 1) {
        $nextOffsetDays = (int) $user['second_reminder_days'];
    } elseif ($stage === 2) {
        $nextOffsetDays = (int) $user['final_reminder_days'];
    } elseif ($stage === 3) {
        $nextOffsetDays = (int) $user['trusted_alert_days'];
    } elseif ($stage >= 4) {
        $nextOffsetDays = (int) $user['trusted_alert_days'];
    }
    $nextReminderIso = gmdate('c', $lastCheckInTs + ($nextOffsetDays * 86400));

    $logsStmt = $pdo->prepare(
        'SELECT id, recipient_email, recipient_role, notification_type, cycle_id, subject, body, delivery_status, created_at
         FROM notification_logs
         WHERE user_id = :uid
         ORDER BY created_at DESC, id DESC
         LIMIT 15'
    );
    $logsStmt->execute([':uid' => $userId]);
    $logs = $logsStmt->fetchAll();

    return [
        'user' => [
            'id'               => (int) $user['id'],
            'user_handle'      => $user['user_handle'],
            'full_name'        => $user['full_name'],
            'email'            => $user['email'],
            'last_check_in'    => $user['last_check_in'],
            'escalation_stage' => $stage,
        ],
        'metrics' => [
            'total_assets'        => $assetsCount,
            'total_wishes'        => $wishesCount,
            'total_contacts'      => $contactsCount,
            'accepted_contacts'   => $acceptedContacts,
            'total_memories'      => $memoriesCount,
            'completion_percent'  => $completionPct,
            'days_inactive'       => $daysInactive,
            'last_check_in'       => $user['last_check_in'],
            'next_reminder_date'  => $nextReminderIso,
            'status_label'        => $statusInfo['label'],
            'status_tone'         => $statusInfo['tone'],
            'escalation_stage'    => $stage,
        ],
        'plan' => [
            'first_reminder_days'  => (int) $user['first_reminder_days'],
            'second_reminder_days' => (int) $user['second_reminder_days'],
            'final_reminder_days'  => (int) $user['final_reminder_days'],
            'trusted_alert_days'   => (int) $user['trusted_alert_days'],
            'general_guidance'     => $user['general_guidance'],
        ],
        'recent_notifications' => $logs,
    ];
}

if ($method === 'GET') {
    jsonResponse([
        'success' => true,
        'data'    => buildDashboardPayload($pdo, $userId),
    ]);
}

if ($method === 'POST') {
    verifyCsrfToken();

    // POST ?action=checkin
    if ($action === 'checkin') {
        $newCycle = 'cycle_' . bin2hex(random_bytes(8));
        $upd = $pdo->prepare(
            'UPDATE users
             SET last_check_in = NOW(),
                 escalation_stage = 0,
                 inactivity_cycle_id = :cycle,
                 updated_at = NOW()
             WHERE id = :uid
             RETURNING email, full_name'
        );
        $upd->execute([':cycle' => $newCycle, ':uid' => $userId]);
        $row = $upd->fetch();

        sendAndLogNotification(
            $pdo,
            $userId,
            $row['email'],
            'user',
            'check_in_reset',
            'Memory Vault — Manual Check-In Confirmed',
            "Hello {$row['full_name']}, your manual check-in succeeded. Your inactivity timer has been reset to Day 0 and all pending escalation reminders have been cleared.",
            $newCycle,
            false
        );

        jsonResponse([
            'success' => true,
            'message' => 'Check-in confirmed. Your inactivity timer is reset to Active (Day 0).',
            'data'    => buildDashboardPayload($pdo, $userId),
        ]);
    }

    // POST ?action=simulate_inactivity
    if ($action === 'simulate_inactivity') {
        $input = getJsonInput();
        $days  = (int) ($input['days'] ?? 0);

        if (!in_array($days, [0, 30, 35, 40, 45, 46], true)) {
            jsonResponse(['success' => false, 'error' => 'Allowed simulation values are 0, 30, 35, 40, or 45+ days.'], 422);
        }

        if ($days === 0) {
            // Reset cleanly back to active state
            $newCycle = 'cycle_' . bin2hex(random_bytes(8));
            $upd = $pdo->prepare(
                'UPDATE users
                 SET last_check_in = NOW(),
                     escalation_stage = 0,
                     inactivity_cycle_id = :cycle,
                     updated_at = NOW()
                 WHERE id = :uid'
            );
            $upd->execute([':cycle' => $newCycle, ':uid' => $userId]);

            jsonResponse([
                'success'   => true,
                'message'   => 'Demo simulation reset to 0 days (Active).',
                'triggered' => [],
                'data'      => buildDashboardPayload($pdo, $userId),
            ]);
        }

        // Set last_check_in back by N days and start a fresh demo cycle if moving backwards or starting from 0
        $currStmt = $pdo->prepare('SELECT escalation_stage, inactivity_cycle_id FROM users WHERE id = :uid');
        $currStmt->execute([':uid' => $userId]);
        $curr = $currStmt->fetch();

        $targetStage = 0;
        if ($days >= 45) {
            $targetStage = 4;
        } elseif ($days >= 40) {
            $targetStage = 3;
        } elseif ($days >= 35) {
            $targetStage = 2;
        } elseif ($days >= 30) {
            $targetStage = 1;
        }

        $cycleId = (string) $curr['inactivity_cycle_id'];
        $resetStage = (int) $curr['escalation_stage'];

        // If user clicks a stage lower than or equal to current stage, begin a clean demo cycle so faculty sees the alerts trigger cleanly
        if ($targetStage <= $resetStage) {
            $cycleId    = 'sim_' . bin2hex(random_bytes(6));
            $resetStage = 0;
        }

        $upd = $pdo->prepare(
            "UPDATE users
             SET last_check_in = NOW() - (:days || ' days')::INTERVAL,
                 escalation_stage = :stage,
                 inactivity_cycle_id = :cycle,
                 updated_at = NOW()
             WHERE id = :uid"
        );
        $upd->execute([
            ':days'  => $days,
            ':stage' => $resetStage,
            ':cycle' => $cycleId,
            ':uid'   => $userId,
        ]);

        // Run the real inactivity monitoring engine immediately
        $evalResult = evaluateInactivityForUser($pdo, $userId);

        jsonResponse([
            'success'   => true,
            'message'   => "Simulated {$days} days of inactivity and executed check_inactivity.php.",
            'triggered' => $evalResult['triggered'] ?? [],
            'data'      => buildDashboardPayload($pdo, $userId),
        ]);
    }
}

jsonResponse(['success' => false, 'error' => 'Unsupported request.'], 405);
