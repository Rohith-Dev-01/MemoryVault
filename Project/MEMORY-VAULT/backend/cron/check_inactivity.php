<?php
/**
 * MEMORY VAULT – 4-Stage Inactivity Monitoring Engine & Cron Script
 *
 * Escalation schedule:
 *   Stage 1 (Day 30): First reminder email to user
 *   Stage 2 (Day 35): Second reminder email to user
 *   Stage 3 (Day 40): Final reminder email to user
 *   Stage 4 (Day 45): Notify trusted contacts to check on the user
 *                     (Inactivity is NEVER proof of death; no vault contents are sent)
 *
 * Usage:
 *   1. CLI Cron: php backend/cron/check_inactivity.php
 *   2. Included helper: evaluateInactivityForUser($pdo, $userId)
 *   3. HTTP trigger (authenticated user/admin demo): GET/POST backend/cron/check_inactivity.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/mailer.php';

/**
 * Evaluate a single user's inactivity duration and trigger all newly reached escalation stages.
 * Deduplicates notifications per (user_id, inactivity_cycle_id, notification_type, recipient_email).
 */
function evaluateInactivityForUser(PDO $pdo, int $userId): array
{
    $stmt = $pdo->prepare(
        'SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in,
                u.escalation_stage, u.inactivity_cycle_id,
                FLOOR(EXTRACT(EPOCH FROM (NOW() - u.last_check_in)) / 86400)::INT AS days_inactive,
                COALESCE(lp.first_reminder_days, 30) AS first_days,
                COALESCE(lp.second_reminder_days, 35) AS second_days,
                COALESCE(lp.final_reminder_days, 40) AS final_days,
                COALESCE(lp.trusted_alert_days, 45) AS alert_days
         FROM users u
         LEFT JOIN legacy_plans lp ON lp.user_id = u.id
         WHERE u.id = :uid
         LIMIT 1'
    );
    $stmt->execute([':uid' => $userId]);
    $user = $stmt->fetch();

    if (!$user) {
        return ['evaluated' => false, 'triggered' => []];
    }

    $daysInactive = max(0, (int) $user['days_inactive']);
    $currentStage = (int) $user['escalation_stage'];
    $cycleId      = (string) $user['inactivity_cycle_id'];
    $newStage     = $currentStage;
    $triggered    = [];

    $firstDays  = (int) $user['first_days'];
    $secondDays = (int) $user['second_days'];
    $finalDays  = (int) $user['final_days'];
    $alertDays  = (int) $user['alert_days'];

    // Stage 1: Day 30 First Reminder
    if ($daysInactive >= $firstDays && $currentStage < 1) {
        $logged = sendAndLogNotification(
            $pdo,
            $userId,
            $user['email'],
            'user',
            'day_30_reminder',
            'Memory Vault — First Activity Check-In Reminder (Day 30)',
            "Hello {$user['full_name']},\n\nIt has been {$daysInactive} days since your last check-in on Memory Vault. Please sign in or click 'Check In Now' on your dashboard to confirm you are active.\n\nNo information has been shared with your trusted contacts.",
            $cycleId,
            true
        );
        $newStage = max($newStage, 1);
        if ($logged) {
            $triggered[] = [
                'stage'   => 1,
                'type'    => 'day_30_reminder',
                'recipient' => $user['email'],
                'summary' => 'Day 30 first reminder sent to vault owner.',
            ];
        }
    }

    // Stage 2: Day 35 Second Reminder
    if ($daysInactive >= $secondDays && $currentStage < 2) {
        $logged = sendAndLogNotification(
            $pdo,
            $userId,
            $user['email'],
            'user',
            'day_35_reminder',
            'Memory Vault — Second Activity Check-In Reminder (Day 35)',
            "Hello {$user['full_name']},\n\nThis is your second reminder ({$daysInactive} days inactive). Please sign in to Memory Vault to reset your inactivity timer. If no check-in is received by Day {$alertDays}, your trusted contacts will be asked to check on your well-being.",
            $cycleId,
            true
        );
        $newStage = max($newStage, 2);
        if ($logged) {
            $triggered[] = [
                'stage'   => 2,
                'type'    => 'day_35_reminder',
                'recipient' => $user['email'],
                'summary' => 'Day 35 second reminder sent to vault owner.',
            ];
        }
    }

    // Stage 3: Day 40 Final Reminder
    if ($daysInactive >= $finalDays && $currentStage < 3) {
        $logged = sendAndLogNotification(
            $pdo,
            $userId,
            $user['email'],
            'user',
            'day_40_reminder',
            'Memory Vault — Final Activity Check-In Reminder (Day 40)',
            "Hello {$user['full_name']},\n\nFinal reminder: your Memory Vault account has been inactive for {$daysInactive} days. Please sign in within the next 5 days to reset your timer. Otherwise, at Day {$alertDays}, we will ask your trusted contacts to reach out and check on you.",
            $cycleId,
            true
        );
        $newStage = max($newStage, 3);
        if ($logged) {
            $triggered[] = [
                'stage'   => 3,
                'type'    => 'day_40_reminder',
                'recipient' => $user['email'],
                'summary' => 'Day 40 final reminder sent to vault owner.',
            ];
        }
    }

    // Stage 4: Day 45 Trusted Contacts Wellness Alert
    if ($daysInactive >= $alertDays && $currentStage < 4) {
        $contactsStmt = $pdo->prepare(
            "SELECT id, name, email, invitation_status
             FROM trusted_contacts
             WHERE user_id = :uid
               AND invitation_status != 'declined'"
        );
        $contactsStmt->execute([':uid' => $userId]);
        $contacts = $contactsStmt->fetchAll();

        foreach ($contacts as $contact) {
            $logged = sendAndLogNotification(
                $pdo,
                $userId,
                $contact['email'],
                'trusted_contact',
                'day_45_trusted_alert',
                "Memory Vault Wellness Check — Please Check on {$user['full_name']}",
                "Hello {$contact['name']},\n\n{$user['full_name']} listed you as a Trusted Contact on Memory Vault and has not checked in for {$daysInactive} days (after 3 reminder notices).\n\nIMPORTANT: Inactivity is NOT proof of death and no private vault records have been released. Please check on {$user['full_name']} directly. Only if a verified legacy event has occurred may you submit a formal Legacy Access Request for administrative review.",
                $cycleId,
                true
            );
            if ($logged) {
                $triggered[] = [
                    'stage'     => 4,
                    'type'      => 'day_45_trusted_alert',
                    'recipient' => $contact['email'],
                    'summary'   => "Day 45 wellness alert sent to trusted contact {$contact['name']} ({$contact['email']}).",
                ];
            }
        }

        // Also log a summary notice if user has no contacts yet
        if (count($contacts) === 0) {
            $logged = sendAndLogNotification(
                $pdo,
                $userId,
                $user['email'],
                'system',
                'day_45_no_contacts',
                'Memory Vault — Day 45 Escalation Reached (No Active Trusted Contacts)',
                "Account for {$user['full_name']} reached Day {$daysInactive} of inactivity, but no active trusted contacts were configured to notify.",
                $cycleId,
                true
            );
            if ($logged) {
                $triggered[] = [
                    'stage'     => 4,
                    'type'      => 'day_45_no_contacts',
                    'recipient' => $user['email'],
                    'summary'   => 'Day 45 reached; no active trusted contacts configured.',
                ];
            }
        }

        $newStage = max($newStage, 4);
    }

    if ($newStage !== $currentStage) {
        $upd = $pdo->prepare(
            'UPDATE users
             SET escalation_stage = :stage, updated_at = NOW()
             WHERE id = :uid'
        );
        $upd->execute([
            ':stage' => $newStage,
            ':uid'   => $userId,
        ]);
    }

    return [
        'evaluated'     => true,
        'user_id'       => $userId,
        'days_inactive' => $daysInactive,
        'stage'         => $newStage,
        'triggered'     => $triggered,
    ];
}

/**
 * Evaluate all users in the database.
 */
function evaluateInactivityForAllUsers(PDO $pdo): array
{
    $stmt = $pdo->query('SELECT id FROM users ORDER BY id ASC');
    $userIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $results = [];

    foreach ($userIds as $uid) {
        $results[] = evaluateInactivityForUser($pdo, (int) $uid);
    }

    return $results;
}

// Direct execution entry point (CLI or direct HTTP call)
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $isCli = (PHP_SAPI === 'cli');

    if (!$isCli) {
        require_once __DIR__ . '/../includes/auth_middleware.php';
        if (empty($_SESSION['user_id']) && empty($_SESSION['admin_id'])) {
            jsonResponse([
                'success' => false,
                'error'   => 'Authentication required to trigger inactivity monitoring via HTTP.',
            ], 401);
        }
    }

    $pdo = getDbConnection();
    $results = evaluateInactivityForAllUsers($pdo);

    if ($isCli) {
        echo "Memory Vault Inactivity Check Completed (" . gmdate('c') . ")\n";
        echo json_encode($results, JSON_PRETTY_PRINT) . "\n";
    } else {
        jsonResponse([
            'success'      => true,
            'evaluated_at' => gmdate('c'),
            'results'      => $results,
        ]);
    }
}
