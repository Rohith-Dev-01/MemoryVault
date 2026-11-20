<?php
/**
 * MEMORY VAULT – Email Notification Wrapper with Database Fallback Logging
 *
 * Attempts native PHP mail() when ENABLE_PHP_MAIL=true (or can be extended with PHPMailer),
 * and ALWAYS logs every triggered notification to the `notification_logs` table so faculty
 * demos work reliably even without an active SMTP server.
 */

declare(strict_types=1);

/**
 * Send (or simulate) an email and record it in `notification_logs`.
 * Returns true if logged/sent, or false if skipped as a duplicate for the same cycle.
 */
function sendAndLogNotification(
    PDO $pdo,
    ?int $userId,
    string $recipientEmail,
    string $recipientRole,
    string $notificationType,
    string $subject,
    string $body,
    string $cycleId = '',
    bool $preventDuplicate = false
): bool {
    $recipientEmail = trim(strtolower($recipientEmail));

    if ($preventDuplicate && $userId !== null && $cycleId !== '') {
        $checkStmt = $pdo->prepare(
            'SELECT id FROM notification_logs
             WHERE user_id = :uid
               AND cycle_id = :cycle_id
               AND notification_type = :ntype
               AND LOWER(recipient_email) = :email
             LIMIT 1'
        );
        $checkStmt->execute([
            ':uid'      => $userId,
            ':cycle_id' => $cycleId,
            ':ntype'    => $notificationType,
            ':email'    => $recipientEmail,
        ]);

        if ($checkStmt->fetch()) {
            return false; // Already dispatched in this inactivity cycle
        }
    }

    $deliveryStatus = 'logged_demo_fallback';

    // Optional real mail dispatch when configured on a live mail-enabled server
    $enableMail = strtolower((string) (getenv('ENABLE_PHP_MAIL') ?: 'false')) === 'true';
    if ($enableMail && function_exists('mail')) {
        $headers = [
            'From: Memory Vault <no-reply@memoryvault.local>',
            'Content-Type: text/plain; charset=UTF-8',
            'X-Mailer: PHP/' . phpversion(),
        ];
        $sent = @mail($recipientEmail, $subject, $body, implode("\r\n", $headers));
        $deliveryStatus = $sent ? 'sent_via_mail' : 'logged_fallback';
    }

    $insertStmt = $pdo->prepare(
        'INSERT INTO notification_logs
            (user_id, recipient_email, recipient_role, notification_type, cycle_id, subject, body, delivery_status)
         VALUES
            (:uid, :email, :role, :ntype, :cycle_id, :subject, :body, :status)'
    );

    $insertStmt->execute([
        ':uid'      => $userId,
        ':email'    => $recipientEmail,
        ':role'     => $recipientRole,
        ':ntype'    => $notificationType,
        ':cycle_id' => $cycleId,
        ':subject'  => $subject,
        ':body'     => $body,
        ':status'   => $deliveryStatus,
    ]);

    return true;
}
