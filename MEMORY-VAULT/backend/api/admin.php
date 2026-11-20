<?php
/**
 * MEMORY VAULT – Administrator Verification & Audit Panel API
 *
 * Endpoints:
 *   GET  (?status=all|pending|approved|rejected) -> List requests, stats & audit trail
 *   POST ?action=review                          -> Approve or reject a request with remarks & audit log
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';
require_once __DIR__ . '/../includes/mailer.php';

$adminId = requireAdminAuth();
$method  = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action  = $_GET['action'] ?? '';
$pdo     = getDbConnection();

// GET — Admin dashboard overview, legacy requests queue, and audit logs
if ($method === 'GET') {
    $statusFilter = cleanString($_GET['status'] ?? 'all', 20);
    $validFilters = ['all', 'pending', 'approved', 'rejected'];
    if (!in_array($statusFilter, $validFilters, true)) {
        $statusFilter = 'all';
    }

    $adminStmt = $pdo->prepare('SELECT id, full_name, email, role FROM admin_users WHERE id = :aid LIMIT 1');
    $adminStmt->execute([':aid' => $adminId]);
    $admin = $adminStmt->fetch();

    // Queue counts
    $counts = ['pending' => 0, 'approved' => 0, 'rejected' => 0];
    $cStmt = $pdo->query('SELECT status, COUNT(*)::INT AS cnt FROM legacy_requests GROUP BY status');
    foreach ($cStmt->fetchAll() as $row) {
        $counts[$row['status']] = (int) $row['cnt'];
    }
    $totalUsers = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $totalNotifs = (int) $pdo->query('SELECT COUNT(*) FROM notification_logs')->fetchColumn();

    // Fetch legacy requests with owner, contact, and authorized item counts
    $sql = 'SELECT lr.id, lr.request_code, lr.status, lr.reason, lr.verification_note,
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
            LEFT JOIN admin_users au ON au.id = lr.reviewed_by';

    $params = [];
    if ($statusFilter !== 'all') {
        $sql .= ' WHERE lr.status = :status';
        $params[':status'] = $statusFilter;
    }
    $sql .= " ORDER BY CASE WHEN lr.status = 'pending' THEN 0 ELSE 1 END, lr.created_at DESC, lr.id DESC";

    $reqStmt = $pdo->prepare($sql);
    $reqStmt->execute($params);
    $requests = $reqStmt->fetchAll();

    // Recent admin audit trail
    $auditStmt = $pdo->query(
        'SELECT al.id, al.action, al.remarks, al.created_at,
                au.full_name AS admin_name, au.email AS admin_email,
                lr.request_code
         FROM admin_action_logs al
         JOIN admin_users au ON au.id = al.admin_id
         LEFT JOIN legacy_requests lr ON lr.id = al.legacy_request_id
         ORDER BY al.created_at DESC, al.id DESC
         LIMIT 20'
    );
    $auditLogs = $auditStmt->fetchAll();

    // Recent notification logs
    $notifStmt = $pdo->query(
        'SELECT id, recipient_email, recipient_role, notification_type, subject, delivery_status, created_at
         FROM notification_logs
         ORDER BY created_at DESC, id DESC
         LIMIT 15'
    );
    $notifications = $notifStmt->fetchAll();

    jsonResponse([
        'success' => true,
        'admin'   => $admin,
        'stats'   => [
            'pending'             => $counts['pending'],
            'approved'            => $counts['approved'],
            'rejected'            => $counts['rejected'],
            'total_users'         => $totalUsers,
            'total_notifications' => $totalNotifs,
        ],
        'requests'      => $requests,
        'audit_logs'    => $auditLogs,
        'notifications' => $notifications,
    ]);
}

// POST ?action=review — Approve or reject a legacy access request
if ($method === 'POST' && $action === 'review') {
    verifyCsrfToken();
    $input = getJsonInput();

    $requestId = (int) ($input['request_id'] ?? 0);
    $decision  = cleanString($input['decision'] ?? '', 20);
    $remarks   = cleanString($input['admin_remarks'] ?? '', 2000);

    if ($requestId <= 0 || !in_array($decision, ['approved', 'rejected'], true)) {
        jsonResponse(['success' => false, 'error' => 'Valid request ID and decision (approved or rejected) are required.'], 422);
    }
    if (mb_strlen($remarks) < 4) {
        jsonResponse(['success' => false, 'error' => 'Please enter administrative review remarks for the audit trail.'], 422);
    }

    $fetchStmt = $pdo->prepare(
        'SELECT lr.id, lr.request_code, lr.user_id, lr.requester_email,
                tc.name AS contact_name, u.full_name AS owner_name
         FROM legacy_requests lr
         JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id
         JOIN users u ON u.id = lr.user_id
         WHERE lr.id = :rid
         LIMIT 1'
    );
    $fetchStmt->execute([':rid' => $requestId]);
    $req = $fetchStmt->fetch();

    if (!$req) {
        jsonResponse(['success' => false, 'error' => 'Legacy access request not found.'], 404);
    }

    $pdo->beginTransaction();
    try {
        $upd = $pdo->prepare(
            'UPDATE legacy_requests
             SET status = :status,
                 admin_remarks = :remarks,
                 reviewed_by = :aid,
                 reviewed_at = NOW(),
                 updated_at = NOW()
             WHERE id = :rid'
        );
        $upd->execute([
            ':status'  => $decision,
            ':remarks' => $remarks,
            ':aid'     => $adminId,
            ':rid'     => $requestId,
        ]);

        $audit = $pdo->prepare(
            'INSERT INTO admin_action_logs (admin_id, legacy_request_id, action, remarks)
             VALUES (:aid, :rid, :action, :remarks)'
        );
        $audit->execute([
            ':aid'     => $adminId,
            ':rid'     => $requestId,
            ':action'  => 'request_' . $decision,
            ':remarks' => $remarks,
        ]);

        $subject = $decision === 'approved'
            ? "Legacy Access Request Approved ({$req['request_code']})"
            : "Legacy Access Request Reviewed — Not Approved ({$req['request_code']})";

        $body = $decision === 'approved'
            ? "Hello {$req['contact_name']},\n\nYour Legacy Access Request ({$req['request_code']}) for {$req['owner_name']}'s Memory Vault has been APPROVED after administrative verification.\n\nRemarks: {$remarks}\n\nYou may now return to the Legacy Access Portal using your email and the owner's identifier to view ONLY the memories and final wishes explicitly designated for you."
            : "Hello {$req['contact_name']},\n\nYour Legacy Access Request ({$req['request_code']}) for {$req['owner_name']}'s Memory Vault was NOT approved.\n\nRemarks: {$remarks}\n\nAll private vault records remain sealed.";

        sendAndLogNotification(
            $pdo,
            (int) $req['user_id'],
            $req['requester_email'],
            'trusted_contact',
            'legacy_request_' . $decision,
            $subject,
            $body,
            '',
            false
        );

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        jsonResponse(['success' => false, 'error' => 'Could not record review decision.'], 500);
    }

    jsonResponse([
        'success' => true,
        'message' => "Request {$req['request_code']} marked as {$decision} and recorded in the audit log.",
    ]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
