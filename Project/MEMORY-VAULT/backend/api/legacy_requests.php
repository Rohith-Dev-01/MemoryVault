<?php
/**
 * MEMORY VAULT – Legacy Access Requests & Printable Summary API
 *
 * IMPORTANT SECURITY RULE:
 * Inactivity is NOT proof of death. Private memories and final wishes are NEVER
 * released unless an administrator explicitly approves the request, and ONLY the
 * specific items authorized for that trusted contact are returned.
 *
 * Endpoints:
 *   GET  ?action=summary                                       -> Authenticated user's complete printable report
 *   GET  ?action=lookup&contact_email=...&owner_identifier=... -> Trusted contact status & authorized items (if approved)
 *   POST ?action=submit                                        -> Trusted contact submits a legacy access request
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';
require_once __DIR__ . '/../includes/mailer.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? '';
$pdo    = getDbConnection();

// 1. GET ?action=summary — Complete printable legacy summary for the signed-in user
if ($method === 'GET' && $action === 'summary') {
    $userId = requireUserAuth();

    $uStmt = $pdo->prepare(
        'SELECT u.id, u.user_handle, u.full_name, u.email, u.last_check_in,
                u.escalation_stage, u.created_at,
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
    $uStmt->execute([':uid' => $userId]);
    $user = $uStmt->fetch();

    $assetsStmt = $pdo->prepare(
        'SELECT a.id, a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                w.action_type, w.custom_instructions, tc.name AS assigned_contact_name
         FROM digital_assets a
         LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
         LEFT JOIN trusted_contacts tc ON tc.id = w.assigned_contact_id AND tc.user_id = a.user_id
         WHERE a.user_id = :uid
         ORDER BY a.id ASC'
    );
    $assetsStmt->execute([':uid' => $userId]);
    $assets = $assetsStmt->fetchAll();

    $contactsStmt = $pdo->prepare(
        'SELECT id, name, email, phone, relationship, invitation_status, responded_at
         FROM trusted_contacts
         WHERE user_id = :uid
         ORDER BY id ASC'
    );
    $contactsStmt->execute([':uid' => $userId]);
    $contacts = $contactsStmt->fetchAll();

    $memoriesStmt = $pdo->prepare(
        'SELECT m.id, m.title, m.message_body, m.custom_recipient, m.release_condition, m.created_at,
                tc.name AS contact_name, tc.relationship AS contact_relationship
         FROM memories m
         LEFT JOIN trusted_contacts tc ON tc.id = m.trusted_contact_id AND tc.user_id = m.user_id
         WHERE m.user_id = :uid
         ORDER BY m.id ASC'
    );
    $memoriesStmt->execute([':uid' => $userId]);
    $memories = $memoriesStmt->fetchAll();

    jsonResponse([
        'success' => true,
        'summary' => [
            'generated_at' => gmdate('c'),
            'user'         => $user,
            'assets'       => $assets,
            'contacts'     => $contacts,
            'memories'     => $memories,
        ],
    ]);
}

// 2. GET ?action=lookup — Trusted Contact checks request status & views ONLY approved authorized items
if ($method === 'GET' && $action === 'lookup') {
    $contactEmail    = strtolower(cleanString($_GET['contact_email'] ?? '', 180));
    $ownerIdentifier = cleanString($_GET['owner_identifier'] ?? '', 180);

    if (!filter_var($contactEmail, FILTER_VALIDATE_EMAIL) || $ownerIdentifier === '') {
        jsonResponse(['success' => false, 'error' => 'Please enter your trusted contact email and the vault owner email or User ID.'], 422);
    }

    $ownerStmt = $pdo->prepare(
        'SELECT id, full_name, user_handle, email
         FROM users
         WHERE LOWER(email) = LOWER(:id1) OR LOWER(user_handle) = LOWER(:id2)
         LIMIT 1'
    );
    $ownerStmt->execute([':id1' => $ownerIdentifier, ':id2' => $ownerIdentifier]);
    $owner = $ownerStmt->fetch();

    if (!$owner) {
        jsonResponse(['success' => false, 'error' => 'No matching request records found for those details.'], 404);
    }

    $reqStmt = $pdo->prepare(
        'SELECT lr.id, lr.request_code, lr.status, lr.reason, lr.verification_note,
                lr.admin_remarks, lr.created_at, lr.reviewed_at,
                lr.trusted_contact_id, tc.name AS contact_name, tc.relationship
         FROM legacy_requests lr
         JOIN trusted_contacts tc ON tc.id = lr.trusted_contact_id
         WHERE lr.user_id = :uid
           AND LOWER(lr.requester_email) = LOWER(:email)
         ORDER BY lr.created_at DESC, lr.id DESC'
    );
    $reqStmt->execute([':uid' => (int) $owner['id'], ':email' => $contactEmail]);
    $requests = $reqStmt->fetchAll();

    $enriched = [];
    foreach ($requests as $req) {
        $authorizedMemories = [];
        $authorizedWishes   = [];

        // STRICT RULE: Release ONLY when explicitly approved by an administrator
        if ($req['status'] === 'approved') {
            $memStmt = $pdo->prepare(
                'SELECT id, title, message_body, custom_recipient, release_condition, created_at
                 FROM memories
                 WHERE user_id = :uid AND trusted_contact_id = :cid
                 ORDER BY id ASC'
            );
            $memStmt->execute([
                ':uid' => (int) $owner['id'],
                ':cid' => (int) $req['trusted_contact_id'],
            ]);
            $authorizedMemories = $memStmt->fetchAll();

            $wishStmt = $pdo->prepare(
                'SELECT a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                        w.action_type, w.custom_instructions
                 FROM final_wishes w
                 JOIN digital_assets a ON a.id = w.asset_id
                 WHERE w.user_id = :uid AND w.assigned_contact_id = :cid
                 ORDER BY a.id ASC'
            );
            $wishStmt->execute([
                ':uid' => (int) $owner['id'],
                ':cid' => (int) $req['trusted_contact_id'],
            ]);
            $authorizedWishes = $wishStmt->fetchAll();
        }

        $req['authorized_memories'] = $authorizedMemories;
        $req['authorized_wishes']   = $authorizedWishes;
        $enriched[] = $req;
    }

    jsonResponse([
        'success'  => true,
        'owner'    => [
            'full_name'   => $owner['full_name'],
            'user_handle' => $owner['user_handle'],
        ],
        'requests' => $enriched,
    ]);
}

// 3. POST ?action=submit — Trusted Contact submits a formal Legacy Access Request
if ($method === 'POST' && $action === 'submit') {
    verifyCsrfToken();
    $input = getJsonInput();

    $contactEmail     = strtolower(cleanString($input['contact_email'] ?? '', 180));
    $ownerIdentifier  = cleanString($input['owner_identifier'] ?? '', 180);
    $reason           = cleanString($input['reason'] ?? '', 200);
    $verificationNote = cleanString($input['verification_note'] ?? '', 2500);

    if (!filter_var($contactEmail, FILTER_VALIDATE_EMAIL) || $ownerIdentifier === '' || $reason === '' || mb_strlen($verificationNote) < 10) {
        jsonResponse([
            'success' => false,
            'error'   => 'Please provide your email, the vault owner email or User ID, a reason, and a verification note (minimum 10 characters).',
        ], 422);
    }

    // Locate vault owner
    $ownerStmt = $pdo->prepare(
        'SELECT id, full_name, email FROM users
         WHERE LOWER(email) = LOWER(:id1) OR LOWER(user_handle) = LOWER(:id2)
         LIMIT 1'
    );
    $ownerStmt->execute([':id1' => $ownerIdentifier, ':id2' => $ownerIdentifier]);
    $owner = $ownerStmt->fetch();

    if (!$owner) {
        jsonResponse(['success' => false, 'error' => 'We could not verify that vault owner and trusted contact combination.'], 404);
    }

    // Verify requester is a registered trusted contact (and did not decline)
    $tcStmt = $pdo->prepare(
        "SELECT id, name, email, invitation_status
         FROM trusted_contacts
         WHERE user_id = :uid AND LOWER(email) = LOWER(:email)
         LIMIT 1"
    );
    $tcStmt->execute([':uid' => (int) $owner['id'], ':email' => $contactEmail]);
    $contact = $tcStmt->fetch();

    if (!$contact) {
        jsonResponse([
            'success' => false,
            'error'   => 'Only registered Trusted Contacts of the vault owner may submit a legacy access request.',
        ], 403);
    }
    if ($contact['invitation_status'] === 'declined') {
        jsonResponse([
            'success' => false,
            'error'   => 'This trusted contact invitation was declined and cannot submit access requests.',
        ], 403);
    }

    // Prevent duplicate simultaneous pending requests
    $pendingCheck = $pdo->prepare(
        "SELECT id, request_code FROM legacy_requests
         WHERE user_id = :uid AND trusted_contact_id = :cid AND status = 'pending'
         LIMIT 1"
    );
    $pendingCheck->execute([':uid' => (int) $owner['id'], ':cid' => (int) $contact['id']]);
    if ($existing = $pendingCheck->fetch()) {
        jsonResponse([
            'success' => false,
            'error'   => "A pending legacy access request ({$existing['request_code']}) is already awaiting administrative review.",
        ], 409);
    }

    $requestCode = 'REQ-' . gmdate('Y') . '-' . random_int(1000, 9999);

    $ins = $pdo->prepare(
        'INSERT INTO legacy_requests
            (request_code, user_id, trusted_contact_id, requester_email, reason, verification_note, status)
         VALUES
            (:code, :uid, :cid, :email, :reason, :note, \'pending\')
         RETURNING id, request_code, status, reason, verification_note, created_at'
    );
    $ins->execute([
        ':code'   => $requestCode,
        ':uid'    => (int) $owner['id'],
        ':cid'    => (int) $contact['id'],
        ':email'  => $contactEmail,
        ':reason' => $reason,
        ':note'   => $verificationNote,
    ]);
    $created = $ins->fetch();

    // Log notification for admin review & requester confirmation
    sendAndLogNotification(
        $pdo,
        (int) $owner['id'],
        $contactEmail,
        'trusted_contact',
        'legacy_request_submitted',
        "Legacy Access Request Received ({$requestCode})",
        "Hello {$contact['name']},\n\nYour Legacy Access Request ({$requestCode}) for {$owner['full_name']}'s vault has been recorded with status PENDING.\n\nNo private data is released until an administrator manually verifies documentation and approves the request.",
        '',
        false
    );

    jsonResponse([
        'success' => true,
        'message' => "Request {$requestCode} submitted for administrative verification. Private information remains locked until explicit admin approval.",
        'request' => $created,
    ], 201);
}

jsonResponse(['success' => false, 'error' => 'Unsupported request.'], 400);
