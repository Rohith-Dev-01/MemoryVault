<?php
/**
 * MEMORY VAULT – Trusted Contacts & Invitation Management API
 *
 * SECURITY RULE: Contact acceptance does NOT automatically grant access to private vault data.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';
require_once __DIR__ . '/../includes/mailer.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? '';
$pdo    = getDbConnection();

// Public Invitation Lookup (when a trusted contact opens their invitation link)
if ($method === 'GET' && $action === 'invitation') {
    $token = cleanString($_GET['token'] ?? '', 80);
    if ($token === '') {
        jsonResponse(['success' => false, 'error' => 'Invitation token is required.'], 422);
    }

    $stmt = $pdo->prepare(
        'SELECT tc.id, tc.name, tc.email, tc.relationship, tc.invitation_status, tc.responded_at,
                u.full_name AS owner_name, u.user_handle AS owner_handle
         FROM trusted_contacts tc
         JOIN users u ON u.id = tc.user_id
         WHERE tc.invitation_token = :token
         LIMIT 1'
    );
    $stmt->execute([':token' => $token]);
    $inv = $stmt->fetch();

    if (!$inv) {
        jsonResponse(['success' => false, 'error' => 'Invitation link is invalid or expired.'], 404);
    }

    jsonResponse(['success' => true, 'invitation' => $inv]);
}

// Public Invitation Response (Accept / Decline via invitation token)
if ($method === 'POST' && $action === 'respond_invitation') {
    verifyCsrfToken();
    $input    = getJsonInput();
    $token    = cleanString($input['token'] ?? '', 80);
    $decision = cleanString($input['decision'] ?? '', 20);

    if ($token === '' || !in_array($decision, ['accepted', 'declined'], true)) {
        jsonResponse(['success' => false, 'error' => 'Valid token and decision (accepted/declined) are required.'], 422);
    }

    $stmt = $pdo->prepare(
        'UPDATE trusted_contacts
         SET invitation_status = :status,
             responded_at = NOW(),
             updated_at = NOW()
         WHERE invitation_token = :token
         RETURNING id, user_id, name, email, invitation_status, responded_at'
    );
    $stmt->execute([':status' => $decision, ':token' => $token]);
    $updated = $stmt->fetch();

    if (!$updated) {
        jsonResponse(['success' => false, 'error' => 'Invitation not found.'], 404);
    }

    // Notify vault owner
    $ownerStmt = $pdo->prepare('SELECT email, full_name FROM users WHERE id = :uid');
    $ownerStmt->execute([':uid' => (int) $updated['user_id']]);
    $owner = $ownerStmt->fetch();
    if ($owner) {
        sendAndLogNotification(
            $pdo,
            (int) $updated['user_id'],
            $owner['email'],
            'user',
            'invitation_' . $decision,
            "Trusted Contact {$updated['name']} {$decision} your invitation",
            "Hello {$owner['full_name']},\n\n{$updated['name']} ({$updated['email']}) has {$decision} your Trusted Contact invitation. Remember: accepting does not grant automatic access to any private vault data.",
            '',
            false
        );
    }

    jsonResponse([
        'success'    => true,
        'message'    => "Invitation marked as {$decision}. Note: this does not grant access to private vault records.",
        'invitation' => $updated,
    ]);
}

// All remaining endpoints require an authenticated vault owner
$userId = requireUserAuth();

// GET — List all trusted contacts owned by current user
if ($method === 'GET') {
    $stmt = $pdo->prepare(
        'SELECT id, name, email, phone, relationship, invitation_token, invitation_status,
                responded_at, created_at, updated_at
         FROM trusted_contacts
         WHERE user_id = :uid
         ORDER BY created_at DESC, id DESC'
    );
    $stmt->execute([':uid' => $userId]);

    jsonResponse([
        'success'  => true,
        'contacts' => $stmt->fetchAll(),
    ]);
}

verifyCsrfToken();
$input = getJsonInput();

// POST — Add a new trusted contact & generate unique invitation token
if ($method === 'POST') {
    $name         = cleanString($input['name'] ?? '', 120);
    $email        = strtolower(cleanString($input['email'] ?? '', 180));
    $phone        = cleanString($input['phone'] ?? '', 40);
    $relationship = cleanString($input['relationship'] ?? '', 80);

    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $relationship === '') {
        jsonResponse(['success' => false, 'error' => 'Name, valid email address, and relationship are required.'], 422);
    }

    // Check duplicate contact email for this user
    $dup = $pdo->prepare('SELECT id FROM trusted_contacts WHERE user_id = :uid AND LOWER(email) = LOWER(:email) LIMIT 1');
    $dup->execute([':uid' => $userId, ':email' => $email]);
    if ($dup->fetch()) {
        jsonResponse(['success' => false, 'error' => 'This email is already registered among your trusted contacts.'], 409);
    }

    $token = 'mv_inv_' . bin2hex(random_bytes(12));

    $stmt = $pdo->prepare(
        'INSERT INTO trusted_contacts (user_id, name, email, phone, relationship, invitation_token, invitation_status)
         VALUES (:uid, :name, :email, :phone, :rel, :token, \'pending\')
         RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at, created_at'
    );
    $stmt->execute([
        ':uid'   => $userId,
        ':name'  => $name,
        ':email' => $email,
        ':phone' => $phone,
        ':rel'   => $relationship,
        ':token' => $token,
    ]);
    $contact = $stmt->fetch();

    // Log invitation email
    $ownerStmt = $pdo->prepare('SELECT full_name FROM users WHERE id = :uid');
    $ownerStmt->execute([':uid' => $userId]);
    $ownerName = (string) ($ownerStmt->fetchColumn() ?: 'A Memory Vault user');

    sendAndLogNotification(
        $pdo,
        $userId,
        $email,
        'trusted_contact',
        'contact_invitation',
        "{$ownerName} invited you as a Trusted Contact on Memory Vault",
        "Hello {$name},\n\n{$ownerName} has designated you as a Trusted Contact ({$relationship}) on Memory Vault.\nInvitation Token: {$token}\n\nImportant Security Policy: Accepting this invitation confirms your willingness to check on {$ownerName} if extended inactivity occurs, and does NOT grant automatic access to private vault data.",
        '',
        false
    );

    jsonResponse([
        'success' => true,
        'message' => 'Trusted contact added and invitation generated.',
        'contact' => $contact,
    ], 201);
}

// PUT — Edit contact details OR simulate invitation status change
if ($method === 'PUT') {
    $id = (int) ($input['id'] ?? 0);
    if ($id <= 0) {
        jsonResponse(['success' => false, 'error' => 'Valid contact ID is required.'], 422);
    }

    // Status simulation toggle for demo convenience
    if (($input['action'] ?? '') === 'simulate_status') {
        $status = cleanString($input['invitation_status'] ?? '', 20);
        if (!in_array($status, ['pending', 'accepted', 'declined'], true)) {
            jsonResponse(['success' => false, 'error' => 'Status must be pending, accepted, or declined.'], 422);
        }

        $stmt = $pdo->prepare(
            "UPDATE trusted_contacts
             SET invitation_status = :status,
                 responded_at = CASE WHEN :status_chk = 'pending' THEN NULL ELSE NOW() END,
                 updated_at = NOW()
             WHERE id = :id AND user_id = :uid
             RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at"
        );
        $stmt->execute([
            ':status'     => $status,
            ':status_chk' => $status,
            ':id'         => $id,
            ':uid'        => $userId,
        ]);
        $updated = $stmt->fetch();
        if (!$updated) {
            jsonResponse(['success' => false, 'error' => 'Trusted contact not found.'], 404);
        }

        jsonResponse([
            'success' => true,
            'message' => "Invitation status updated to {$status}. Private vault data remains protected.",
            'contact' => $updated,
        ]);
    }

    // Regular contact detail update
    $name         = cleanString($input['name'] ?? '', 120);
    $email        = strtolower(cleanString($input['email'] ?? '', 180));
    $phone        = cleanString($input['phone'] ?? '', 40);
    $relationship = cleanString($input['relationship'] ?? '', 80);

    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $relationship === '') {
        jsonResponse(['success' => false, 'error' => 'Name, valid email address, and relationship are required.'], 422);
    }

    $stmt = $pdo->prepare(
        'UPDATE trusted_contacts
         SET name = :name,
             email = :email,
             phone = :phone,
             relationship = :rel,
             updated_at = NOW()
         WHERE id = :id AND user_id = :uid
         RETURNING id, name, email, phone, relationship, invitation_token, invitation_status, responded_at'
    );
    $stmt->execute([
        ':name'  => $name,
        ':email' => $email,
        ':phone' => $phone,
        ':rel'   => $relationship,
        ':id'    => $id,
        ':uid'   => $userId,
    ]);
    $updated = $stmt->fetch();
    if (!$updated) {
        jsonResponse(['success' => false, 'error' => 'Trusted contact not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Trusted contact updated.',
        'contact' => $updated,
    ]);
}

// DELETE — Remove trusted contact
if ($method === 'DELETE') {
    $id = (int) ($_GET['id'] ?? ($input['id'] ?? 0));
    if ($id <= 0) {
        jsonResponse(['success' => false, 'error' => 'Valid contact ID is required.'], 422);
    }

    $stmt = $pdo->prepare('DELETE FROM trusted_contacts WHERE id = :id AND user_id = :uid');
    $stmt->execute([':id' => $id, ':uid' => $userId]);

    if ($stmt->rowCount() === 0) {
        jsonResponse(['success' => false, 'error' => 'Trusted contact not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Trusted contact removed.',
    ]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
