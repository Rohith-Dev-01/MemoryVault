<?php
/**
 * MEMORY VAULT – Memories & Farewell Letters CRUD API
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';

$userId = requireUserAuth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$pdo    = getDbConnection();

// GET — List all personal memories & farewell letters + trusted contacts for selector
if ($method === 'GET') {
    $stmt = $pdo->prepare(
        'SELECT m.id, m.title, m.message_body, m.trusted_contact_id, m.custom_recipient,
                m.release_condition, m.created_at, m.updated_at,
                tc.name AS contact_name, tc.email AS contact_email, tc.relationship AS contact_relationship
         FROM memories m
         LEFT JOIN trusted_contacts tc ON tc.id = m.trusted_contact_id AND tc.user_id = m.user_id
         WHERE m.user_id = :uid
         ORDER BY m.created_at DESC, m.id DESC'
    );
    $stmt->execute([':uid' => $userId]);

    $contactsStmt = $pdo->prepare(
        'SELECT id, name, email, relationship, invitation_status
         FROM trusted_contacts
         WHERE user_id = :uid
         ORDER BY name ASC'
    );
    $contactsStmt->execute([':uid' => $userId]);

    jsonResponse([
        'success'  => true,
        'memories' => $stmt->fetchAll(),
        'contacts' => $contactsStmt->fetchAll(),
    ]);
}

verifyCsrfToken();
$input = getJsonInput();

// POST — Create a new farewell letter / memory
if ($method === 'POST') {
    $title            = cleanString($input['title'] ?? '', 180);
    $body             = cleanString($input['message_body'] ?? '', 10000);
    $contactId        = !empty($input['trusted_contact_id']) ? (int) $input['trusted_contact_id'] : null;
    $customRecipient  = cleanString($input['custom_recipient'] ?? '', 140);
    $releaseCondition = cleanString($input['release_condition'] ?? 'Upon verified admin approval', 120);

    if ($title === '' || $body === '') {
        jsonResponse(['success' => false, 'error' => 'Both a letter title and message body are required.'], 422);
    }
    if ($contactId === null && $customRecipient === '') {
        jsonResponse(['success' => false, 'error' => 'Please choose a trusted contact or enter a custom recipient.'], 422);
    }

    if ($contactId !== null) {
        $check = $pdo->prepare('SELECT id FROM trusted_contacts WHERE id = :cid AND user_id = :uid LIMIT 1');
        $check->execute([':cid' => $contactId, ':uid' => $userId]);
        if (!$check->fetch()) {
            jsonResponse(['success' => false, 'error' => 'Selected trusted contact was not found.'], 422);
        }
    }

    $stmt = $pdo->prepare(
        'INSERT INTO memories (user_id, trusted_contact_id, custom_recipient, title, message_body, release_condition)
         VALUES (:uid, :cid, :custom, :title, :body, :cond)
         RETURNING id, trusted_contact_id, custom_recipient, title, message_body, release_condition, created_at, updated_at'
    );
    $stmt->execute([
        ':uid'    => $userId,
        ':cid'    => $contactId,
        ':custom' => $customRecipient,
        ':title'  => $title,
        ':body'   => $body,
        ':cond'   => $releaseCondition,
    ]);

    jsonResponse([
        'success' => true,
        'message' => 'Your letter has been preserved in the vault.',
        'memory'  => $stmt->fetch(),
    ], 201);
}

// PUT — Edit an existing memory
if ($method === 'PUT') {
    $id               = (int) ($input['id'] ?? 0);
    $title            = cleanString($input['title'] ?? '', 180);
    $body             = cleanString($input['message_body'] ?? '', 10000);
    $contactId        = !empty($input['trusted_contact_id']) ? (int) $input['trusted_contact_id'] : null;
    $customRecipient  = cleanString($input['custom_recipient'] ?? '', 140);
    $releaseCondition = cleanString($input['release_condition'] ?? 'Upon verified admin approval', 120);

    if ($id <= 0 || $title === '' || $body === '') {
        jsonResponse(['success' => false, 'error' => 'Valid memory ID, title, and message body are required.'], 422);
    }
    if ($contactId === null && $customRecipient === '') {
        jsonResponse(['success' => false, 'error' => 'Please select a trusted contact or specify a recipient.'], 422);
    }

    if ($contactId !== null) {
        $check = $pdo->prepare('SELECT id FROM trusted_contacts WHERE id = :cid AND user_id = :uid LIMIT 1');
        $check->execute([':cid' => $contactId, ':uid' => $userId]);
        if (!$check->fetch()) {
            jsonResponse(['success' => false, 'error' => 'Selected trusted contact was not found.'], 422);
        }
    }

    $stmt = $pdo->prepare(
        'UPDATE memories
         SET trusted_contact_id = :cid,
             custom_recipient = :custom,
             title = :title,
             message_body = :body,
             release_condition = :cond,
             updated_at = NOW()
         WHERE id = :id AND user_id = :uid
         RETURNING id, trusted_contact_id, custom_recipient, title, message_body, release_condition, created_at, updated_at'
    );
    $stmt->execute([
        ':cid'    => $contactId,
        ':custom' => $customRecipient,
        ':title'  => $title,
        ':body'   => $body,
        ':cond'   => $releaseCondition,
        ':id'     => $id,
        ':uid'    => $userId,
    ]);

    $updated = $stmt->fetch();
    if (!$updated) {
        jsonResponse(['success' => false, 'error' => 'Memory not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Letter updated.',
        'memory'  => $updated,
    ]);
}

// DELETE — Remove a memory
if ($method === 'DELETE') {
    $id = (int) ($_GET['id'] ?? ($input['id'] ?? 0));
    if ($id <= 0) {
        jsonResponse(['success' => false, 'error' => 'Valid memory ID is required.'], 422);
    }

    $stmt = $pdo->prepare('DELETE FROM memories WHERE id = :id AND user_id = :uid');
    $stmt->execute([':id' => $id, ':uid' => $userId]);

    if ($stmt->rowCount() === 0) {
        jsonResponse(['success' => false, 'error' => 'Memory not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Letter deleted from vault.',
    ]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
