<?php
/**
 * MEMORY VAULT – Final Wishes API
 *
 * Assigns explicit post-legacy instructions to each saved digital asset.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';

$userId = requireUserAuth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$pdo    = getDbConnection();

const ALLOWED_WISH_ACTIONS = [
    'preserve_account',
    'preserve_memories',
    'share_information',
    'request_memorialization',
    'request_deletion',
];

// GET — Fetch all user assets paired with their assigned final wish & trusted contacts list
if ($method === 'GET') {
    $stmt = $pdo->prepare(
        'SELECT a.id AS asset_id, a.asset_name, a.platform, a.category, a.account_identifier,
                w.id AS wish_id, w.action_type, w.custom_instructions, w.assigned_contact_id,
                w.updated_at AS wish_updated_at,
                tc.name AS assigned_contact_name
         FROM digital_assets a
         LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
         LEFT JOIN trusted_contacts tc ON tc.id = w.assigned_contact_id AND tc.user_id = a.user_id
         WHERE a.user_id = :uid
         ORDER BY a.created_at DESC, a.id DESC'
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
        'items'    => $stmt->fetchAll(),
        'contacts' => $contactsStmt->fetchAll(),
    ]);
}

verifyCsrfToken();
$input = getJsonInput();

// POST / PUT — Save or update a final wish for a specific digital asset
if ($method === 'POST' || $method === 'PUT') {
    $assetId           = (int) ($input['asset_id'] ?? 0);
    $actionType        = cleanString($input['action_type'] ?? '', 60);
    $customInstr       = cleanString($input['custom_instructions'] ?? '', 2500);
    $assignedContactId = !empty($input['assigned_contact_id']) ? (int) $input['assigned_contact_id'] : null;

    if ($assetId <= 0) {
        jsonResponse(['success' => false, 'error' => 'Please select a valid digital asset.'], 422);
    }
    if (!in_array($actionType, ALLOWED_WISH_ACTIONS, true)) {
        jsonResponse(['success' => false, 'error' => 'Please choose a valid final wish instruction.'], 422);
    }

    // Verify asset ownership
    $assetCheck = $pdo->prepare('SELECT id FROM digital_assets WHERE id = :aid AND user_id = :uid LIMIT 1');
    $assetCheck->execute([':aid' => $assetId, ':uid' => $userId]);
    if (!$assetCheck->fetch()) {
        jsonResponse(['success' => false, 'error' => 'Digital asset not found in your vault.'], 404);
    }

    // Verify optional assigned contact belongs to the user
    if ($assignedContactId !== null) {
        $cCheck = $pdo->prepare('SELECT id FROM trusted_contacts WHERE id = :cid AND user_id = :uid LIMIT 1');
        $cCheck->execute([':cid' => $assignedContactId, ':uid' => $userId]);
        if (!$cCheck->fetch()) {
            jsonResponse(['success' => false, 'error' => 'Selected trusted contact was not found.'], 422);
        }
    }

    $stmt = $pdo->prepare(
        'INSERT INTO final_wishes (user_id, asset_id, assigned_contact_id, action_type, custom_instructions)
         VALUES (:uid, :aid, :cid, :action, :instr)
         ON CONFLICT (asset_id) DO UPDATE
         SET assigned_contact_id = EXCLUDED.assigned_contact_id,
             action_type = EXCLUDED.action_type,
             custom_instructions = EXCLUDED.custom_instructions,
             updated_at = NOW()
         WHERE final_wishes.user_id = :uid_check
         RETURNING id, asset_id, assigned_contact_id, action_type, custom_instructions, updated_at'
    );
    $stmt->execute([
        ':uid'       => $userId,
        ':aid'       => $assetId,
        ':cid'       => $assignedContactId,
        ':action'    => $actionType,
        ':instr'     => $customInstr,
        ':uid_check' => $userId,
    ]);

    jsonResponse([
        'success' => true,
        'message' => 'Final wish instructions saved.',
        'wish'    => $stmt->fetch(),
    ]);
}

// DELETE — Clear final wish for an asset
if ($method === 'DELETE') {
    $wishId = (int) ($_GET['id'] ?? ($input['id'] ?? 0));
    if ($wishId <= 0) {
        jsonResponse(['success' => false, 'error' => 'Valid wish ID is required.'], 422);
    }

    $stmt = $pdo->prepare('DELETE FROM final_wishes WHERE id = :id AND user_id = :uid');
    $stmt->execute([':id' => $wishId, ':uid' => $userId]);

    if ($stmt->rowCount() === 0) {
        jsonResponse(['success' => false, 'error' => 'Final wish not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Final wish removed.',
    ]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
