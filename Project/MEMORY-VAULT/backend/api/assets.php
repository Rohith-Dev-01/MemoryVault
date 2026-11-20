<?php
/**
 * MEMORY VAULT – Digital Assets CRUD API
 *
 * SECURITY RULE: Never collect or store third-party account passwords.
 * Enforces strict user ownership (`WHERE user_id = :uid`) on every query.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';

$userId = requireUserAuth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$pdo    = getDbConnection();

// GET — List all digital assets belonging to the signed-in user
if ($method === 'GET') {
    $stmt = $pdo->prepare(
        'SELECT a.id, a.asset_name, a.platform, a.category, a.account_identifier, a.notes,
                a.created_at, a.updated_at,
                w.id AS wish_id, w.action_type AS wish_action_type
         FROM digital_assets a
         LEFT JOIN final_wishes w ON w.asset_id = a.id AND w.user_id = a.user_id
         WHERE a.user_id = :uid
         ORDER BY a.created_at DESC, a.id DESC'
    );
    $stmt->execute([':uid' => $userId]);

    jsonResponse([
        'success' => true,
        'assets'  => $stmt->fetchAll(),
    ]);
}

verifyCsrfToken();
$input = getJsonInput();

// Reject accidental password keys
if (isset($input['password']) || isset($input['account_password'])) {
    jsonResponse([
        'success' => false,
        'error'   => 'Security Policy: Memory Vault never collects or stores third-party account passwords.',
    ], 422);
}

// POST — Create a new digital asset
if ($method === 'POST') {
    $assetName  = cleanString($input['asset_name'] ?? '', 140);
    $platform   = cleanString($input['platform'] ?? '', 100);
    $category   = cleanString($input['category'] ?? '', 80);
    $identifier = cleanString($input['account_identifier'] ?? '', 180);
    $notes      = cleanString($input['notes'] ?? '', 1500);

    if ($assetName === '' || $platform === '' || $category === '' || $identifier === '') {
        jsonResponse(['success' => false, 'error' => 'Asset name, platform, category, and account identifier are required.'], 422);
    }

    $stmt = $pdo->prepare(
        'INSERT INTO digital_assets (user_id, asset_name, platform, category, account_identifier, notes)
         VALUES (:uid, :name, :platform, :category, :identifier, :notes)
         RETURNING id, asset_name, platform, category, account_identifier, notes, created_at, updated_at'
    );
    $stmt->execute([
        ':uid'        => $userId,
        ':name'       => $assetName,
        ':platform'   => $platform,
        ':category'   => $category,
        ':identifier' => $identifier,
        ':notes'      => $notes,
    ]);

    jsonResponse([
        'success' => true,
        'message' => 'Digital asset saved to your vault.',
        'asset'   => $stmt->fetch(),
    ], 201);
}

// PUT — Edit an existing digital asset (ownership enforced)
if ($method === 'PUT') {
    $id         = (int) ($input['id'] ?? 0);
    $assetName  = cleanString($input['asset_name'] ?? '', 140);
    $platform   = cleanString($input['platform'] ?? '', 100);
    $category   = cleanString($input['category'] ?? '', 80);
    $identifier = cleanString($input['account_identifier'] ?? '', 180);
    $notes      = cleanString($input['notes'] ?? '', 1500);

    if ($id <= 0 || $assetName === '' || $platform === '' || $category === '' || $identifier === '') {
        jsonResponse(['success' => false, 'error' => 'Valid asset ID and all required fields must be provided.'], 422);
    }

    $stmt = $pdo->prepare(
        'UPDATE digital_assets
         SET asset_name = :name,
             platform = :platform,
             category = :category,
             account_identifier = :identifier,
             notes = :notes,
             updated_at = NOW()
         WHERE id = :id AND user_id = :uid
         RETURNING id, asset_name, platform, category, account_identifier, notes, created_at, updated_at'
    );
    $stmt->execute([
        ':name'       => $assetName,
        ':platform'   => $platform,
        ':category'   => $category,
        ':identifier' => $identifier,
        ':notes'      => $notes,
        ':id'         => $id,
        ':uid'        => $userId,
    ]);

    $updated = $stmt->fetch();
    if (!$updated) {
        jsonResponse(['success' => false, 'error' => 'Digital asset not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Digital asset updated.',
        'asset'   => $updated,
    ]);
}

// DELETE — Remove an asset (cascades its final wish)
if ($method === 'DELETE') {
    $id = (int) ($_GET['id'] ?? ($input['id'] ?? 0));
    if ($id <= 0) {
        jsonResponse(['success' => false, 'error' => 'Valid asset ID is required.'], 422);
    }

    $stmt = $pdo->prepare('DELETE FROM digital_assets WHERE id = :id AND user_id = :uid');
    $stmt->execute([':id' => $id, ':uid' => $userId]);

    if ($stmt->rowCount() === 0) {
        jsonResponse(['success' => false, 'error' => 'Digital asset not found.'], 404);
    }

    jsonResponse([
        'success' => true,
        'message' => 'Digital asset removed from your vault.',
    ]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
