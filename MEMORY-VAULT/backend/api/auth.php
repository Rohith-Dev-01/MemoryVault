<?php
/**
 * MEMORY VAULT – Unified Role-Aware Authentication API
 *
 * Endpoints:
 *   GET  ?action=me            -> Return current session role ('user' | 'admin' | null), profile & CSRF token
 *   POST ?action=register      -> Register a new Vault User account
 *   POST ?action=login         -> Role-aware login (role: 'user' | 'admin') with strict table & cross-role checks
 *   POST ?action=logout        -> End active user/admin session
 *   POST ?action=admin_login   -> Alias for role='admin' login
 *   POST ?action=admin_logout  -> Alias for logout
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth_middleware.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? '';
$pdo    = getDbConnection();

// GET ?action=me — Session status, explicit role & CSRF bootstrap
if ($method === 'GET' && ($action === 'me' || $action === '')) {
    $role  = $_SESSION['role'] ?? null;
    $user  = null;
    $admin = null;

    if ($role === 'user' && !empty($_SESSION['user_id'])) {
        $stmt = $pdo->prepare(
            'SELECT id, user_handle, full_name, email, last_check_in, escalation_stage, created_at
             FROM users WHERE id = :id LIMIT 1'
        );
        $stmt->execute([':id' => (int) $_SESSION['user_id']]);
        $user = $stmt->fetch() ?: null;
        if (!$user) {
            unset($_SESSION['user_id'], $_SESSION['role']);
            $role = null;
        }
    } elseif ($role === 'admin' && !empty($_SESSION['admin_id'])) {
        $stmt = $pdo->prepare(
            'SELECT id, full_name, email, role, created_at
             FROM admin_users WHERE id = :id LIMIT 1'
        );
        $stmt->execute([':id' => (int) $_SESSION['admin_id']]);
        $admin = $stmt->fetch() ?: null;
        if (!$admin) {
            unset($_SESSION['admin_id'], $_SESSION['role']);
            $role = null;
        }
    } else {
        $role = null;
    }

    jsonResponse([
        'success'             => true,
        'role'                => $role,
        'authenticated'       => $role === 'user' && $user !== null,
        'admin_authenticated' => $role === 'admin' && $admin !== null,
        'user'                => $user,
        'admin'               => $admin,
        'csrf_token'          => $_SESSION['csrf_token'],
    ]);
}

if ($method !== 'POST') {
    jsonResponse(['success' => false, 'error' => 'Method not allowed.'], 405);
}

$input = getJsonInput();

// POST ?action=register (Vault Users only — Administrators are provisioned in admin_users)
if ($action === 'register') {
    verifyCsrfToken();

    $requestedRole = strtolower(cleanString($input['role'] ?? 'user', 20));
    if ($requestedRole !== 'user') {
        jsonResponse([
            'success' => false,
            'error'   => 'Public registration is restricted to Vault User accounts. Administrators must sign in with provisioned credentials.',
        ], 403);
    }

    $userHandle = cleanString($input['user_handle'] ?? '', 60);
    $fullName   = cleanString($input['full_name'] ?? '', 120);
    $email      = strtolower(cleanString($input['email'] ?? '', 180));
    $password   = (string) ($input['password'] ?? '');

    if ($userHandle === '' || !preg_match('/^[a-zA-Z0-9._-]{3,40}$/', $userHandle)) {
        jsonResponse(['success' => false, 'error' => 'User ID must be 3–40 characters (letters, numbers, dots, underscores, or hyphens).'], 422);
    }
    if (mb_strlen($fullName) < 2) {
        jsonResponse(['success' => false, 'error' => 'Please enter your full name.'], 422);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(['success' => false, 'error' => 'Please enter a valid email address.'], 422);
    }
    if (strlen($password) < 8) {
        jsonResponse(['success' => false, 'error' => 'Password must be at least 8 characters long.'], 422);
    }

    // Prevent email collision with existing users or admin accounts
    $dupUser = $pdo->prepare(
        'SELECT id FROM users WHERE LOWER(email) = LOWER(:email) OR LOWER(user_handle) = LOWER(:handle) LIMIT 1'
    );
    $dupUser->execute([':email' => $email, ':handle' => $userHandle]);
    if ($dupUser->fetch()) {
        jsonResponse(['success' => false, 'error' => 'An account with that email or User ID already exists.'], 409);
    }

    $dupAdmin = $pdo->prepare('SELECT id FROM admin_users WHERE LOWER(email) = LOWER(:email) LIMIT 1');
    $dupAdmin->execute([':email' => $email]);
    if ($dupAdmin->fetch()) {
        jsonResponse(['success' => false, 'error' => 'That email is reserved for an Administrator account.'], 409);
    }

    $hash    = password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
    $cycleId = 'cycle_' . bin2hex(random_bytes(8));

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO users (user_handle, full_name, email, password_hash, last_check_in, escalation_stage, inactivity_cycle_id)
             VALUES (:handle, :full_name, :email, :hash, NOW(), 0, :cycle)
             RETURNING id, user_handle, full_name, email, last_check_in, escalation_stage, created_at'
        );
        $stmt->execute([
            ':handle'    => $userHandle,
            ':full_name' => $fullName,
            ':email'     => $email,
            ':hash'      => $hash,
            ':cycle'     => $cycleId,
        ]);
        $newUser = $stmt->fetch();

        $planStmt = $pdo->prepare(
            'INSERT INTO legacy_plans (user_id, first_reminder_days, second_reminder_days, final_reminder_days, trusted_alert_days)
             VALUES (:uid, 30, 35, 40, 45)'
        );
        $planStmt->execute([':uid' => (int) $newUser['id']]);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        jsonResponse(['success' => false, 'error' => 'Registration failed. Please try again.'], 500);
    }

    session_regenerate_id(true);
    unset($_SESSION['admin_id']);
    $_SESSION['role']       = 'user';
    $_SESSION['user_id']    = (int) $newUser['id'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    jsonResponse([
        'success'    => true,
        'role'       => 'user',
        'redirect'   => 'dashboard.html',
        'message'    => 'Your Memory Vault account has been created.',
        'user'       => $newUser,
        'csrf_token' => $_SESSION['csrf_token'],
    ], 201);
}

// POST ?action=login (Unified Role-Aware Login) or ?action=admin_login
if ($action === 'login' || $action === 'admin_login') {
    verifyCsrfToken();

    $role = $action === 'admin_login'
        ? 'admin'
        : strtolower(cleanString($input['role'] ?? 'user', 20));

    if (!in_array($role, ['user', 'admin'], true)) {
        jsonResponse(['success' => false, 'error' => 'Please select a valid account role (Vault User or Administrator).'], 422);
    }

    $identifier = cleanString($input['identifier'] ?? ($input['email'] ?? ''), 180);
    $password   = (string) ($input['password'] ?? '');

    if ($identifier === '' || $password === '') {
        jsonResponse(['success' => false, 'error' => 'Please enter both your account identifier and password.'], 422);
    }

    // Role === 'admin': Strictly authenticate against admin_users
    if ($role === 'admin') {
        $stmt = $pdo->prepare(
            'SELECT id, full_name, email, password_hash, role, created_at
             FROM admin_users
             WHERE LOWER(email) = LOWER(:email)
             LIMIT 1'
        );
        $stmt->execute([':email' => $identifier]);
        $admin = $stmt->fetch();

        if (!$admin) {
            // Check if a Vault User accidentally tried signing in as Administrator
            $crossStmt = $pdo->prepare(
                'SELECT id FROM users WHERE LOWER(email) = LOWER(:id1) OR LOWER(user_handle) = LOWER(:id2) LIMIT 1'
            );
            $crossStmt->execute([':id1' => $identifier, ':id2' => $identifier]);
            if ($crossStmt->fetch()) {
                jsonResponse([
                    'success' => false,
                    'error'   => 'This account is a Vault User, not an Administrator. Please switch the role selector to "Vault User" to sign in.',
                ], 403);
            }
            jsonResponse(['success' => false, 'error' => 'Invalid administrator email or password.'], 401);
        }

        if (!password_verify($password, $admin['password_hash'])) {
            jsonResponse(['success' => false, 'error' => 'Invalid administrator email or password.'], 401);
        }

        session_regenerate_id(true);
        unset($_SESSION['user_id']);
        $_SESSION['role']       = 'admin';
        $_SESSION['admin_id']   = (int) $admin['id'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        unset($admin['password_hash']);

        jsonResponse([
            'success'    => true,
            'role'       => 'admin',
            'redirect'   => 'admin.html',
            'message'    => 'Signed in as Administrator. Opening Verification Console…',
            'admin'      => $admin,
            'csrf_token' => $_SESSION['csrf_token'],
        ]);
    }

    // Role === 'user': Strictly authenticate against users
    $stmt = $pdo->prepare(
        'SELECT id, user_handle, full_name, email, password_hash, last_check_in, escalation_stage, created_at
         FROM users
         WHERE LOWER(email) = LOWER(:id1) OR LOWER(user_handle) = LOWER(:id2)
         LIMIT 1'
    );
    $stmt->execute([':id1' => $identifier, ':id2' => $identifier]);
    $user = $stmt->fetch();

    if (!$user) {
        // Check if an Administrator accidentally tried signing in as Vault User
        $crossStmt = $pdo->prepare('SELECT id FROM admin_users WHERE LOWER(email) = LOWER(:email) LIMIT 1');
        $crossStmt->execute([':email' => $identifier]);
        if ($crossStmt->fetch()) {
            jsonResponse([
                'success' => false,
                'error'   => 'This account is an Administrator, not a Vault User. Please switch the role selector to "Administrator" to sign in.',
            ], 403);
        }
        jsonResponse(['success' => false, 'error' => 'Invalid email/User ID or password.'], 401);
    }

    if (!password_verify($password, $user['password_hash'])) {
        jsonResponse(['success' => false, 'error' => 'Invalid email/User ID or password.'], 401);
    }

    // Successful Vault User login resets inactivity timer & clears escalation stage
    $newCycle = 'cycle_' . bin2hex(random_bytes(8));
    $upd = $pdo->prepare(
        'UPDATE users
         SET last_check_in = NOW(),
             escalation_stage = 0,
             inactivity_cycle_id = :cycle,
             updated_at = NOW()
         WHERE id = :uid
         RETURNING id, user_handle, full_name, email, last_check_in, escalation_stage, created_at'
    );
    $upd->execute([':cycle' => $newCycle, ':uid' => (int) $user['id']]);
    $freshUser = $upd->fetch();

    session_regenerate_id(true);
    unset($_SESSION['admin_id']);
    $_SESSION['role']       = 'user';
    $_SESSION['user_id']    = (int) $freshUser['id'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    jsonResponse([
        'success'    => true,
        'role'       => 'user',
        'redirect'   => 'dashboard.html',
        'message'    => 'Welcome back. Your activity check-in timer has been refreshed.',
        'user'       => $freshUser,
        'csrf_token' => $_SESSION['csrf_token'],
    ]);
}

// POST ?action=logout or ?action=admin_logout
if ($action === 'logout' || $action === 'admin_logout') {
    verifyCsrfToken();
    unset($_SESSION['user_id'], $_SESSION['admin_id'], $_SESSION['role']);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    jsonResponse([
        'success'    => true,
        'message'    => 'You have been signed out safely.',
        'csrf_token' => $_SESSION['csrf_token'],
    ]);
}

jsonResponse(['success' => false, 'error' => 'Unknown authentication action.'], 400);
