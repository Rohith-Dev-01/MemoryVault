<?php
/**
 * MEMORY VAULT – Authentication, Role Enforcement & CSRF Middleware
 */

declare(strict_types=1);

require_once __DIR__ . '/cors.php';

/**
 * Verify CSRF token on state-changing requests (POST, PUT, DELETE).
 */
function verifyCsrfToken(): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return;
    }

    $providedToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $sessionToken  = $_SESSION['csrf_token'] ?? '';

    if ($sessionToken === '' || $providedToken === '' || !hash_equals($sessionToken, $providedToken)) {
        jsonResponse([
            'success' => false,
            'error'   => 'Invalid or missing CSRF security token. Please refresh the page and try again.',
        ], 403);
    }
}

/**
 * Enforce an authenticated Vault User session (`role === 'user'`) and return numeric user_id.
 */
function requireUserAuth(): int
{
    $role = $_SESSION['role'] ?? null;

    if ($role === 'admin' && !empty($_SESSION['admin_id'])) {
        jsonResponse([
            'success'  => false,
            'error'    => 'Administrators cannot access Vault User endpoints. Use the Administrator Dashboard.',
            'redirect' => 'admin.html',
        ], 403);
    }

    if ($role !== 'user' || empty($_SESSION['user_id'])) {
        jsonResponse([
            'success'  => false,
            'error'    => 'Authentication required. Please sign in as a Vault User.',
            'redirect' => 'login.html',
        ], 401);
    }

    return (int) $_SESSION['user_id'];
}

/**
 * Enforce an authenticated Administrator session (`role === 'admin'`) and return numeric admin_id.
 */
function requireAdminAuth(): int
{
    $role = $_SESSION['role'] ?? null;

    if ($role === 'user' && !empty($_SESSION['user_id'])) {
        jsonResponse([
            'success'  => false,
            'error'    => 'Access denied. Administrator role is required for this endpoint.',
            'redirect' => 'dashboard.html',
        ], 403);
    }

    if ($role !== 'admin' || empty($_SESSION['admin_id'])) {
        jsonResponse([
            'success'  => false,
            'error'    => 'Administrator authentication required. Please sign in as an Administrator.',
            'redirect' => 'login.html?role=admin',
        ], 401);
    }

    return (int) $_SESSION['admin_id'];
}

/**
 * Sanitize and trim string input safely.
 */
function cleanString($value, int $maxLength = 500): string
{
    $str = trim((string) ($value ?? ''));
    if (mb_strlen($str) > $maxLength) {
        $str = mb_substr($str, 0, $maxLength);
    }
    return $str;
}
