<?php
/**
 * MEMORY VAULT – CORS, Secure Session Cookie & JSON Bootstrap
 *
 * Supports both local same-origin XAMPP (http://localhost/MEMORY-VAULT)
 * and an external Vercel frontend with credentialed cross-origin fetch requests.
 */

declare(strict_types=1);

// Allowlist of trusted frontend origins (never use wildcard '*' with credentials)
$allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
];

// Optional comma-separated extra origins via environment variable (e.g. your Vercel URL)
$extraOriginsEnv = getenv('ALLOWED_ORIGINS') ?: '';
if ($extraOriginsEnv !== '') {
    foreach (explode(',', $extraOriginsEnv) as $extraOrigin) {
        $trimmed = trim($extraOrigin);
        if ($trimmed !== '') {
            $allowedOrigins[] = $trimmed;
        }
    }
}

$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
    (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') ||
    (($_SERVER['SERVER_PORT'] ?? '') === '443')
);

// Allow listed origins or Vercel preview/production subdomains when explicitly configured
$originAllowed = false;
if ($requestOrigin !== '') {
    if (in_array($requestOrigin, $allowedOrigins, true)) {
        $originAllowed = true;
    } elseif (preg_match('/^https:\/\/[a-zA-Z0-9-]+\.vercel\.app$/', $requestOrigin)) {
        $originAllowed = true;
    }
}

if ($originAllowed) {
    header('Access-Control-Allow-Origin: ' . $requestOrigin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}

header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, X-Requested-With, Accept');
header('Content-Type: application/json; charset=utf-8');

// Handle CORS preflight immediately
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Configure secure PHP session cookies
if (session_status() === PHP_SESSION_NONE) {
    // Use SameSite=None + Secure for cross-origin HTTPS (Vercel -> Tunnel),
    // and SameSite=Lax for plain HTTP localhost XAMPP so browsers accept the cookie cleanly.
    $sameSite = $isHttps ? 'None' : 'Lax';

    session_set_cookie_params([
        'lifetime' => 60 * 60 * 6, // 6 hours
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => $sameSite,
    ]);

    session_name('MV_SESSION');
    session_start();
}

// Initialize per-session CSRF token if absent
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Send a consistent JSON response and terminate execution.
 */
function jsonResponse(array $payload, int $statusCode = 200): void
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Parse JSON request body safely.
 */
function getJsonInput(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}
