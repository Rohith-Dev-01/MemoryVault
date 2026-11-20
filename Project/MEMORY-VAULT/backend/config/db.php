<?php
/**
 * MEMORY VAULT – Database Connection (Supabase PostgreSQL via PDO)
 *
 * Uses Supabase Session Pooler (port 5432, SSL required).
 * Keep credentials isolated in this server-side file or environment variables;
 * NEVER expose database credentials to frontend JavaScript.
 */

declare(strict_types=1);

function getDbConnection(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    // Prefer environment variables when available; fallback to local XAMPP configuration values.
    // Replace the placeholder strings below with your Supabase Session Pooler details:
    // Supabase Dashboard -> Project Settings -> Database -> Connection String -> Session Pooler
    $host     = getenv('SUPABASE_DB_HOST') ?: 'aws-0-ap-south-1.pooler.supabase.com';
    $port     = getenv('SUPABASE_DB_PORT') ?: '5432';
    $dbname   = getenv('SUPABASE_DB_NAME') ?: 'postgres';
    $user     = getenv('SUPABASE_DB_USER') ?: 'postgres.YOUR_PROJECT_REF';
    $password = getenv('SUPABASE_DB_PASS') ?: 'YOUR_SUPABASE_DB_PASSWORD';

    $dsn = sprintf(
        'pgsql:host=%s;port=%s;dbname=%s;sslmode=require',
        $host,
        $port,
        $dbname
    );

    try {
        $pdo = new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'success' => false,
            'error'   => 'Database connection failed. Verify pdo_pgsql is enabled in php.ini and check backend/config/db.php credentials.',
        ]);
        exit;
    }
}
