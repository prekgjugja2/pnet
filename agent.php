<?php
declare(strict_types=1);

require __DIR__ . '/lib/app.php';

pnet_security_headers();

try {
    $pdo = pnet_boot();
} catch (Throwable $e) {
    pnet_fail(500, 'PNet could not start.');
}

if (!pnet_on_home_network()) {
    pnet_fail(403, 'Connect to home Wi-Fi to report traffic.');
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok' => true,
        'service' => 'PNet traffic agent',
        'version' => 1,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($method !== 'POST') {
    pnet_fail(405, 'Use POST to report traffic.');
}

$raw = file_get_contents('php://input');
$data = json_decode($raw !== false && $raw !== '' ? $raw : '[]', true);
if (!is_array($data)) {
    pnet_fail(422, 'Request was not valid JSON.');
}

$token = trim((string) ($data['token'] ?? ''));
if ($token === '') {
    $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (preg_match('/^Bearer\s+(\S+)/i', $auth, $m)) {
        $token = trim($m[1]);
    }
}
if ($token === '') {
    pnet_fail(401, 'Agent token required.');
}

try {
    $result = pnet_agent_report($pdo, $token, $data);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (InvalidArgumentException $e) {
    pnet_fail(401, $e->getMessage());
} catch (Throwable $e) {
    pnet_fail(500, 'PNet could not save agent report.');
}
