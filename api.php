<?php
declare(strict_types=1);

require __DIR__ . '/lib/app.php';

pnet_session();
pnet_security_headers();

try {
    $pdo = pnet_boot();
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $action = (string) ($_GET['action'] ?? '');

    if (!pnet_on_home_network()) {
        if ($method === 'GET' && $action !== 'state' && $action !== '') {
            header('Location: index.php');
            exit;
        }
        pnet_fail(403, 'Connect to this home Wi-Fi to use PNet.');
    }

    if ($method === 'GET') {
        if ($action === 'state') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok' => true, 'state' => pnet_state($pdo)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        if ($action === 'traffic') {
            $deviceId = isset($_GET['device_id']) ? (int) $_GET['device_id'] : null;
            if ($deviceId !== null && $deviceId < 1) {
                $deviceId = null;
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(pnet_traffic_live($pdo, $deviceId), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        if ($action === 'router_login') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok' => true,
                'login' => pnet_router_get_login($pdo),
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        if ($action === 'export_hosts') {
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="pnet-blocklist.txt"');
            echo pnet_export_hosts($pdo);
            exit;
        }
        if ($action === 'dns_prepare') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok' => true, 'dns' => pnet_dns_prepare($pdo)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        if ($action === 'export_policy') {
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="pnet-policy.txt"');
            echo pnet_export_policy($pdo);
            exit;
        }
        if ($action === 'export_backup') {
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="pnet-backup.json"');
            echo pnet_export_backup($pdo);
            exit;
        }
        pnet_fail(404, 'Unknown request.');
    }

    $raw = file_get_contents('php://input');
    $data = json_decode($raw !== false && $raw !== '' ? $raw : '[]', true);
    if (!is_array($data)) {
        throw new InvalidArgumentException('Request was not valid JSON.');
    }
    pnet_check_csrf(isset($data['csrf']) ? (string) $data['csrf'] : null);
    $name = (string) ($data['action'] ?? '');
    $message = pnet_handle($pdo, $name, $data);
    pnet_ok($pdo, $message);
} catch (InvalidArgumentException $e) {
    pnet_fail(422, $e->getMessage());
} catch (RuntimeException $e) {
    pnet_fail(400, $e->getMessage());
} catch (Throwable $e) {
    pnet_fail(500, 'PNet could not finish that action.');
}
