<?php
declare(strict_types=1);

function pnet_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $script = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? ''));
    $base = rtrim(dirname($script), '/');
    if ($base === '' || $base === '.') {
        $base = '/';
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('pnet_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => $base,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function pnet_security_headers(): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'self'; img-src 'self' http: https: data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}

function pnet_h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function pnet_csrf(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function pnet_check_csrf(?string $token): void
{
    $known = $_SESSION['csrf'] ?? '';
    if (!is_string($known) || $known === '' || !is_string($token) || !hash_equals($known, $token)) {
        throw new InvalidArgumentException('Refresh the page and try again.');
    }
}

function pnet_now(): string
{
    return gmdate('Y-m-d H:i:s');
}

function pnet_boot(): PDO
{
    if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
        throw new RuntimeException('SQLite is not enabled in PHP. In XAMPP, open php.ini and enable extension=pdo_sqlite and extension=sqlite3, then restart Apache.');
    }
    $root = dirname(__DIR__);
    $dir = $root . DIRECTORY_SEPARATOR . 'data';
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new RuntimeException('PNet cannot create its data folder. Give the web server permission to write inside the pnet folder.');
    }
    try {
        $pdo = new PDO('sqlite:' . $dir . DIRECTORY_SEPARATOR . 'pnet.sqlite');
    } catch (PDOException $e) {
        throw new RuntimeException('PNet cannot open its database. Check that the data folder is writable.');
    }
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 3000');
    $pdo->exec('PRAGMA journal_mode = WAL');
    pnet_migrate($pdo);
    return $pdo;
}

function pnet_add_column(PDO $pdo, string $table, string $column, string $definition): void
{
    $known = [];
    foreach ($pdo->query('PRAGMA table_info(' . $table . ')')->fetchAll() as $row) {
        $known[(string) $row['name']] = true;
    }
    if (!isset($known[$column])) {
        $pdo->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $definition);
    }
}

function pnet_migrate(PDO $pdo): void
{
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    skey TEXT PRIMARY KEY,
    svalue TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    last_seen TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    direction TEXT NOT NULL,
    action TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    port TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    address TEXT NOT NULL,
    kind TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    fingerprint TEXT,
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    snapshot_url TEXT NOT NULL DEFAULT '',
    stream_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    last_seen TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS port_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    external_port TEXT NOT NULL,
    internal_ip TEXT NOT NULL,
    internal_port TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dhcp_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mac_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mac TEXT NOT NULL,
    mode TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    days TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    action TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_fp ON alerts(fingerprint) WHERE fingerprint IS NOT NULL AND status != 'resolved';
CREATE TABLE IF NOT EXISTS device_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS device_traffic (
    device_id INTEGER PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'agent',
    ip TEXT NOT NULL DEFAULT '',
    down_bps INTEGER NOT NULL DEFAULT 0,
    up_bps INTEGER NOT NULL DEFAULT 0,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    apps_json TEXT NOT NULL DEFAULT '[]',
    updated_at REAL NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
SQL);
    pnet_add_column($pdo, 'devices', 'trust', "TEXT NOT NULL DEFAULT 'unknown'");
    pnet_add_column($pdo, 'devices', 'access_profile', "TEXT NOT NULL DEFAULT 'normal'");
    pnet_add_column($pdo, 'devices', 'bandwidth_limit', 'INTEGER NOT NULL DEFAULT 0');
    pnet_add_column($pdo, 'devices', 'protected', 'INTEGER NOT NULL DEFAULT 0');
    pnet_add_column($pdo, 'devices', 'ping_ms', 'INTEGER');
    pnet_ensure_router_defaults($pdo);
    $count = (int) $pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn();
    $has_real_data = false;
    foreach (['devices', 'rules', 'sites', 'ips', 'alerts', 'cameras'] as $table) {
        if ((int) $pdo->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn() > 0) {
            $has_real_data = true;
            break;
        }
    }
    if ($count === 0 || !$has_real_data) {
        pnet_seed($pdo);
    }
}

function pnet_ensure_router_defaults(PDO $pdo): void
{
    $defaults = [
        'wifi_ssid' => '',
        'wifi_ssid_5g' => '',
        'wifi_security' => 'wpa2',
        'wifi_channel' => 'auto',
        'wifi_channel_5g' => 'auto',
        'wifi_band' => 'both',
        'wifi_hidden' => '0',
        'wifi_wps' => '0',
        'wifi_isolation' => '0',
        'guest_enabled' => '0',
        'guest_ssid' => 'Guest',
        'guest_security' => 'wpa2',
        'guest_isolation' => '1',
        'guest_bandwidth' => '0',
        'lan_ip' => '',
        'lan_mask' => '255.255.255.0',
        'dhcp_enabled' => '1',
        'dhcp_start' => '',
        'dhcp_end' => '',
        'dhcp_lease' => '24',
        'wan_mode' => 'dhcp',
        'wan_ip' => '',
        'wan_gateway' => '',
        'wan_dns1' => '',
        'wan_dns2' => '',
        'dns_mode' => 'isp',
        'dns_primary' => '',
        'dns_secondary' => '',
        'upnp_enabled' => '0',
        'remote_admin' => '0',
        'qos_enabled' => '0',
        'qos_mode' => 'device',
        'vpn_enabled' => '0',
        'vpn_type' => 'none',
        'vpn_server' => '',
        'vpn_notes' => '',
        'router_admin_url' => '',
        'router_model' => '',
        'router_brand' => '',
        'router_brand_name' => '',
        'router_notes' => '',
        'router_traffic_enabled' => '1',
        'mac_filter_mode' => 'disabled',
    ];
    foreach ($defaults as $key => $value) {
        if (pnet_setting($pdo, $key, '__missing__') === '__missing__') {
            pnet_setting_set($pdo, $key, $value);
        }
    }
}

function pnet_seed(PDO $pdo): void
{
    $pdo->beginTransaction();
    pnet_setting_set($pdo, 'home_name', 'My home');
    pnet_setting_set($pdo, 'lan_cidr', '');
    pnet_setting_set($pdo, 'sample_loaded', '0');
    pnet_log($pdo, 'setup', 'Initialized a blank home network dashboard for real data entry.');
    $pdo->commit();
}

function pnet_setting_set(PDO $pdo, string $key, string $value): void
{
    $pdo->prepare('INSERT OR REPLACE INTO settings (skey, svalue) VALUES (?, ?)')->execute([$key, $value]);
    $cache =& pnet_settings_cache($pdo);
    $cache[$key] = $value;
}

/** @return array<string,string> */
function &pnet_settings_cache(PDO $pdo, bool $refresh = false): array
{
    static $cache = null;
    if ($refresh || $cache === null) {
        $cache = [];
        foreach ($pdo->query('SELECT skey, svalue FROM settings') as $row) {
            $cache[(string) $row['skey']] = (string) $row['svalue'];
        }
    }
    return $cache;
}

function pnet_setting(PDO $pdo, string $key, string $default = ''): string
{
    $all = pnet_settings_cache($pdo);
    return array_key_exists($key, $all) ? $all[$key] : $default;
}

function pnet_log(PDO $pdo, string $action, string $detail): void
{
    $pdo->prepare('INSERT INTO activity (action, detail, created_at) VALUES (?, ?, ?)')->execute([
        pnet_text($action, 40, 'Action', true),
        pnet_text($detail, 240, 'Detail', true),
        pnet_now(),
    ]);
    $pdo->exec('DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY id DESC LIMIT 200)');
}

function pnet_user_count(PDO $pdo): int
{
    return (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
}

function pnet_user(PDO $pdo): ?array
{
    $id = $_SESSION['uid'] ?? 0;
    if (!is_int($id) && !ctype_digit((string) $id)) {
        return null;
    }
    $st = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE id = ?');
    $st->execute([(int) $id]);
    $row = $st->fetch();
    return $row ?: null;
}

function pnet_flash(string $message): void
{
    $_SESSION['flash'] = $message;
}

function pnet_take_flash(): string
{
    $message = $_SESSION['flash'] ?? '';
    unset($_SESSION['flash']);
    return is_string($message) ? $message : '';
}

function pnet_setup(PDO $pdo, array $post): void
{
    pnet_check_csrf($post['csrf'] ?? null);
    $pdo->beginTransaction();
    if (pnet_user_count($pdo) > 0) {
        $pdo->rollBack();
        throw new InvalidArgumentException('An admin account already exists.');
    }
    $username = pnet_username($post['username'] ?? '');
    $password = (string) ($post['password'] ?? '');
    $confirm = (string) ($post['confirm'] ?? '');
    pnet_password_rules($password, $confirm, $username);
    $home = trim((string) ($post['home_name'] ?? ''));
    if ($home === '') {
        $home = 'My home';
    }
    $home = pnet_text($home, 60, 'Home name', true);
    $now = pnet_now();
    $pdo->prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')->execute([
        $username,
        password_hash($password, PASSWORD_DEFAULT),
        $now,
    ]);
    pnet_setting_set($pdo, 'home_name', $home);
    $id = (int) $pdo->lastInsertId();
    pnet_log($pdo, 'account', 'Created the admin account.');
    $pdo->commit();
    session_regenerate_id(true);
    $_SESSION['uid'] = $id;
    $_SESSION['fails'] = 0;
}

function pnet_login(PDO $pdo, array $post): void
{
    pnet_check_csrf($post['csrf'] ?? null);
    $fails = (int) ($_SESSION['fails'] ?? 0);
    $failAt = (int) ($_SESSION['fail_at'] ?? 0);
    if ($fails >= 5 && (time() - $failAt) < 60) {
        throw new InvalidArgumentException('Too many tries. Wait a minute and try again.');
    }
    if ($fails >= 5) {
        $_SESSION['fails'] = 0;
    }
    $username = trim((string) ($post['username'] ?? ''));
    $password = (string) ($post['password'] ?? '');
    $st = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
    $st->execute([$username]);
    $row = $st->fetch();
    if (!$row || !password_verify($password, (string) $row['password_hash'])) {
        $_SESSION['fails'] = (int) ($_SESSION['fails'] ?? 0) + 1;
        $_SESSION['fail_at'] = time();
        throw new InvalidArgumentException('Wrong username or password.');
    }
    session_regenerate_id(true);
    $_SESSION['uid'] = (int) $row['id'];
    $_SESSION['fails'] = 0;
}

function pnet_text(string $value, int $max, string $label, bool $required): string
{
    $value = trim($value);
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value)) {
        throw new InvalidArgumentException($label . ' has unsupported characters.');
    }
    if ($required && $value === '') {
        throw new InvalidArgumentException($label . ' is required.');
    }
    $length = function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
    if ($length > $max) {
        throw new InvalidArgumentException($label . ' is too long.');
    }
    return $value;
}

function pnet_username(string $value): string
{
    $value = trim($value);
    if (!preg_match('/^[A-Za-z0-9._-]{3,32}$/', $value)) {
        throw new InvalidArgumentException('Username must be 3 to 32 letters, numbers, dots, dashes, or underscores.');
    }
    return $value;
}

function pnet_password_rules(string $password, string $confirm, string $username): void
{
    if (strlen($password) < 8 || strlen($password) > 200) {
        throw new InvalidArgumentException('Password must be at least 8 characters.');
    }
    if ($password !== $confirm) {
        throw new InvalidArgumentException('Passwords do not match.');
    }
    if (strcasecmp($password, $username) === 0) {
        throw new InvalidArgumentException('Use a password that is different from the username.');
    }
}

function pnet_enum(string $value, array $allowed, string $label): string
{
    $value = strtolower(trim($value));
    if (!in_array($value, $allowed, true)) {
        throw new InvalidArgumentException($label . ' is not valid.');
    }
    return $value;
}

function pnet_ip(string $value, bool $required, string $label = 'IP address'): string
{
    $value = trim($value);
    if ($value === '') {
        if ($required) {
            throw new InvalidArgumentException($label . ' is required.');
        }
        return '';
    }
    if (!filter_var($value, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException($label . ' must be a valid IP address.');
    }
    return $value;
}

function pnet_is_lan_ipv4(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    $parts = array_map('intval', explode('.', $ip));
    if ($parts[0] === 10) {
        return true;
    }
    if ($parts[0] === 192 && $parts[1] === 168) {
        return true;
    }
    if ($parts[0] === 172 && $parts[1] >= 16 && $parts[1] <= 31) {
        return true;
    }
    return false;
}

function pnet_client_ip(): string
{
    $ip = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    if (stripos($ip, '::ffff:') === 0) {
        $ip = substr($ip, 7);
    }
    return $ip;
}

function pnet_on_home_network(): bool
{
    $ip = pnet_client_ip();
    if ($ip === '::1') {
        return true;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = array_map('intval', explode('.', $ip));
        if ($parts[0] === 127 || ($parts[0] === 169 && $parts[1] === 254)) {
            return true;
        }
        return pnet_is_lan_ipv4($ip);
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return false;
    }
    $bin = inet_pton($ip);
    if ($bin === false || strlen($bin) !== 16) {
        return false;
    }
    $first = ord($bin[0]);
    $second = ord($bin[1]);
    if (($first & 0xfe) === 0xfc) {
        return true;
    }
    return $first === 0xfe && ($second & 0xc0) === 0x80;
}

function pnet_mac(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    $hex = strtoupper(str_replace('-', ':', $value));
    if (!preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/', $hex)) {
        throw new InvalidArgumentException('MAC address should look like AA:BB:CC:DD:EE:FF.');
    }
    return $hex;
}

function pnet_domain(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/\.+$/', '', $value) ?? '';
    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $value)) {
        throw new InvalidArgumentException('Enter a domain like example.com.');
    }
    return $value;
}

function pnet_endpoint(string $value): string
{
    $value = trim($value);
    if ($value === '' || strtolower($value) === 'any') {
        return 'any';
    }
    if (!preg_match('/^[0-9A-Za-z.:\/_-]{1,80}$/', $value)) {
        throw new InvalidArgumentException('Use an IP, a CIDR such as 192.168.1.0/24, or any.');
    }
    return $value;
}

function pnet_port(string $value): string
{
    $value = trim($value);
    if ($value === '' || strtolower($value) === 'any') {
        return '';
    }
    if (!preg_match('/^\d{1,5}(,\d{1,5})*$/', $value)) {
        throw new InvalidArgumentException('Port must be a number, or a list like 80,443.');
    }
    foreach (explode(',', $value) as $part) {
        $port = (int) $part;
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException('Ports must be between 1 and 65535.');
        }
    }
    return $value;
}

function pnet_url(string $value, array $schemes, string $label): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    if (strlen($value) > 500 || preg_match('/[\s<>"\']/', $value)) {
        throw new InvalidArgumentException($label . ' is not a usable link.');
    }
    $parts = parse_url($value);
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = (string) ($parts['host'] ?? '');
    if (!in_array($scheme, $schemes, true) || $host === '') {
        throw new InvalidArgumentException($label . ' must start with ' . implode(' or ', $schemes) . ' and include a host.');
    }
    return $value;
}

function pnet_id(array $data): int
{
    $id = (int) ($data['id'] ?? 0);
    if ($id < 1) {
        throw new InvalidArgumentException('That record was not found.');
    }
    return $id;
}

function pnet_tx(PDO $pdo, callable $work): string
{
    $pdo->beginTransaction();
    try {
        $message = $work();
        $pdo->commit();
        return is_string($message) ? $message : 'Saved.';
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function pnet_handle(PDO $pdo, string $action, array $data): string
{
    switch ($action) {
        case 'save_device':
            return pnet_save_device($pdo, $data);
        case 'set_device_access':
            return pnet_set_device_access($pdo, $data);
        case 'protect_device':
            return pnet_protect_device($pdo, $data);
        case 'delete_device':
            return pnet_delete_row($pdo, 'devices', 'Device removed.', $data);
        case 'save_rule':
            return pnet_save_rule($pdo, $data);
        case 'delete_rule':
            return pnet_delete_row($pdo, 'rules', 'Firewall rule removed.', $data);
        case 'toggle_rule':
            return pnet_toggle($pdo, 'rules', 'Firewall rule updated.', $data);
        case 'save_site':
            $message = pnet_save_site($pdo, $data);
            pnet_hosts_stale($pdo);
            return $message;
        case 'delete_site':
            $message = pnet_delete_row($pdo, 'sites', 'Site removed from the block list.', $data);
            pnet_hosts_stale($pdo);
            return $message;
        case 'toggle_site':
            $message = pnet_toggle($pdo, 'sites', 'Block list updated.', $data);
            pnet_hosts_stale($pdo);
            return $message;
        case 'set_ad_block':
            $message = pnet_set_ad_block($pdo, $data);
            pnet_hosts_stale($pdo);
            return $message;
        case 'set_adult_block':
            return pnet_set_adult_block($pdo, $data);
        case 'set_category_block':
            return pnet_set_category_block($pdo, $data);
        case 'save_bedtime':
            return pnet_save_bedtime($pdo, $data);
        case 'set_block_exception':
            return pnet_set_block_exception($pdo, $data);
        case 'mark_hosts_applied':
            return pnet_mark_hosts_applied($pdo, $data);
        case 'mark_hosts_removed':
            return pnet_mark_hosts_removed($pdo);
        case 'dns_blocker_report':
            return pnet_dns_blocker_report($pdo, $data);
        case 'use_pnet_dns':
            return pnet_use_pnet_dns($pdo);
        case 'dns_prepare':
            pnet_dns_prepare($pdo);
            return 'Network blocker files ready.';
        case 'wifi_dns_info':
            return pnet_wifi_dns_info_message($pdo);
        case 'save_ip':
            return pnet_save_ip($pdo, $data);
        case 'delete_ip':
            return pnet_delete_row($pdo, 'ips', 'Address removed.', $data);
        case 'save_alert':
            return pnet_save_alert($pdo, $data);
        case 'delete_alert':
            return pnet_delete_row($pdo, 'alerts', 'Defender item removed.', $data);
        case 'set_alert_status':
            return pnet_set_alert_status($pdo, $data);
        case 'save_camera':
            return pnet_save_camera($pdo, $data);
        case 'delete_camera':
            return pnet_delete_row($pdo, 'cameras', 'Camera removed.', $data);
        case 'save_settings':
            return pnet_save_settings($pdo, $data);
        case 'save_router_settings':
            return pnet_save_router_settings($pdo, $data);
        case 'save_port_forward':
            return pnet_save_port_forward($pdo, $data);
        case 'delete_port_forward':
            return pnet_delete_row($pdo, 'port_forwards', 'Port forward removed.', $data);
        case 'toggle_port_forward':
            return pnet_toggle($pdo, 'port_forwards', 'Port forward updated.', $data);
        case 'save_dhcp_reservation':
            return pnet_save_dhcp_reservation($pdo, $data);
        case 'delete_dhcp_reservation':
            return pnet_delete_row($pdo, 'dhcp_reservations', 'DHCP reservation removed.', $data);
        case 'toggle_dhcp_reservation':
            return pnet_toggle($pdo, 'dhcp_reservations', 'DHCP reservation updated.', $data);
        case 'save_mac_filter':
            return pnet_save_mac_filter($pdo, $data);
        case 'delete_mac_filter':
            return pnet_delete_row($pdo, 'mac_filters', 'MAC filter entry removed.', $data);
        case 'toggle_mac_filter':
            return pnet_toggle($pdo, 'mac_filters', 'MAC filter updated.', $data);
        case 'save_access_schedule':
            return pnet_save_access_schedule($pdo, $data);
        case 'delete_access_schedule':
            return pnet_delete_row($pdo, 'access_schedules', 'Access schedule removed.', $data);
        case 'toggle_access_schedule':
            return pnet_toggle($pdo, 'access_schedules', 'Access schedule updated.', $data);
        case 'change_password':
            return pnet_change_password($pdo, $data);
        case 'import_backup':
            return pnet_import_backup($pdo, $data);
        case 'check_host':
            return pnet_check_host($pdo, $data);
        case 'wake_device':
            return pnet_wake_device($pdo, $data);
        case 'find_devices':
            return pnet_find_devices($pdo);
        case 'port_scan':
            return pnet_port_scan($pdo);
        case 'defender_scan':
            return pnet_defender_scan($pdo);
        case 'clear_sample':
            return pnet_clear_sample($pdo);
        case 'router_connect':
            return pnet_router_connect($pdo, $data);
        case 'router_save_login':
            return pnet_router_save_login($pdo, $data);
        case 'router_probe':
            return pnet_router_probe_action($pdo);
        case 'router_sync_upnp':
            return pnet_router_sync_upnp($pdo);
        case 'router_sync_devices':
            return pnet_router_sync_devices($pdo);
        case 'create_device_agent':
            return pnet_create_device_agent($pdo, $data);
        case 'revoke_device_agent':
            return pnet_revoke_device_agent($pdo, $data);
        default:
            throw new InvalidArgumentException('Unknown action.');
    }
}

function pnet_require_login(PDO $pdo): void
{
    if (!pnet_user($pdo)) {
        throw new InvalidArgumentException('Sign in required.');
    }
}

function pnet_save_device(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $ip = pnet_ip((string) ($data['ip'] ?? ''), true);
    $mac = pnet_mac((string) ($data['mac'] ?? ''));
    $type = pnet_enum((string) ($data['type'] ?? 'other'), ['router', 'computer', 'phone', 'tablet', 'tv', 'console', 'printer', 'iot', 'camera', 'speaker', 'other'], 'Type');
    $vendor = pnet_text((string) ($data['vendor'] ?? ''), 80, 'Vendor', false);
    $status = pnet_enum((string) ($data['status'] ?? 'unknown'), ['online', 'offline', 'unknown'], 'Status');
    $trust = pnet_enum((string) ($data['trust'] ?? 'unknown'), ['trusted', 'unknown', 'guest', 'blocked'], 'Trust');
    $access = pnet_enum((string) ($data['access_profile'] ?? 'normal'), ['normal', 'limited', 'quarantined'], 'Access profile');
    $bandwidth = pnet_bandwidth_limit($data['bandwidth_limit'] ?? 0);
    $protected = !empty($data['protected']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $data, $name, $ip, $mac, $type, $vendor, $status, $trust, $access, $bandwidth, $protected, $notes, $now) {
        $id = (int) ($data['id'] ?? 0);
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE devices SET name=?, ip=?, mac=?, type=?, vendor=?, status=?, trust=?, access_profile=?, bandwidth_limit=?, protected=?, notes=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$name, $ip, $mac, $type, $vendor, $status, $trust, $access, $bandwidth, $protected, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'devices', $id)) {
                throw new InvalidArgumentException('That device was not found.');
            }
            pnet_log($pdo, 'device', 'Updated ' . $name . '.');
            return 'Device updated.';
        }
        $pdo->prepare('INSERT INTO devices (name, ip, mac, type, vendor, status, last_seen, trust, access_profile, bandwidth_limit, protected, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')->execute([$name, $ip, $mac, $type, $vendor, $status, '', $trust, $access, $bandwidth, $protected, $notes, $now, $now]);
        pnet_log($pdo, 'device', 'Added ' . $name . '.');
        return 'Device added.';
    });
}

function pnet_bandwidth_limit($value): int
{
    $limit = (int) $value;
    if ($limit < 0 || $limit > 100000) {
        throw new InvalidArgumentException('Bandwidth limit must be between 0 and 100000 Kbps.');
    }
    return $limit;
}

function pnet_set_device_access(PDO $pdo, array $data): string
{
    $id = pnet_id($data);
    $profile = pnet_enum((string) ($data['access_profile'] ?? ''), ['normal', 'limited', 'quarantined'], 'Access profile');
    return pnet_tx($pdo, function () use ($pdo, $id, $profile) {
        $st = $pdo->prepare('SELECT * FROM devices WHERE id = ?');
        $st->execute([$id]);
        $device = $st->fetch();
        if (!$device) {
            throw new InvalidArgumentException('That device was not found.');
        }
        $now = pnet_now();
        $trust = $profile === 'quarantined' ? 'blocked' : (string) $device['trust'];
        $pdo->prepare('UPDATE devices SET access_profile=?, trust=?, sample=0, updated_at=? WHERE id=?')->execute([$profile, $trust, $now, $id]);
        if ($profile === 'quarantined') {
            pnet_add_quarantine_policy($pdo, (string) $device['name'], (string) $device['ip'], $now);
            pnet_log($pdo, 'access', 'Quarantined ' . (string) $device['name'] . ' in policy.');
            return 'Device quarantined in policy.';
        }
        if ($profile === 'limited') {
            pnet_log($pdo, 'access', 'Marked ' . (string) $device['name'] . ' as limited access.');
            return 'Device marked limited.';
        }
        pnet_log($pdo, 'access', 'Resumed normal access for ' . (string) $device['name'] . '.');
        return 'Device set to normal access.';
    });
}

function pnet_add_quarantine_policy(PDO $pdo, string $name, string $ip, string $now): void
{
    $ruleName = 'Quarantine ' . $name;
    $st = $pdo->prepare('SELECT id FROM rules WHERE name = ? AND source = ? AND action = ?');
    $st->execute([$ruleName, $ip, 'block']);
    if (!$st->fetch()) {
        $pdo->prepare('INSERT INTO rules (name, direction, action, protocol, source, destination, port, priority, enabled, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')->execute([
            $ruleName,
            'outbound',
            'block',
            'any',
            $ip,
            'any',
            '',
            10,
            1,
            'Apply this rule on your router/firewall to quarantine this device.',
            $now,
            $now,
        ]);
    }
    $st = $pdo->prepare("SELECT id FROM ips WHERE address = ? AND kind = 'blocked'");
    $st->execute([$ip]);
    if (!$st->fetch()) {
        $pdo->prepare('INSERT INTO ips (label, address, kind, mac, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)')->execute([
            $name,
            $ip,
            'blocked',
            '',
            'Added from device quarantine.',
            $now,
            $now,
        ]);
    }
}

function pnet_protect_device(PDO $pdo, array $data): string
{
    $id = pnet_id($data);
    return pnet_tx($pdo, function () use ($pdo, $id) {
        $st = $pdo->prepare('UPDATE devices SET trust=?, protected=1, access_profile=CASE WHEN access_profile = \'quarantined\' THEN \'normal\' ELSE access_profile END, sample=0, updated_at=? WHERE id=?');
        $st->execute(['trusted', pnet_now(), $id]);
        if ($st->rowCount() < 1 && !pnet_exists($pdo, 'devices', $id)) {
            throw new InvalidArgumentException('That device was not found.');
        }
        pnet_log($pdo, 'protect', 'Marked a device trusted and protected.');
        return 'Device marked trusted and protected.';
    });
}

function pnet_save_rule(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $direction = pnet_enum((string) ($data['direction'] ?? ''), ['inbound', 'outbound'], 'Direction');
    $action = pnet_enum((string) ($data['action'] ?? ''), ['allow', 'block'], 'Action');
    $protocol = pnet_enum((string) ($data['protocol'] ?? 'any'), ['any', 'tcp', 'udp', 'icmp'], 'Protocol');
    $source = pnet_endpoint((string) ($data['source'] ?? 'any'));
    $destination = pnet_endpoint((string) ($data['destination'] ?? 'any'));
    $port = pnet_port((string) ($data['port'] ?? ''));
    $priority = (int) ($data['priority'] ?? 100);
    if ($priority < 1 || $priority > 9999) {
        throw new InvalidArgumentException('Priority must be between 1 and 9999.');
    }
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $data, $name, $direction, $action, $protocol, $source, $destination, $port, $priority, $enabled, $notes, $now) {
        $id = (int) ($data['id'] ?? 0);
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE rules SET name=?, direction=?, action=?, protocol=?, source=?, destination=?, port=?, priority=?, enabled=?, notes=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$name, $direction, $action, $protocol, $source, $destination, $port, $priority, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'rules', $id)) {
                throw new InvalidArgumentException('That rule was not found.');
            }
            pnet_log($pdo, 'firewall', 'Updated ' . $name . '.');
            return 'Firewall rule updated.';
        }
        $pdo->prepare('INSERT INTO rules (name, direction, action, protocol, source, destination, port, priority, enabled, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')->execute([$name, $direction, $action, $protocol, $source, $destination, $port, $priority, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'firewall', 'Added ' . $name . '.');
        return 'Firewall rule added.';
    });
}

function pnet_save_site(PDO $pdo, array $data): string
{
    $domain = pnet_domain((string) ($data['domain'] ?? ''));
    $category = pnet_enum((string) ($data['category'] ?? 'custom'), ['social', 'games', 'ads', 'adult', 'shopping', 'custom'], 'Category');
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    $id = (int) ($data['id'] ?? 0);
    $st = $pdo->prepare('SELECT id FROM sites WHERE domain = ? AND id != ?');
    $st->execute([$domain, $id]);
    if ($st->fetch()) {
        throw new InvalidArgumentException('That domain is already on the list.');
    }
    return pnet_tx($pdo, function () use ($pdo, $id, $domain, $category, $enabled, $notes, $now) {
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE sites SET domain=?, category=?, enabled=?, notes=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$domain, $category, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'sites', $id)) {
                throw new InvalidArgumentException('That site was not found.');
            }
            pnet_log($pdo, 'block', 'Updated ' . $domain . '.');
            return 'Block list updated.';
        }
        $pdo->prepare('INSERT INTO sites (domain, category, enabled, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)')->execute([$domain, $category, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'block', 'Blocked ' . $domain . '.');
        return 'Site added to the block list.';
    });
}

function pnet_adguard_filter_url(): string
{
    return 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt';
}

function pnet_adguard_cache_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.cache_adguard_filter.txt';
}

function pnet_adguard_legacy_cache_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.cache_adguard_filter.json';
}

/** @return array{source?:string,title?:string,fetched_at?:string,count?:int,domains?:list<string>}|null */
function pnet_adguard_cache_load(bool $withDomains = true): ?array
{
    $path = pnet_adguard_cache_path();
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if (!is_string($raw) || $raw === '') {
        return null;
    }
    $source = pnet_adguard_filter_url();
    $title = 'AdGuard DNS filter';
    $fetchedAt = '';
    $count = 0;
    $domains = [];
    foreach (preg_split('/\R/', $raw) ?: [] as $line) {
        $line = trim((string) $line);
        if ($line === '') {
            if (!$withDomains && $count > 0) {
                break;
            }
            continue;
        }
        if (str_starts_with($line, '# source:')) {
            $source = trim(substr($line, 9));
            continue;
        }
        if (str_starts_with($line, '# title:')) {
            $title = trim(substr($line, 8));
            continue;
        }
        if (str_starts_with($line, '# fetched_at:')) {
            $fetchedAt = trim(substr($line, 13));
            continue;
        }
        if (str_starts_with($line, '# count:')) {
            $count = (int) trim(substr($line, 8));
            if (!$withDomains && $count > 0) {
                break;
            }
            continue;
        }
        if ($line[0] === '#') {
            continue;
        }
        if (!$withDomains) {
            break;
        }
        if (pnet_is_blockable_domain($line)) {
            $domains[] = strtolower($line);
        }
    }
    if ($withDomains) {
        if (!$domains) {
            return null;
        }
        $domains = array_values(array_unique($domains));
        $count = count($domains);
    } elseif ($count < 1) {
        return null;
    }
    $result = [
        'source' => $source,
        'title' => $title,
        'fetched_at' => $fetchedAt,
        'count' => $count,
    ];
    if ($withDomains) {
        $result['domains'] = $domains;
    }
    return $result;
}

/** @param array{source:string,title:string,fetched_at:string,count:int,domains:list<string>} $cache */
function pnet_adguard_cache_save(array $cache): void
{
    $path = pnet_adguard_cache_path();
    $lines = [
        '# pnet-adguard-cache 1',
        '# title: ' . ($cache['title'] ?? 'AdGuard DNS filter'),
        '# source: ' . ($cache['source'] ?? pnet_adguard_filter_url()),
        '# fetched_at: ' . ($cache['fetched_at'] ?? pnet_now()),
        '# count: ' . (int) ($cache['count'] ?? count($cache['domains'] ?? [])),
        '',
    ];
    foreach ($cache['domains'] as $domain) {
        $lines[] = $domain;
    }
    $lines[] = '';
    @file_put_contents($path, implode("\n", $lines), LOCK_EX);
    $legacy = pnet_adguard_legacy_cache_path();
    if (is_file($legacy)) {
        @unlink($legacy);
    }
}

function pnet_is_blockable_domain(string $domain): bool
{
    $domain = strtolower(trim($domain));
    $domain = preg_replace('/\.+$/', '', $domain) ?? '';
    if ($domain === '' || strlen($domain) > 253 || filter_var($domain, FILTER_VALIDATE_IP)) {
        return false;
    }
    return (bool) preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain);
}

/** @return list<string> */
function pnet_parse_adguard_filter(string $text): array
{
    $domains = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        $line = trim((string) $line);
        if ($line === '' || $line[0] === '!' || $line[0] === '[') {
            continue;
        }
        if (str_starts_with($line, '@@')) {
            continue;
        }
        if (str_starts_with($line, '||')) {
            $rest = substr($line, 2);
            $domain = preg_replace('/[\^|$].*$/', '', $rest) ?? '';
            $domain = strtolower(trim($domain));
            if (pnet_is_blockable_domain($domain)) {
                $domains[$domain] = true;
            }
            continue;
        }
        if (preg_match('/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)/', $line, $match)) {
            $domain = strtolower($match[1]);
            if (pnet_is_blockable_domain($domain)) {
                $domains[$domain] = true;
            }
        }
    }
    $list = array_keys($domains);
    sort($list);
    return $list;
}

function pnet_http_get_prefix(string $url, int $bytes, int $timeoutSec = 30): string
{
    if ($bytes < 1 || !function_exists('curl_init')) {
        throw new RuntimeException('Could not read the block list header.');
    }
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Could not read the block list header.');
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => $timeoutSec,
        CURLOPT_USERAGENT => 'PNet/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_RANGE => '0-' . max(0, $bytes - 1),
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if (!is_string($body) || $body === '' || $code < 200 || $code >= 300) {
        throw new RuntimeException($err !== '' ? 'Download failed: ' . $err : 'Could not read the block list.');
    }
    return $body;
}

function pnet_http_get(string $url, int $timeoutSec = 90): string
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        if ($ch !== false) {
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_CONNECTTIMEOUT => 20,
                CURLOPT_TIMEOUT => $timeoutSec,
                CURLOPT_USERAGENT => 'PNet/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if (is_string($body) && $body !== '' && $code >= 200 && $code < 300) {
                return $body;
            }
            if ($err !== '') {
                throw new RuntimeException('Download failed: ' . $err);
            }
        }
    }

    $ctx = stream_context_create([
        'http' => [
            'timeout' => $timeoutSec,
            'user_agent' => 'PNet/1.0',
            'follow_location' => 1,
            'header' => "Accept: text/plain\r\n",
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    if (!is_string($body) || $body === '') {
        throw new RuntimeException('Download failed. Allow outbound HTTPS from PHP (curl or allow_url_fopen).');
    }
    return $body;
}

/**
 * @return array{cache:array{source:string,title:string,fetched_at:string,count:int,domains?:list<string>},downloaded:bool,stale:bool,error?:string}
 */
function pnet_sync_adguard_filter(bool $requireFresh = false): array
{
    $meta = pnet_adguard_cache_load(false);
    try {
        @set_time_limit(180);
        $body = pnet_http_get(pnet_adguard_filter_url(), 90);
        $domains = pnet_parse_adguard_filter($body);
        if (!$domains) {
            throw new RuntimeException('The AdGuard filter file was empty.');
        }
        $cache = [
            'source' => pnet_adguard_filter_url(),
            'title' => 'AdGuard DNS filter',
            'fetched_at' => pnet_now(),
            'count' => count($domains),
            'domains' => $domains,
        ];
        pnet_adguard_cache_save($cache);
        unset($cache['domains']);
        return ['cache' => $cache, 'downloaded' => true, 'stale' => false];
    } catch (Throwable $e) {
        if ($meta !== null) {
            return [
                'cache' => $meta,
                'downloaded' => false,
                'stale' => true,
                'error' => $e->getMessage(),
            ];
        }
        if ($requireFresh) {
            throw new RuntimeException('Could not download the AdGuard block list. Check your internet connection and try again.');
        }
        throw $e;
    }
}

function pnet_ad_block_note(): string
{
    return 'AdGuard DNS filter';
}

function pnet_ad_block_cleanup_legacy(PDO $pdo): void
{
    $pdo->prepare('DELETE FROM sites WHERE notes IN (?, ?)')->execute(['PNet ad list', pnet_ad_block_note()]);
}

function pnet_adguard_domain_count(PDO $pdo): int
{
    if (pnet_setting($pdo, 'ad_block_enabled', '0') !== '1') {
        return 0;
    }
    $cache = pnet_adguard_cache_load(false);
    return $cache ? (int) ($cache['count'] ?? 0) : 0;
}

/** @return list<string> */
function pnet_blocked_domains(PDO $pdo): array
{
    $domains = [];
    if (pnet_setting($pdo, 'ad_block_enabled', '0') === '1') {
        $cache = pnet_adguard_cache_load(true);
        if ($cache && !empty($cache['domains'])) {
            foreach ($cache['domains'] as $domain) {
                $domains[$domain] = true;
            }
        }
    }
    foreach ($pdo->query('SELECT domain FROM sites WHERE enabled = 1 ORDER BY domain')->fetchAll() as $site) {
        $domain = strtolower((string) $site['domain']);
        $domains[$domain] = true;
        if (!str_starts_with($domain, 'www.')) {
            $domains['www.' . $domain] = true;
        }
    }
    $list = array_keys($domains);
    sort($list);
    return $list;
}

function pnet_hosts_stale(PDO $pdo): void
{
    pnet_setting_set($pdo, 'hosts_applied', '0');
    pnet_dns_blocker_mark_pending($pdo);
}

function pnet_mark_hosts_applied(PDO $pdo, array $data): string
{
    $count = (int) ($data['count'] ?? 0);
    if ($count < 1) {
        $count = count(pnet_blocked_domains($pdo));
    }
    pnet_setting_set($pdo, 'hosts_applied', '1');
    pnet_setting_set($pdo, 'hosts_applied_at', pnet_now());
    pnet_setting_set($pdo, 'hosts_applied_count', (string) $count);
    pnet_log($pdo, 'block', 'Applied block list on this PC (' . $count . ' domains).');
    return 'Block list applied on this PC. Blocked sites should stop opening in your browser.';
}

function pnet_mark_hosts_removed(PDO $pdo): string
{
    pnet_setting_set($pdo, 'hosts_applied', '0');
    pnet_setting_set($pdo, 'hosts_applied_at', '');
    pnet_setting_set($pdo, 'hosts_applied_count', '0');
    pnet_log($pdo, 'block', 'Removed PNet block list from this PC.');
    return 'PNet block list removed from this PC.';
}

function pnet_set_ad_block(PDO $pdo, array $data): string
{
    $enabled = !empty($data['enabled']) ? 1 : 0;
    if ($enabled === 1) {
        $sync = pnet_sync_adguard_filter(true);
        $cache = $sync['cache'];
        return pnet_tx($pdo, function () use ($pdo, $sync, $cache) {
            pnet_ad_block_cleanup_legacy($pdo);
            pnet_setting_set($pdo, 'ad_block_enabled', '1');
            pnet_setting_set($pdo, 'ad_block_updated', (string) ($cache['fetched_at'] ?? pnet_now()));
            pnet_dns_blocker_mark_pending($pdo);
            pnet_log($pdo, 'ads', 'AdGuard list loaded (' . $cache['count'] . ' domains).');
            $count = number_format((int) $cache['count']);
            if ($sync['downloaded']) {
                return 'AdGuard ad blocker on. ' . $count . ' domains loaded. Start the network blocker so the whole Wi‑Fi uses them.';
            }
            return 'AdGuard ad blocker on using cached list (' . $count . ' domains). Could not refresh: ' . ($sync['error'] ?? 'download failed') . '.';
        });
    }

    return pnet_tx($pdo, function () use ($pdo) {
        pnet_setting_set($pdo, 'ad_block_enabled', '0');
        pnet_dns_blocker_mark_pending($pdo);
        pnet_log($pdo, 'ads', 'Ad blocker turned off.');
        return 'Ad blocker off. Your custom blocked sites were left alone.';
    });
}

function pnet_adult_filter_url(): string
{
    return 'https://blocklistproject.github.io/Lists/porn.txt';
}

function pnet_adult_cache_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.cache_adult_filter.txt';
}

/** @return array{source:string,title:string,fetched_at:string,count:int}|null */
function pnet_adult_cache_load(): ?array
{
    $path = pnet_adult_cache_path();
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if (!is_string($raw) || $raw === '') {
        return null;
    }
    $cache = [
        'source' => pnet_adult_filter_url(),
        'title' => 'Adult sites',
        'fetched_at' => '',
        'count' => 0,
    ];
    foreach (preg_split('/\R/', $raw) ?: [] as $line) {
        $line = trim((string) $line);
        if (str_starts_with($line, '# title:')) {
            $cache['title'] = trim(substr($line, 8));
        } elseif (str_starts_with($line, '# source:')) {
            $cache['source'] = trim(substr($line, 9));
        } elseif (str_starts_with($line, '# fetched_at:')) {
            $cache['fetched_at'] = trim(substr($line, 13));
        } elseif (str_starts_with($line, '# count:')) {
            $cache['count'] = (int) trim(substr($line, 8));
        }
    }
    if ($cache['count'] < 1) {
        return null;
    }
    return $cache;
}

/** @param array{source:string,title:string,fetched_at:string,count:int} $cache */
function pnet_adult_cache_save(array $cache): void
{
    $lines = [
        '# pnet-adult-cache 1',
        '# title: ' . ($cache['title'] ?? 'Adult sites'),
        '# source: ' . ($cache['source'] ?? pnet_adult_filter_url()),
        '# fetched_at: ' . ($cache['fetched_at'] ?? pnet_now()),
        '# count: ' . (int) ($cache['count'] ?? 0),
        '',
    ];
    @file_put_contents(pnet_adult_cache_path(), implode("\n", $lines), LOCK_EX);
}

/**
 * @return array{cache:array{source:string,title:string,fetched_at:string,count:int},downloaded:bool,stale:bool,error?:string}
 */
function pnet_sync_adult_filter(bool $requireFresh = false): array
{
    $meta = pnet_adult_cache_load();
    try {
        @set_time_limit(60);
        $head = pnet_http_get_prefix(pnet_adult_filter_url(), 4096);
        $title = 'Adult sites';
        $count = 0;
        if (preg_match('/^# Title:\s*(.+)$/m', $head, $match)) {
            $title = trim($match[1]);
        }
        if (preg_match('/^# Entries:\s*([\d,]+)/m', $head, $match)) {
            $count = (int) str_replace(',', '', $match[1]);
        }
        if ($count < 1000) {
            throw new RuntimeException('The adult block list did not include a usable domain count.');
        }
        $cache = [
            'source' => pnet_adult_filter_url(),
            'title' => $title,
            'fetched_at' => pnet_now(),
            'count' => $count,
        ];
        pnet_adult_cache_save($cache);
        return ['cache' => $cache, 'downloaded' => true, 'stale' => false];
    } catch (Throwable $e) {
        if ($meta !== null) {
            return [
                'cache' => $meta,
                'downloaded' => false,
                'stale' => true,
                'error' => $e->getMessage(),
            ];
        }
        if ($requireFresh) {
            throw new RuntimeException('Could not reach the adult block list. Check your internet connection and try again.');
        }
        throw $e;
    }
}

function pnet_adult_domain_count(PDO $pdo): int
{
    if (pnet_setting($pdo, 'adult_block_enabled', '0') !== '1') {
        return 0;
    }
    $cache = pnet_adult_cache_load();
    return $cache ? (int) ($cache['count'] ?? 0) : 0;
}

function pnet_set_adult_block(PDO $pdo, array $data): string
{
    $enabled = !empty($data['enabled']) ? 1 : 0;
    if ($enabled === 1) {
        $sync = pnet_sync_adult_filter(true);
        $cache = $sync['cache'];
        return pnet_tx($pdo, function () use ($pdo, $sync, $cache) {
            pnet_setting_set($pdo, 'adult_block_enabled', '1');
            pnet_setting_set($pdo, 'adult_block_updated', (string) ($cache['fetched_at'] ?? pnet_now()));
            pnet_dns_blocker_mark_pending($pdo);
            pnet_log($pdo, 'block', 'Adult site list on (' . $cache['count'] . ' domains).');
            $count = number_format((int) $cache['count']);
            if ($sync['downloaded']) {
                return 'Adult sites blocked. ' . $count . ' domains. Sync the network blocker so the whole Wi‑Fi uses the list. Search engines are set to safe search.';
            }
            return 'Adult sites blocked using the saved list (' . $count . ' domains). Could not refresh: ' . ($sync['error'] ?? 'download failed') . '.';
        });
    }

    return pnet_tx($pdo, function () use ($pdo) {
        pnet_setting_set($pdo, 'adult_block_enabled', '0');
        pnet_dns_blocker_mark_pending($pdo);
        pnet_log($pdo, 'block', 'Adult site list turned off.');
        return 'Adult site blocking off. Ads and your custom blocked sites were left alone.';
    });
}

/** @return array<string, list<string>> */
function pnet_category_domains(): array
{
    return [
        'social' => ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'instagram.com', 'cdninstagram.com', 'threads.net', 'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'snapchat.com', 'twitter.com', 'x.com', 'twimg.com', 't.co', 'reddit.com', 'redd.it', 'pinterest.com', 'linkedin.com', 'discord.com', 'discordapp.com', 'whatsapp.com', 'whatsapp.net', 'telegram.org', 't.me', 'tumblr.com'],
        'games' => ['roblox.com', 'rbxcdn.com', 'steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'epicgames.com', 'fortnite.com', 'minecraft.net', 'mojang.com', 'xbox.com', 'xboxlive.com', 'playstation.com', 'playstation.net', 'nintendo.com', 'nintendo.net', 'ea.com', 'origin.com', 'battle.net', 'blizzard.com', 'riotgames.com', 'leagueoflegends.com', 'ubisoft.com', 'rockstargames.com'],
        'streaming' => ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'netflix.com', 'nflxvideo.net', 'nflximg.net', 'disneyplus.com', 'bamgrid.com', 'hulu.com', 'primevideo.com', 'twitch.tv', 'ttvnw.net', 'jtvnw.net', 'hbomax.com', 'max.com', 'paramountplus.com', 'peacocktv.com', 'spotify.com', 'scdn.co'],
    ];
}

function pnet_home_timezone(): DateTimeZone
{
    static $tz = null;
    if ($tz instanceof DateTimeZone) {
        return $tz;
    }
    $name = date_default_timezone_get();
    if ($name === 'UTC' || $name === 'Etc/UTC') {
        $win = trim((string) @shell_exec('tzutil /g'));
        $map = [
            'Pacific Standard Time' => 'America/Los_Angeles',
            'Mountain Standard Time' => 'America/Denver',
            'Central Standard Time' => 'America/Chicago',
            'Eastern Standard Time' => 'America/New_York',
            'Alaskan Standard Time' => 'America/Anchorage',
            'Hawaiian Standard Time' => 'Pacific/Honolulu',
            'GMT Standard Time' => 'Europe/London',
            'W. Europe Standard Time' => 'Europe/Berlin',
            'Romance Standard Time' => 'Europe/Paris',
            'Central Europe Standard Time' => 'Europe/Budapest',
            'Tokyo Standard Time' => 'Asia/Tokyo',
            'China Standard Time' => 'Asia/Shanghai',
            'India Standard Time' => 'Asia/Kolkata',
            'AUS Eastern Standard Time' => 'Australia/Sydney',
        ];
        if (isset($map[$win])) {
            $name = $map[$win];
        }
    }
    try {
        $tz = new DateTimeZone($name);
    } catch (Throwable $e) {
        $tz = new DateTimeZone('UTC');
    }
    return $tz;
}

function pnet_bedtime_active(PDO $pdo): bool
{
    if (pnet_setting($pdo, 'bedtime_enabled', '0') !== '1') {
        return false;
    }
    $start = pnet_setting($pdo, 'bedtime_start', '22:00');
    $end = pnet_setting($pdo, 'bedtime_end', '07:00');
    if (!preg_match('/^(\d{2}):(\d{2})$/', $start, $sm) || !preg_match('/^(\d{2}):(\d{2})$/', $end, $em)) {
        return false;
    }
    $now = new DateTimeImmutable('now', pnet_home_timezone());
    $minutes = ((int) $now->format('H')) * 60 + (int) $now->format('i');
    $startMin = ((int) $sm[1]) * 60 + (int) $sm[2];
    $endMin = ((int) $em[1]) * 60 + (int) $em[2];
    if ($startMin === $endMin) {
        return true;
    }
    if ($startMin < $endMin) {
        return $minutes >= $startMin && $minutes < $endMin;
    }
    return $minutes >= $startMin || $minutes < $endMin;
}

/** @return list<string> */
function pnet_bedtime_targets(PDO $pdo): array
{
    $raw = pnet_setting($pdo, 'bedtime_targets', 'social,games,streaming');
    $allowed = array_keys(pnet_category_domains());
    $out = [];
    foreach (explode(',', $raw) as $part) {
        $part = trim($part);
        if (in_array($part, $allowed, true)) {
            $out[] = $part;
        }
    }
    return $out;
}

function pnet_category_active(PDO $pdo, string $category): bool
{
    if (!isset(pnet_category_domains()[$category])) {
        return false;
    }
    if (pnet_setting($pdo, $category . '_block_enabled', '0') === '1') {
        return true;
    }
    return pnet_bedtime_active($pdo) && in_array($category, pnet_bedtime_targets($pdo), true);
}

/** @return array<int, list<string>> */
function pnet_block_exceptions(PDO $pdo): array
{
    $data = json_decode(pnet_setting($pdo, 'block_exceptions', '{}'), true);
    if (!is_array($data)) {
        return [];
    }
    $allowed = array_keys(pnet_category_domains());
    $out = [];
    foreach ($data as $id => $cats) {
        $deviceId = (int) $id;
        if ($deviceId < 1 || !is_array($cats)) {
            continue;
        }
        $clean = [];
        foreach ($cats as $cat) {
            $cat = (string) $cat;
            if (in_array($cat, $allowed, true)) {
                $clean[] = $cat;
            }
        }
        if ($clean) {
            $out[$deviceId] = array_values(array_unique($clean));
        }
    }
    return $out;
}

function pnet_save_block_exceptions(PDO $pdo, array $map): void
{
    pnet_setting_set($pdo, 'block_exceptions', json_encode($map, JSON_UNESCAPED_UNICODE));
}

/** @return list<array{device_id:int,name:string,ip:string,categories:list<string>}> */
function pnet_block_allow_rows(PDO $pdo): array
{
    $map = pnet_block_exceptions($pdo);
    if (!$map) {
        return [];
    }
    $rows = [];
    $st = $pdo->prepare('SELECT id, name, ip FROM devices WHERE id = ?');
    foreach ($map as $id => $cats) {
        $st->execute([$id]);
        $device = $st->fetch();
        if (!$device) {
            continue;
        }
        $rows[] = [
            'device_id' => $id,
            'name' => (string) $device['name'],
            'ip' => (string) $device['ip'],
            'categories' => $cats,
        ];
    }
    return $rows;
}

function pnet_block_rules_signature(PDO $pdo): string
{
    $active = [];
    foreach (array_keys(pnet_category_domains()) as $cat) {
        if (pnet_category_active($pdo, $cat)) {
            $active[] = $cat;
        }
    }
    return hash('sha256', json_encode([
        $active,
        pnet_block_exceptions($pdo),
        pnet_custom_block_domains($pdo),
    ]));
}

function pnet_apply_block_rules(PDO $pdo): void
{
    $sig = pnet_block_rules_signature($pdo);
    if (pnet_setting($pdo, 'block_rules_sig', '') === $sig) {
        return;
    }
    pnet_dns_write_user_rules($pdo);
    pnet_setting_set($pdo, 'block_rules_sig', $sig);
    pnet_dns_blocker_mark_pending($pdo);
}

function pnet_set_category_block(PDO $pdo, array $data): string
{
    $category = (string) ($data['category'] ?? '');
    $names = ['social' => 'Social sites', 'games' => 'Games', 'streaming' => 'Streaming'];
    if (!isset($names[$category])) {
        throw new InvalidArgumentException('Unknown block list.');
    }
    $enabled = !empty($data['enabled']) ? '1' : '0';
    return pnet_tx($pdo, function () use ($pdo, $category, $enabled, $names) {
        pnet_setting_set($pdo, $category . '_block_enabled', $enabled);
        pnet_apply_block_rules($pdo);
        pnet_log($pdo, 'block', $names[$category] . ($enabled === '1' ? ' blocked.' : ' blocking off.'));
        $count = count(pnet_category_domains()[$category]);
        if ($enabled === '1') {
            return $names[$category] . ' blocked (' . $count . ' domains). Sync the network blocker so the whole Wi‑Fi uses them.';
        }
        return $names[$category] . ' blocking off.';
    });
}

function pnet_save_bedtime(PDO $pdo, array $data): string
{
    $start = trim((string) ($data['bedtime_start'] ?? '22:00'));
    $end = trim((string) ($data['bedtime_end'] ?? '07:00'));
    if (!preg_match('/^(\d{2}:\d{2})/', $start, $startMatch) || !preg_match('/^(\d{2}:\d{2})/', $end, $endMatch)) {
        throw new InvalidArgumentException('Use times like 22:00 and 07:00.');
    }
    $start = $startMatch[1];
    $end = $endMatch[1];
    $targets = [];
    foreach (array_keys(pnet_category_domains()) as $cat) {
        if (!empty($data['bedtime_' . $cat])) {
            $targets[] = $cat;
        }
    }
    if (!$targets) {
        $targets = ['social', 'games', 'streaming'];
    }
    return pnet_tx($pdo, function () use ($pdo, $data, $start, $end, $targets) {
        pnet_setting_set($pdo, 'bedtime_enabled', !empty($data['enabled']) ? '1' : '0');
        pnet_setting_set($pdo, 'bedtime_start', $start);
        pnet_setting_set($pdo, 'bedtime_end', $end);
        pnet_setting_set($pdo, 'bedtime_targets', implode(',', $targets));
        pnet_apply_block_rules($pdo);
        $on = pnet_bedtime_active($pdo);
        pnet_log($pdo, 'block', 'Bedtime saved' . ($on ? ' (active now).' : '.'));
        return $on
            ? 'Bedtime is on now (' . $start . '–' . $end . '). Sync the network blocker.'
            : 'Bedtime saved for ' . $start . '–' . $end . '.';
    });
}

function pnet_set_block_exception(PDO $pdo, array $data): string
{
    $category = (string) ($data['category'] ?? '');
    if (!isset(pnet_category_domains()[$category])) {
        throw new InvalidArgumentException('Pick social, games, or streaming.');
    }
    $id = (int) ($data['device_id'] ?? $data['id'] ?? 0);
    $st = $pdo->prepare('SELECT id, name, ip FROM devices WHERE id = ?');
    $st->execute([$id]);
    $device = $st->fetch();
    if (!$device) {
        throw new InvalidArgumentException('Pick a device.');
    }
    $allow = !isset($data['allow']) || !empty($data['allow']);
    return pnet_tx($pdo, function () use ($pdo, $device, $category, $allow) {
        $map = pnet_block_exceptions($pdo);
        $id = (int) $device['id'];
        $cats = $map[$id] ?? [];
        $cats = array_values(array_filter($cats, static fn (string $cat): bool => $cat !== $category));
        if ($allow) {
            $cats[] = $category;
            $map[$id] = $cats;
        } elseif ($cats) {
            $map[$id] = $cats;
        } else {
            unset($map[$id]);
        }
        pnet_save_block_exceptions($pdo, $map);
        pnet_apply_block_rules($pdo);
        $label = (string) $device['name'];
        if ($allow) {
            pnet_log($pdo, 'block', $label . ' may open ' . $category . ' sites.');
            return $label . ' can open ' . $category . ' sites. Sync the network blocker.';
        }
        pnet_log($pdo, 'block', $label . ' exception removed for ' . $category . '.');
        return 'Exception removed for ' . $label . '.';
    });
}

function pnet_dns_dir(): string
{
    $dir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'adguardhome';
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new RuntimeException('Could not create the AdGuard Home data folder.');
    }
    return $dir;
}

function pnet_dns_password_hash(): string
{
    $path = pnet_dns_dir() . DIRECTORY_SEPARATOR . '.password_hash';
    if (is_file($path)) {
        $hash = trim((string) file_get_contents($path));
        if ($hash !== '') {
            return $hash;
        }
    }
    $hash = password_hash('pnet-dns', PASSWORD_BCRYPT);
    file_put_contents($path, $hash);
    return $hash;
}

/** @return list<string> */
function pnet_custom_block_domains(PDO $pdo): array
{
    $domains = [];
    foreach ($pdo->query('SELECT domain FROM sites WHERE enabled = 1 ORDER BY domain')->fetchAll() as $site) {
        $domain = strtolower((string) $site['domain']);
        if ($domain === '') {
            continue;
        }
        $domains[$domain] = true;
        if (!str_starts_with($domain, 'www.')) {
            $domains['www.' . $domain] = true;
        }
    }
    $list = array_keys($domains);
    sort($list);
    return $list;
}

/** @return list<string> */
function pnet_block_rule_lines(PDO $pdo): array
{
    $lines = [];
    $catalog = pnet_category_domains();
    $active = [];
    foreach ($catalog as $category => $domains) {
        if (!pnet_category_active($pdo, $category)) {
            continue;
        }
        $active[$category] = $domains;
        foreach ($domains as $domain) {
            $lines[] = '||' . $domain . '^';
        }
    }
    if ($active) {
        $st = $pdo->prepare('SELECT ip FROM devices WHERE id = ?');
        foreach (pnet_block_exceptions($pdo) as $deviceId => $cats) {
            $st->execute([$deviceId]);
            $ip = (string) ($st->fetchColumn() ?: '');
            if (!pnet_is_lan_ipv4($ip)) {
                continue;
            }
            foreach ($cats as $category) {
                foreach ($active[$category] ?? [] as $domain) {
                    $lines[] = '@@||' . $domain . '^$client=' . $ip;
                }
            }
        }
    }
    foreach (pnet_custom_block_domains($pdo) as $domain) {
        $lines[] = '||' . $domain . '^';
    }
    return $lines;
}

function pnet_dns_write_user_rules(PDO $pdo): string
{
    $path = pnet_dns_dir() . DIRECTORY_SEPARATOR . 'pnet-user-rules.txt';
    $lines = [
        '! Title: PNet custom blocks',
        '! Generated ' . pnet_now() . ' UTC',
        '!',
    ];
    foreach (pnet_block_rule_lines($pdo) as $rule) {
        $lines[] = $rule;
    }
    $lines[] = '';
    file_put_contents($path, implode("\n", $lines));
    return $path;
}

function pnet_dns_write_yaml(PDO $pdo): string
{
    $dir = pnet_dns_dir();
    $rules = $dir . DIRECTORY_SEPARATOR . 'pnet-user-rules.txt';
    if (!is_file($rules)) {
        pnet_dns_write_user_rules($pdo);
    }
    $rulesUri = 'file:///' . str_replace('\\', '/', $rules);
    $hash = pnet_dns_password_hash();
    $adEnabled = pnet_setting($pdo, 'ad_block_enabled', '0') === '1' ? 'true' : 'false';
    $adultEnabled = pnet_setting($pdo, 'adult_block_enabled', '0') === '1' ? 'true' : 'false';
    $adultUrl = pnet_adult_filter_url();
    $yaml = <<<YAML
bind_host: 127.0.0.1
bind_port: 3000
users:
  - name: pnet
    password: {$hash}
auth_attempts: 5
block_auth_min: 15
http:
  address: 127.0.0.1:3000
  session_ttl: 720h
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  upstream_dns:
    - https://dns.cloudflare.com/dns-query
    - 1.1.1.1
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  protection_enabled: true
  ratelimit: 0
  cache_size: 4194304
  enable_dnssec: false
filtering:
  protection_enabled: true
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safebrowsing_enabled: false
  safesearch_enabled: {$adultEnabled}
querylog:
  enabled: true
  file_enabled: true
  interval: 24h
  size_memory: 1000
statistics:
  enabled: true
  interval: 24h
filters:
  - enabled: {$adEnabled}
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: {$rulesUri}
    name: PNet custom blocks
    id: 2
  - enabled: {$adultEnabled}
    url: {$adultUrl}
    name: Adult sites
    id: 3
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
schema_version: 28
YAML;
    $path = $dir . DIRECTORY_SEPARATOR . 'AdGuardHome.yaml';
    file_put_contents($path, $yaml);
    return $path;
}

function pnet_dns_blocker_mark_pending(PDO $pdo): void
{
    pnet_setting_set($pdo, 'dns_blocker_sync_pending', '1');
}

/** @return array<string,mixed> */
function pnet_dns_prepare(PDO $pdo): array
{
    $rules = pnet_dns_write_user_rules($pdo);
    $yaml = pnet_dns_write_yaml($pdo);
    $net = pnet_network_info();
    $payload = [
        'source_dir' => pnet_dns_dir(),
        'filter_path' => $rules,
        'yaml_path' => $yaml,
        'password_hash' => pnet_dns_password_hash(),
        'username' => 'pnet',
        'password' => 'pnet-dns',
        'lan_ip' => (string) ($net['local_ip'] ?? ''),
        'ad_block_enabled' => pnet_setting($pdo, 'ad_block_enabled', '0') === '1',
        'adult_block_enabled' => pnet_setting($pdo, 'adult_block_enabled', '0') === '1',
        'adguard_filter_url' => pnet_adguard_filter_url(),
        'adult_filter_url' => pnet_adult_filter_url(),
        'user_rules' => pnet_block_rule_lines($pdo),
        'web_port' => 3000,
        'dns_port' => 53,
    ];
    file_put_contents(
        pnet_dns_dir() . DIRECTORY_SEPARATOR . 'meta.json',
        json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
    );
    return $payload;
}

function pnet_dns_blocker_report(PDO $pdo, array $data): string
{
    $running = !empty($data['running']) ? '1' : '0';
    $lan = pnet_ip((string) ($data['lan_ip'] ?? ''), false, 'LAN IP');
    pnet_setting_set($pdo, 'dns_blocker_enabled', $running);
    pnet_setting_set($pdo, 'dns_blocker_host', $lan);
    pnet_setting_set($pdo, 'dns_blocker_updated', pnet_now());
    if (!empty($data['synced'])) {
        pnet_setting_set($pdo, 'dns_blocker_sync_pending', '0');
    }
    if ($running === '1') {
        pnet_log($pdo, 'dns', 'Network DNS blocker running on ' . ($lan !== '' ? $lan : 'this PC') . '.');
        return 'Network DNS blocker is running. Set your router DNS to this PC.';
    }
    pnet_log($pdo, 'dns', 'Network DNS blocker stopped.');
    return 'Network DNS blocker stopped.';
}

function pnet_use_pnet_dns(PDO $pdo): string
{
    $net = pnet_network_info();
    $ip = (string) ($net['local_ip'] ?? '');
    if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
        $saved = pnet_setting($pdo, 'dns_blocker_host', '');
        $ip = $saved;
    }
    if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
        throw new InvalidArgumentException('Could not detect this PC’s Wi‑Fi address. Start the network blocker first.');
    }
    return pnet_tx($pdo, function () use ($pdo, $ip) {
        pnet_setting_set($pdo, 'dns_mode', 'custom');
        pnet_setting_set($pdo, 'dns_primary', $ip);
        if (pnet_setting($pdo, 'dns_secondary', '') === '') {
            pnet_setting_set($pdo, 'dns_secondary', '1.1.1.1');
        }
        pnet_log($pdo, 'dns', 'Router DNS plan set to PNet (' . $ip . ').');
        return 'Saved PNet DNS (' . $ip . ') in your router plan. Open the router and set the same DNS so the whole Wi‑Fi is blocked.';
    });
}

function pnet_wifi_dns_info(): array
{
    $empty = [
        'ok' => true,
        'wifi_adapter' => '',
        'wifi_dns' => [],
        'wifi_pushed' => false,
    ];
    if (PHP_OS_FAMILY !== 'Windows' || !pnet_can_exec()) {
        return $empty;
    }
    $script = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'pnet-dns.ps1';
    if (is_file($script)) {
        $cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' . escapeshellarg($script)
            . ' -Action pull-wifi -WorkDir ' . escapeshellarg(sys_get_temp_dir());
        $lines = [];
        $code = 1;
        exec($cmd, $lines, $code);
        $raw = trim(implode("\n", $lines));
        if ($raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                return [
                    'ok' => true,
                    'wifi_adapter' => (string) ($decoded['wifi_adapter'] ?? ''),
                    'wifi_dns' => array_values(array_filter(array_map('strval', is_array($decoded['wifi_dns'] ?? null) ? $decoded['wifi_dns'] : []))),
                    'wifi_pushed' => !empty($decoded['wifi_pushed']),
                ];
            }
        }
    }
    // Fallback: parse ipconfig /all for the active adapter DNS list.
    $live = pnet_live_adapter_details();
    $dns = is_array($live['dns'] ?? null) ? array_values(array_filter(array_map('strval', $live['dns']))) : [];
    return [
        'ok' => true,
        'wifi_adapter' => (string) ($live['adapter'] ?? 'Wi‑Fi'),
        'wifi_dns' => $dns,
        'wifi_pushed' => in_array('127.0.0.1', $dns, true),
    ];
}

function pnet_wifi_dns_info_message(PDO $pdo): string
{
    $info = pnet_wifi_dns_info();
    $adapter = (string) ($info['wifi_adapter'] ?? 'Wi‑Fi');
    $dns = is_array($info['wifi_dns'] ?? null) ? $info['wifi_dns'] : [];
    $list = $dns ? implode(', ', $dns) : 'automatic (DHCP)';
    $tag = !empty($info['wifi_pushed']) ? ' (PNet)' : '';
    pnet_setting_set($pdo, 'wifi_dns_last', json_encode($info, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    return $adapter . ': ' . $list . $tag;
}

function pnet_save_ip(PDO $pdo, array $data): string
{
    $label = pnet_text((string) ($data['label'] ?? ''), 80, 'Label', true);
    $address = pnet_ip((string) ($data['address'] ?? ''), true, 'Address');
    $kind = pnet_enum((string) ($data['kind'] ?? 'other'), ['lan', 'guest', 'reserved', 'blocked', 'gateway', 'dns', 'public', 'vpn', 'other'], 'Kind');
    $mac = pnet_mac((string) ($data['mac'] ?? ''));
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $data, $label, $address, $kind, $mac, $notes, $now) {
        $id = (int) ($data['id'] ?? 0);
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE ips SET label=?, address=?, kind=?, mac=?, notes=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$label, $address, $kind, $mac, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'ips', $id)) {
                throw new InvalidArgumentException('That address was not found.');
            }
            pnet_log($pdo, 'address', 'Updated ' . $label . '.');
            return 'Address updated.';
        }
        $pdo->prepare('INSERT INTO ips (label, address, kind, mac, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)')->execute([$label, $address, $kind, $mac, $notes, $now, $now]);
        pnet_log($pdo, 'address', 'Added ' . $label . '.');
        return 'Address added.';
    });
}

function pnet_save_alert(PDO $pdo, array $data): string
{
    $title = pnet_text((string) ($data['title'] ?? ''), 120, 'Title', true);
    $severity = pnet_enum((string) ($data['severity'] ?? 'medium'), ['info', 'low', 'medium', 'high', 'critical'], 'Severity');
    $source = pnet_ip((string) ($data['source_ip'] ?? ''), false, 'Source IP');
    $category = pnet_enum((string) ($data['category'] ?? 'other'), ['intrusion', 'malware', 'scan', 'policy', 'camera', 'device', 'other'], 'Category');
    $status = pnet_enum((string) ($data['status'] ?? 'open'), ['open', 'acknowledged', 'resolved'], 'Status');
    $details = pnet_text((string) ($data['details'] ?? ''), 1000, 'Details', false);
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $data, $title, $severity, $source, $category, $status, $details, $now) {
        $id = (int) ($data['id'] ?? 0);
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE alerts SET title=?, severity=?, source_ip=?, category=?, status=?, details=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$title, $severity, $source, $category, $status, $details, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'alerts', $id)) {
                throw new InvalidArgumentException('That defender item was not found.');
            }
            pnet_log($pdo, 'defender', 'Updated ' . $title . '.');
            return 'Defender item updated.';
        }
        $pdo->prepare('INSERT INTO alerts (title, severity, source_ip, category, status, details, fingerprint, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?)')->execute([$title, $severity, $source, $category, $status, $details, $now, $now]);
        pnet_log($pdo, 'defender', 'Logged ' . $title . '.');
        return 'Defender item logged.';
    });
}

function pnet_save_camera(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $ip = pnet_ip((string) ($data['ip'] ?? ''), true, 'Camera IP');
    $location = pnet_text((string) ($data['location'] ?? ''), 80, 'Location', false);
    $snapshot = pnet_url((string) ($data['snapshot_url'] ?? ''), ['http', 'https'], 'Snapshot URL');
    $stream = pnet_url((string) ($data['stream_url'] ?? ''), ['http', 'https', 'rtsp'], 'Stream URL');
    $status = pnet_enum((string) ($data['status'] ?? 'unknown'), ['online', 'offline', 'unknown'], 'Status');
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $data, $name, $ip, $location, $snapshot, $stream, $status, $notes, $now) {
        $id = (int) ($data['id'] ?? 0);
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE cameras SET name=?, ip=?, location=?, snapshot_url=?, stream_url=?, status=?, notes=?, sample=0, updated_at=? WHERE id=?');
            $st->execute([$name, $ip, $location, $snapshot, $stream, $status, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'cameras', $id)) {
                throw new InvalidArgumentException('That camera was not found.');
            }
            pnet_log($pdo, 'camera', 'Updated ' . $name . '.');
            return 'Camera updated.';
        }
        $pdo->prepare('INSERT INTO cameras (name, ip, location, snapshot_url, stream_url, status, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')->execute([$name, $ip, $location, $snapshot, $stream, $status, $notes, $now, $now]);
        pnet_log($pdo, 'camera', 'Added ' . $name . '.');
        return 'Camera added.';
    });
}

function pnet_exists(PDO $pdo, string $table, int $id): bool
{
    $allowed = ['devices', 'rules', 'sites', 'ips', 'alerts', 'cameras', 'port_forwards', 'dhcp_reservations', 'mac_filters', 'access_schedules'];
    if (!in_array($table, $allowed, true)) {
        return false;
    }
    $st = $pdo->prepare('SELECT 1 FROM ' . $table . ' WHERE id = ?');
    $st->execute([$id]);
    return (bool) $st->fetchColumn();
}

function pnet_delete_row(PDO $pdo, string $table, string $message, array $data): string
{
    $allowed = ['devices', 'rules', 'sites', 'ips', 'alerts', 'cameras', 'port_forwards', 'dhcp_reservations', 'mac_filters', 'access_schedules'];
    if (!in_array($table, $allowed, true)) {
        throw new InvalidArgumentException('Unknown action.');
    }
    $id = pnet_id($data);
    return pnet_tx($pdo, function () use ($pdo, $table, $message, $id) {
        $st = $pdo->prepare('DELETE FROM ' . $table . ' WHERE id = ?');
        $st->execute([$id]);
        if ($st->rowCount() < 1) {
            throw new InvalidArgumentException('That record was not found.');
        }
        pnet_log($pdo, 'edit', $message);
        return $message;
    });
}

function pnet_toggle(PDO $pdo, string $table, string $message, array $data): string
{
    if (!in_array($table, ['rules', 'sites', 'port_forwards', 'dhcp_reservations', 'mac_filters', 'access_schedules'], true)) {
        throw new InvalidArgumentException('Unknown action.');
    }
    $id = pnet_id($data);
    return pnet_tx($pdo, function () use ($pdo, $table, $message, $id) {
        $st = $pdo->prepare('SELECT enabled FROM ' . $table . ' WHERE id = ?');
        $st->execute([$id]);
        $current = $st->fetchColumn();
        if ($current === false) {
            throw new InvalidArgumentException('That record was not found.');
        }
        $next = ((int) $current) === 1 ? 0 : 1;
        $pdo->prepare('UPDATE ' . $table . ' SET enabled = ?, sample = 0, updated_at = ? WHERE id = ?')->execute([$next, pnet_now(), $id]);
        pnet_log($pdo, 'edit', $message);
        return $message;
    });
}

function pnet_set_alert_status(PDO $pdo, array $data): string
{
    $id = pnet_id($data);
    $status = pnet_enum((string) ($data['status'] ?? ''), ['open', 'acknowledged', 'resolved'], 'Status');
    return pnet_tx($pdo, function () use ($pdo, $id, $status) {
        $st = $pdo->prepare('UPDATE alerts SET status = ?, sample = 0, updated_at = ? WHERE id = ?');
        $st->execute([$status, pnet_now(), $id]);
        if ($st->rowCount() < 1 && !pnet_exists($pdo, 'alerts', $id)) {
            throw new InvalidArgumentException('That defender item was not found.');
        }
        pnet_log($pdo, 'defender', 'Marked an item ' . $status . '.');
        return 'Defender item updated.';
    });
}

function pnet_save_settings(PDO $pdo, array $data): string
{
    $home = pnet_text((string) ($data['home_name'] ?? ''), 60, 'Home name', true);
    $lan = pnet_text((string) ($data['lan_cidr'] ?? ''), 40, 'Network label', false);
    return pnet_tx($pdo, function () use ($pdo, $home, $lan) {
        pnet_setting_set($pdo, 'home_name', $home);
        pnet_setting_set($pdo, 'lan_cidr', $lan);
        pnet_log($pdo, 'settings', 'Updated home settings.');
        return 'Settings saved.';
    });
}

function pnet_router_setting_keys(): array
{
    return [
        'wifi_ssid', 'wifi_ssid_5g', 'wifi_security', 'wifi_channel', 'wifi_channel_5g', 'wifi_band',
        'wifi_hidden', 'wifi_wps', 'wifi_isolation',
        'guest_enabled', 'guest_ssid', 'guest_security', 'guest_isolation', 'guest_bandwidth',
        'lan_ip', 'lan_mask', 'dhcp_enabled', 'dhcp_start', 'dhcp_end', 'dhcp_lease',
        'wan_mode', 'wan_ip', 'wan_gateway', 'wan_dns1', 'wan_dns2',
        'dns_mode', 'dns_primary', 'dns_secondary',
        'upnp_enabled', 'remote_admin', 'qos_enabled', 'qos_mode',
        'vpn_enabled', 'vpn_type', 'vpn_server', 'vpn_notes',
        'router_admin_url', 'router_model', 'router_brand', 'router_brand_name', 'router_notes', 'router_traffic_enabled', 'mac_filter_mode',
    ];
}

function pnet_save_router_settings(PDO $pdo, array $data): string
{
    $section = pnet_enum((string) ($data['section'] ?? 'wireless'), [
        'wireless', 'guest', 'lan', 'wan', 'dns', 'qos', 'vpn', 'system', 'macmode',
    ], 'Section');
    $bools = ['wifi_hidden', 'wifi_wps', 'wifi_isolation', 'guest_enabled', 'guest_isolation', 'dhcp_enabled', 'upnp_enabled', 'remote_admin', 'qos_enabled', 'vpn_enabled', 'router_traffic_enabled'];
    $enums = [
        'wifi_security' => ['open', 'wpa2', 'wpa3', 'wpa2wpa3'],
        'wifi_channel' => ['auto', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13'],
        'wifi_channel_5g' => ['auto', '36', '40', '44', '48', '149', '153', '157', '161'],
        'wifi_band' => ['2.4', '5', 'both'],
        'guest_security' => ['open', 'wpa2', 'wpa3'],
        'wan_mode' => ['dhcp', 'static', 'pppoe'],
        'dns_mode' => ['isp', 'custom', 'cloudflare', 'google', 'quad9'],
        'qos_mode' => ['device', 'app', 'priority'],
        'vpn_type' => ['none', 'openvpn', 'wireguard', 'ipsec', 'pptp'],
        'mac_filter_mode' => ['disabled', 'allow', 'deny'],
    ];
    $map = [
        'wireless' => ['wifi_ssid', 'wifi_ssid_5g', 'wifi_security', 'wifi_channel', 'wifi_channel_5g', 'wifi_band', 'wifi_hidden', 'wifi_wps', 'wifi_isolation'],
        'guest' => ['guest_enabled', 'guest_ssid', 'guest_security', 'guest_isolation', 'guest_bandwidth'],
        'lan' => ['lan_ip', 'lan_mask', 'dhcp_enabled', 'dhcp_start', 'dhcp_end', 'dhcp_lease'],
        'wan' => ['wan_mode', 'wan_ip', 'wan_gateway', 'wan_dns1', 'wan_dns2'],
        'dns' => ['dns_mode', 'dns_primary', 'dns_secondary'],
        'qos' => ['qos_enabled', 'qos_mode'],
        'vpn' => ['vpn_enabled', 'vpn_type', 'vpn_server', 'vpn_notes'],
        'system' => ['router_admin_url', 'router_model', 'router_brand', 'router_brand_name', 'router_notes', 'router_traffic_enabled', 'upnp_enabled', 'remote_admin'],
        'macmode' => ['mac_filter_mode'],
    ];
    $keys = $map[$section];
    return pnet_tx($pdo, function () use ($pdo, $data, $keys, $bools, $enums, $section) {
        foreach ($keys as $key) {
            $raw = (string) ($data[$key] ?? '');
            if (in_array($key, $bools, true)) {
                $value = !empty($data[$key]) && (string) $data[$key] !== '0' ? '1' : '0';
            } elseif (isset($enums[$key])) {
                $value = pnet_enum($raw !== '' ? $raw : $enums[$key][0], $enums[$key], $key);
            } elseif ($key === 'guest_bandwidth' || $key === 'dhcp_lease') {
                $n = (int) $raw;
                if ($n < 0 || $n > 100000) {
                    throw new InvalidArgumentException('Value out of range for ' . $key . '.');
                }
                $value = (string) $n;
            } elseif (in_array($key, ['lan_ip', 'dhcp_start', 'dhcp_end', 'wan_ip', 'wan_gateway', 'wan_dns1', 'wan_dns2', 'dns_primary', 'dns_secondary'], true)) {
                $value = pnet_ip($raw, false, $key);
            } elseif ($key === 'router_admin_url') {
                $value = $raw === '' ? '' : pnet_url($raw, ['http', 'https'], 'Router admin URL');
            } elseif ($key === 'vpn_notes' || $key === 'router_notes') {
                $value = pnet_text($raw, 500, $key, false);
            } else {
                $value = pnet_text($raw, 120, $key, false);
            }
            pnet_setting_set($pdo, $key, $value);
        }
        pnet_log($pdo, 'router', 'Updated router ' . $section . ' settings.');
        return 'Router ' . $section . ' settings saved.';
    });
}

function pnet_save_port_forward(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $protocol = pnet_enum((string) ($data['protocol'] ?? 'tcp'), ['tcp', 'udp', 'both'], 'Protocol');
    $external = pnet_port((string) ($data['external_port'] ?? ''));
    if ($external === '') {
        throw new InvalidArgumentException('External port is required.');
    }
    $internalIp = pnet_ip((string) ($data['internal_ip'] ?? ''), true, 'Internal IP');
    $internal = pnet_port((string) ($data['internal_port'] ?? ''));
    if ($internal === '') {
        $internal = $external;
    }
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    $id = isset($data['id']) ? pnet_id($data) : 0;
    return pnet_tx($pdo, function () use ($pdo, $id, $name, $protocol, $external, $internalIp, $internal, $enabled, $notes, $now) {
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE port_forwards SET name = ?, protocol = ?, external_port = ?, internal_ip = ?, internal_port = ?, enabled = ?, notes = ?, updated_at = ? WHERE id = ?');
            $st->execute([$name, $protocol, $external, $internalIp, $internal, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'port_forwards', $id)) {
                throw new InvalidArgumentException('That port forward was not found.');
            }
            pnet_log($pdo, 'router', 'Updated port forward ' . $name . '.');
            return 'Port forward updated.';
        }
        $pdo->prepare('INSERT INTO port_forwards (name, protocol, external_port, internal_ip, internal_port, enabled, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
            ->execute([$name, $protocol, $external, $internalIp, $internal, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'router', 'Added port forward ' . $name . '.');
        return 'Port forward added.';
    });
}

function pnet_save_dhcp_reservation(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $mac = pnet_mac((string) ($data['mac'] ?? ''));
    if ($mac === '') {
        throw new InvalidArgumentException('MAC address is required.');
    }
    $ip = pnet_ip((string) ($data['ip'] ?? ''), true);
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    $id = isset($data['id']) ? pnet_id($data) : 0;
    return pnet_tx($pdo, function () use ($pdo, $id, $name, $mac, $ip, $enabled, $notes, $now) {
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE dhcp_reservations SET name = ?, mac = ?, ip = ?, enabled = ?, notes = ?, updated_at = ? WHERE id = ?');
            $st->execute([$name, $mac, $ip, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'dhcp_reservations', $id)) {
                throw new InvalidArgumentException('That reservation was not found.');
            }
            pnet_log($pdo, 'router', 'Updated DHCP reservation ' . $name . '.');
            return 'DHCP reservation updated.';
        }
        $pdo->prepare('INSERT INTO dhcp_reservations (name, mac, ip, enabled, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            ->execute([$name, $mac, $ip, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'router', 'Added DHCP reservation ' . $name . '.');
        return 'DHCP reservation added.';
    });
}

function pnet_save_mac_filter(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $mac = pnet_mac((string) ($data['mac'] ?? ''));
    if ($mac === '') {
        throw new InvalidArgumentException('MAC address is required.');
    }
    $mode = pnet_enum((string) ($data['mode'] ?? 'allow'), ['allow', 'deny'], 'Mode');
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    $id = isset($data['id']) ? pnet_id($data) : 0;
    return pnet_tx($pdo, function () use ($pdo, $id, $name, $mac, $mode, $enabled, $notes, $now) {
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE mac_filters SET name = ?, mac = ?, mode = ?, enabled = ?, notes = ?, updated_at = ? WHERE id = ?');
            $st->execute([$name, $mac, $mode, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'mac_filters', $id)) {
                throw new InvalidArgumentException('That MAC filter was not found.');
            }
            pnet_log($pdo, 'router', 'Updated MAC filter ' . $name . '.');
            return 'MAC filter updated.';
        }
        $pdo->prepare('INSERT INTO mac_filters (name, mac, mode, enabled, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            ->execute([$name, $mac, $mode, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'router', 'Added MAC filter ' . $name . '.');
        return 'MAC filter added.';
    });
}

function pnet_save_access_schedule(PDO $pdo, array $data): string
{
    $name = pnet_text((string) ($data['name'] ?? ''), 80, 'Name', true);
    $target = pnet_text((string) ($data['target'] ?? ''), 120, 'Target', true);
    $days = pnet_text((string) ($data['days'] ?? 'Mon-Fri'), 40, 'Days', true);
    $start = pnet_text((string) ($data['start_time'] ?? '22:00'), 8, 'Start time', true);
    $end = pnet_text((string) ($data['end_time'] ?? '07:00'), 8, 'End time', true);
    if (!preg_match('/^\d{1,2}:\d{2}$/', $start) || !preg_match('/^\d{1,2}:\d{2}$/', $end)) {
        throw new InvalidArgumentException('Times must look like 22:00.');
    }
    $action = pnet_enum((string) ($data['action'] ?? 'block'), ['block', 'allow', 'limit'], 'Action');
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $notes = pnet_text((string) ($data['notes'] ?? ''), 500, 'Notes', false);
    $now = pnet_now();
    $id = isset($data['id']) ? pnet_id($data) : 0;
    return pnet_tx($pdo, function () use ($pdo, $id, $name, $target, $days, $start, $end, $action, $enabled, $notes, $now) {
        if ($id > 0) {
            $st = $pdo->prepare('UPDATE access_schedules SET name = ?, target = ?, days = ?, start_time = ?, end_time = ?, action = ?, enabled = ?, notes = ?, updated_at = ? WHERE id = ?');
            $st->execute([$name, $target, $days, $start, $end, $action, $enabled, $notes, $now, $id]);
            if ($st->rowCount() < 1 && !pnet_exists($pdo, 'access_schedules', $id)) {
                throw new InvalidArgumentException('That schedule was not found.');
            }
            pnet_log($pdo, 'router', 'Updated access schedule ' . $name . '.');
            return 'Access schedule updated.';
        }
        $pdo->prepare('INSERT INTO access_schedules (name, target, days, start_time, end_time, action, enabled, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
            ->execute([$name, $target, $days, $start, $end, $action, $enabled, $notes, $now, $now]);
        pnet_log($pdo, 'router', 'Added access schedule ' . $name . '.');
        return 'Access schedule added.';
    });
}

function pnet_change_password(PDO $pdo, array $data): string
{
    $user = pnet_user($pdo);
    if (!$user) {
        throw new InvalidArgumentException('Sign in required.');
    }
    $current = (string) ($data['current_password'] ?? '');
    $password = (string) ($data['new_password'] ?? '');
    $confirm = (string) ($data['confirm_password'] ?? '');
    if (!password_verify($current, (string) $user['password_hash'])) {
        throw new InvalidArgumentException('Current password is wrong.');
    }
    pnet_password_rules($password, $confirm, (string) $user['username']);
    return pnet_tx($pdo, function () use ($pdo, $user, $password) {
        $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([
            password_hash($password, PASSWORD_DEFAULT),
            (int) $user['id'],
        ]);
        pnet_log($pdo, 'account', 'Changed the admin password.');
        return 'Password changed.';
    });
}

function pnet_check_host(PDO $pdo, array $data): string
{
    $kind = (string) ($data['kind'] ?? '');
    if (!in_array($kind, ['device', 'camera'], true)) {
        throw new InvalidArgumentException('Unknown check.');
    }
    $id = pnet_id($data);
    $table = $kind === 'device' ? 'devices' : 'cameras';
    $st = $pdo->prepare('SELECT id, name, ip FROM ' . $table . ' WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) {
        throw new InvalidArgumentException('That record was not found.');
    }
    $ip = (string) $row['ip'];
    if (!pnet_is_lan_ipv4($ip)) {
        throw new RuntimeException('PNet only pings private home addresses, such as 192.168.1.20.');
    }
    $pingResult = pnet_ping_with_latency($ip);
    $online = $pingResult['online'];
    $pingMs = $pingResult['ms'];
    $status = $online ? 'online' : 'offline';
    $now = pnet_now();
    return pnet_tx($pdo, function () use ($pdo, $table, $id, $status, $now, $row, $online, $pingMs) {
        if ($table === 'devices') {
            $pdo->prepare('UPDATE devices SET status = ?, last_seen = ?, ping_ms = ?, updated_at = ? WHERE id = ?')->execute([$status, $now, $pingMs, $now, $id]);
        } else {
            $pdo->prepare('UPDATE cameras SET status = ?, last_seen = ?, updated_at = ? WHERE id = ?')->execute([$status, $now, $now, $id]);
        }
        $detail = $row['name'] . ($online ? ' replied (' . $pingMs . 'ms).' : ' did not reply.');
        pnet_log($pdo, 'check', $detail);
        return $detail;
    });
}

function pnet_wake_device(PDO $pdo, array $data): string
{
    if (!pnet_can_exec()) {
        throw new RuntimeException('PHP exec is disabled, so Wake-on-LAN cannot run.');
    }
    $id = pnet_id($data);
    $st = $pdo->prepare('SELECT id, name, mac, ip FROM devices WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) {
        throw new InvalidArgumentException('That device was not found.');
    }
    $mac = (string) $row['mac'];
    if ($mac === '' || !preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/', $mac)) {
        throw new InvalidArgumentException('This device has no valid MAC address for Wake-on-LAN.');
    }
    $ip = (string) $row['ip'];
    $broadcast = '255.255.255.255';
    if ($ip !== '' && pnet_is_lan_ipv4($ip)) {
        $parts = explode('.', $ip);
        $broadcast = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.255';
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'powershell -Command "Invoke-Expression (\' wol.exe ' . escapeshellarg($mac) . ' ' . escapeshellarg($broadcast) . '\')" 2>&1';
    } else {
        $cmd = 'wakeonlan -i ' . escapeshellarg($broadcast) . ' ' . escapeshellarg($mac) . ' 2>&1';
    }
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    $now = pnet_now();
    pnet_log($pdo, 'wol', 'Sent Wake-on-LAN packet to ' . (string) $row['name'] . ' (' . $mac . ').');
    return 'Wake-on-LAN packet sent to ' . (string) $row['name'] . '.';
}

function pnet_ping(string $ip): bool
{
    if (!pnet_is_lan_ipv4($ip) || !function_exists('exec')) {
        throw new RuntimeException('Ping is not available from PHP on this PC.');
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (in_array('exec', $disabled, true)) {
        throw new RuntimeException('PHP exec is disabled, so the check cannot run. Enable exec in php.ini if you want live checks.');
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'ping -n 1 -w 800 ' . escapeshellarg($ip);
    } else {
        $cmd = 'ping -c 1 -W 1 ' . escapeshellarg($ip);
    }
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    $text = implode("\n", $output);
    if (stripos($text, 'not recognized') !== false || stripos($text, 'not found') !== false) {
        throw new RuntimeException('Ping is not available on this PC.');
    }
    return $code === 0;
}

function pnet_ping_with_latency(string $ip): array
{
    if (!pnet_is_lan_ipv4($ip) || !function_exists('exec')) {
        throw new RuntimeException('Ping is not available from PHP on this PC.');
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (in_array('exec', $disabled, true)) {
        throw new RuntimeException('PHP exec is disabled, so the check cannot run. Enable exec in php.ini if you want live checks.');
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'ping -n 1 ' . escapeshellarg($ip);
    } else {
        $cmd = 'ping -c 1 ' . escapeshellarg($ip);
    }
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    $text = implode("\n", $output);
    if (stripos($text, 'not recognized') !== false || stripos($text, 'not found') !== false) {
        throw new RuntimeException('Ping is not available on this PC.');
    }
    $online = $code === 0;
    $ms = null;
    if ($online) {
        if (PHP_OS_FAMILY === 'Windows') {
            if (preg_match('/time[=<](\d+)ms/i', $text, $match)) {
                $ms = (int) $match[1];
            }
        } else {
            if (preg_match('/time[=<](\d+\.?\d*)\s*ms/i', $text, $match)) {
                $ms = (int) $match[1];
            }
        }
    }
    return ['online' => $online, 'ms' => $ms];
}

function pnet_can_exec(): bool
{
    if (!function_exists('exec')) {
        return false;
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    return !in_array('exec', $disabled, true);
}

function pnet_runtime_cache_get(string $key, int $ttlSec = 8): ?array
{
    $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.cache_' . preg_replace('/[^a-z0-9_]+/i', '_', $key) . '.json';
    if (!is_file($path)) {
        return null;
    }
    $mtime = @filemtime($path) ?: 0;
    if ($mtime < 1 || (time() - $mtime) > $ttlSec) {
        return null;
    }
    $raw = @file_get_contents($path);
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($decoded) ? $decoded : null;
}

function pnet_runtime_cache_set(string $key, array $value): void
{
    $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.cache_' . preg_replace('/[^a-z0-9_]+/i', '_', $key) . '.json';
    @file_put_contents($path, json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function pnet_wifi_info(): array
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $fromDisk = pnet_runtime_cache_get('wifi_info', 10);
    if ($fromDisk !== null) {
        return $cached = $fromDisk;
    }
    $empty = [
        'available' => false,
        'message' => 'Wi-Fi details are not available from this server.',
        'name' => '',
        'description' => '',
        'state' => '',
        'ssid' => '',
        'bssid' => '',
        'network_type' => '',
        'radio_type' => '',
        'authentication' => '',
        'cipher' => '',
        'connection_mode' => '',
        'channel' => '',
        'signal' => '',
        'receive_rate' => '',
        'transmit_rate' => '',
        'profile' => '',
    ];
    if (PHP_OS_FAMILY !== 'Windows') {
        $empty['message'] = 'Wi-Fi details use Windows netsh on this install.';
        return $cached = $empty;
    }
    if (!pnet_can_exec()) {
        $empty['message'] = 'PHP exec is disabled, so Wi-Fi details cannot be read.';
        return $cached = $empty;
    }
    $output = [];
    $code = 1;
    exec('netsh wlan show interfaces', $output, $code);
    $raw = implode("\n", $output);
    if (stripos($raw, 'requires elevation') !== false || stripos($raw, 'error 5') !== false) {
        $empty['message'] = 'Windows requires administrator permission to read Wi-Fi details from this PHP process.';
        return $cached = $empty;
    }
    if (!$output || $code !== 0) {
        $empty['message'] = 'Windows did not return Wi-Fi interface details.';
        return $cached = $empty;
    }
    $map = [
        'name' => 'name',
        'description' => 'description',
        'state' => 'state',
        'ssid' => 'ssid',
        'bssid' => 'bssid',
        'network type' => 'network_type',
        'radio type' => 'radio_type',
        'authentication' => 'authentication',
        'cipher' => 'cipher',
        'connection mode' => 'connection_mode',
        'channel' => 'channel',
        'receive rate (mbps)' => 'receive_rate',
        'transmit rate (mbps)' => 'transmit_rate',
        'signal' => 'signal',
        'profile' => 'profile',
    ];
    $info = $empty;
    foreach ($output as $line) {
        if (strpos($line, ':') === false) {
            continue;
        }
        [$key, $value] = array_map('trim', explode(':', $line, 2));
        $key = strtolower($key);
        if ($key === 'ssid' && preg_match('/^bssid/i', trim($line))) {
            continue;
        }
        if (isset($map[$key])) {
            $info[$map[$key]] = pnet_text($value, 160, 'Wi-Fi detail', false);
        }
    }
    $connected = strtolower($info['state']) === 'connected' || $info['ssid'] !== '';
    $info['available'] = $connected;
    $info['message'] = $connected ? 'Connected' : 'This PC is not connected to Wi-Fi.';
    pnet_runtime_cache_set('wifi_info', $info);
    return $cached = $info;
}

function pnet_oui_vendor(string $mac): string
{
    $hex = strtoupper(str_replace([':', '-'], '', $mac));
    if (strlen($hex) < 6) {
        return '';
    }
    $prefix = substr($hex, 0, 6);
    static $map = [
        '000C29' => 'VMware', '001A11' => 'Google', '001B63' => 'Apple', '001C42' => 'Parallels',
        '001D7E' => 'Cisco-Linksys', '001E58' => 'D-Link', '001F3B' => 'Intel', '001F5B' => 'Apple',
        '0021E9' => 'TP-Link', '0022FB' => 'Intel', '0024D7' => 'Intel', '0025A0' => 'Nintendo',
        '0026B0' => 'Apple', '002711' => 'ASUSTek', '0050F2' => 'Microsoft', '00A0C9' => 'Intel',
        '00B0D0' => 'Dell', '00D0B7' => 'Intel', '00E04C' => 'Realtek', '040E3C' => 'HP',
        '0C4DE9' => 'Apple', '14ABB7' => 'Google', '18B430' => 'Nest', '1C1AC0' => 'Apple',
        '204747' => 'Dell', '24F5AA' => 'Samsung', '28C63F' => 'Intel', '2C54CF' => 'LG',
        '34CDBE' => 'Huawei', '3C5A37' => 'Samsung', '40A6D9' => 'Apple', '44D9E7' => 'Ubiquiti',
        '48A195' => 'Apple', '4C3275' => 'Apple', '50E4E0' => 'Dell', '54AF97' => 'TP-Link',
        '5C969D' => 'Apple', '60A4D0' => 'Apple', '64BC0C' => 'ASUSTek', '68A86D' => 'Apple',
        '6C4008' => 'Apple', '74D02B' => 'ASUSTek', '78A3E4' => 'Apple', '7C2EBD' => 'Google',
        '80E650' => 'Apple', '84A134' => 'Apple', '88E9FE' => 'Apple', '8C8590' => 'Apple',
        '90B21F' => 'Apple', '94E979' => 'Liteon', '98D6BB' => 'Apple', '9C207B' => 'Apple',
        'A4C361' => 'Apple', 'A8BBCF' => 'Apple', 'ACBC32' => 'Apple', 'B065BD' => 'Apple',
        'B0BE76' => 'Apple', 'B8E856' => 'Apple', 'C8D083' => 'Apple', 'CC08E0' => 'Apple',
        'D0E140' => 'Apple', 'D4A33D' => 'Apple', 'D8A25E' => 'Apple', 'DC56E7' => 'Apple',
        'E0CB4E' => 'ASUSTek', 'E4CE8F' => 'Apple', 'E8B2AC' => 'Apple', 'EC3586' => 'Apple',
        'F0DCE2' => 'Apple', 'F4F5D8' => 'Google', 'F8FFC2' => 'Apple', 'FC253F' => 'Apple',
        '00259C' => 'Cisco-Linksys', 'C0C1C0' => 'Cisco-Linksys', '001E13' => 'Cisco',
        '0015C7' => 'Cisco', '001120' => 'Cisco', 'B827EB' => 'Raspberry Pi', 'DCA632' => 'Raspberry Pi',
        'E45F01' => 'Raspberry Pi', '28CDC1' => 'Raspberry Pi', '000D4B' => 'Roku', 'B0A737' => 'Roku',
        'D0E782' => 'AzureWave', 'B4B676' => 'Intel', 'FCFBFB' => 'Cisco', '00155D' => 'Microsoft',
        '0050B6' => 'Microsoft', '7C1E52' => 'Microsoft', '00DB70' => 'Apple', '525400' => 'QEMU/KVM',
        '080027' => 'VirtualBox', 'DCA632' => 'Raspberry Pi',
    ];
    return $map[$prefix] ?? '';
}

function pnet_guess_device_type(string $vendor, string $hostname = ''): string
{
    $hay = strtolower($vendor . ' ' . $hostname);
    if (preg_match('/\b(roku|nintendo|playstation|xbox)\b/', $hay)) {
        if (str_contains($hay, 'roku')) {
            return 'tv';
        }
        return 'console';
    }
    if (preg_match('/raspberry|nest\b|ring\b/', $hay)) {
        if (str_contains($hay, 'raspberry')) {
            return 'iot';
        }
        if (str_contains($hay, 'nest') || str_contains($hay, 'ring')) {
            return str_contains($hay, 'ring') ? 'camera' : 'speaker';
        }
    }
    if (preg_match('/roku|apple.?tv|chromecast|fire.?tv|smart.?tv|bravia|webos|mi tv|shield tv/', $hay)) {
        return 'tv';
    }
    if (preg_match('/iphone|pixel|galaxy s|galaxy a|galaxy z|android-|oneplus|redmi|poco|mobile|phone/', $hay)) {
        return 'phone';
    }
    if (preg_match('/ipad|tablet|galaxy tab|surface go|kindle fire hd/', $hay)) {
        return 'tablet';
    }
    if (preg_match('/playstation|\bps[345]\b|xbox|nintendo|switch|steam deck/', $hay)) {
        return 'console';
    }
    if (preg_match('/printer|epson|brother|canon|pixma|laserjet|deskjet|mfc-/', $hay)) {
        return 'printer';
    }
    if (preg_match('/nest|echo|homepod|sonos|speaker|google home|alexa|home mini/', $hay)) {
        return 'speaker';
    }
    if (preg_match('/camera|ring-|arlo|wyze|hikvision|dahua|amcrest|reolink|doorbell|cam-/', $hay)) {
        return 'camera';
    }
    if (preg_match('/router|gateway|cisco|ubiquiti|asus|tp-?link|netgear|linksys|fritz!?box|eero|orbi/', $hay)) {
        return 'router';
    }
    if (preg_match('/raspberry|iot|esp|shelly|tuya|hue|smart plug|thermostat|bulb|sensor/', $hay)) {
        return 'iot';
    }
    if (preg_match('/macbook|imac|desktop|laptop|pc-|win-|thinkpad|latitude|xps|surface laptop|chromebook|intel|dell|lenovo|vmware|virtualbox/', $hay)) {
        return 'computer';
    }
    return 'other';
}

function pnet_device_auto_name(string $brand, string $type, string $ip): string
{
    $words = [
        'phone' => 'phone',
        'tablet' => 'tablet',
        'tv' => 'TV',
        'console' => 'console',
        'computer' => 'PC',
        'printer' => 'printer',
        'camera' => 'camera',
        'speaker' => 'speaker',
        'iot' => 'smart device',
        'router' => 'router',
    ];
    $word = $words[$type] ?? 'device';
    $brand = trim($brand);
    if ($brand === '' || strcasecmp($brand, 'Device') === 0) {
        return $word === 'device' ? ('Seen ' . $ip) : ucfirst($word);
    }
    return $brand . ' ' . $word;
}

function pnet_router_brand_catalog(): array
{
    return [
        'tp-link' => ['name' => 'TP-Link', 'admin' => 'http://tplinkwifi.net'],
        'netgear' => ['name' => 'NETGEAR', 'admin' => 'http://routerlogin.net'],
        'asus' => ['name' => 'ASUS', 'admin' => 'http://router.asus.com'],
        'linksys' => ['name' => 'Linksys', 'admin' => 'http://myrouter.local'],
        'ubiquiti' => ['name' => 'Ubiquiti', 'admin' => 'https://unifi.ui.com'],
        'd-link' => ['name' => 'D-Link', 'admin' => 'http://dlinkrouter.local'],
        'cisco' => ['name' => 'Cisco', 'admin' => ''],
        'google' => ['name' => 'Google Nest', 'admin' => 'http://setup.google/home'],
        'eero' => ['name' => 'eero', 'admin' => 'http://eero.com'],
        'arris' => ['name' => 'Arris', 'admin' => 'http://192.168.0.1'],
        'huawei' => ['name' => 'Huawei', 'admin' => 'http://192.168.1.1'],
        'zte' => ['name' => 'ZTE', 'admin' => 'http://192.168.1.1'],
        'mikrotik' => ['name' => 'MikroTik', 'admin' => ''],
        'fritzbox' => ['name' => 'FRITZ!Box', 'admin' => 'http://fritz.box'],
        'xfinity' => ['name' => 'Xfinity', 'admin' => 'http://10.0.0.1'],
        'verizon' => ['name' => 'Verizon', 'admin' => 'http://myfiosgateway.com'],
        'generic' => ['name' => 'Router', 'admin' => ''],
    ];
}

function pnet_match_router_brand(string $text): string
{
    $hay = strtolower(trim($text));
    if ($hay === '') {
        return 'generic';
    }
    $patterns = [
        'tp-link' => '/tp-?link|tplink|mercury|archer|deco|re\.?650|ax\d{2,4}/',
        'netgear' => '/netgear|nighthawk|orbi|r\d{4,5}|xr\d{3,4}/',
        'asus' => '/asus|asustek|rt-?ac|rt-?ax|rog rapture|zenwifi/',
        'linksys' => '/linksys|velop|smart wi-?fi/',
        'ubiquiti' => '/ubiquiti|unifi|edgerouter|amplifi|uap-/',
        'd-link' => '/d-?link|dir-?\d+/',
        'cisco' => '/cisco/',
        'google' => '/google|nest wifi|onhub/',
        'eero' => '/eero/',
        'arris' => '/arris|surfboard|sb\d{4}/',
        'huawei' => '/huawei|honor router/',
        'zte' => '/\bzte\b|zxhn|f627|f660|f664|f680|f460|h288|h388|e2631|sr7410|frm_logintoken/',
        'mikrotik' => '/mikrotik|routeros/',
        'fritzbox' => '/fritz!?box|avm/',
        'xfinity' => '/xfinity|comcast|xb\d-|cg\d+/',
        'verizon' => '/verizon|fios|actiontec|quantum gateway/',
    ];
    foreach ($patterns as $slug => $regex) {
        if (preg_match($regex, $hay)) {
            return $slug;
        }
    }
    return 'generic';
}

function pnet_router_oui_brand(string $mac): string
{
    $hex = strtoupper(str_replace([':', '-'], '', $mac));
    if (strlen($hex) < 6) {
        return 'generic';
    }
    $prefix = substr($hex, 0, 6);
    static $map = [
        '0021E9' => 'tp-link', '54AF97' => 'tp-link', '74DA88' => 'tp-link', '5C628B' => 'tp-link',
        '98DAC4' => 'tp-link', 'A842A1' => 'tp-link', 'C006C3' => 'tp-link', 'F4F26D' => 'tp-link',
        '001D7E' => 'linksys', '00259C' => 'linksys', 'C0C1C0' => 'linksys', '203CE6' => 'linksys',
        '002711' => 'asus', '64BC0C' => 'asus', '74D02B' => 'asus', 'E0CB4E' => 'asus', '2C56DC' => 'asus',
        '44D9E7' => 'ubiquiti', '0418D6' => 'ubiquiti', '788A20' => 'ubiquiti', 'B4FBE4' => 'ubiquiti',
        '001E58' => 'd-link', '1CBDB9' => 'd-link', 'C8BE19' => 'd-link', '9094E4' => 'd-link',
        '001E13' => 'cisco', '001120' => 'cisco', '0015C7' => 'cisco', 'FCFBFB' => 'cisco',
        '20E52A' => 'netgear', 'C03F0E' => 'netgear', 'A021B7' => 'netgear', '6CCDD6' => 'netgear',
        '001A11' => 'google', '14ABB7' => 'google', 'F4F5D8' => 'google', '7C2EBD' => 'google',
        '34CDBE' => 'huawei', '002EC7' => 'huawei', '4C54E9' => 'huawei',
        '001E73' => 'zte', '001E8F' => 'zte', '0026ED' => 'zte', '083FBC' => 'zte',
        '4C09B4' => 'zte', '544B8C' => 'zte', '647002' => 'zte', 'F4B72A' => 'zte',
        '001E58' => 'd-link', '001CF0' => 'arris', '001599' => 'arris', '001CC1' => 'arris',
        'D4D7A5' => 'eero', '6C5AB0' => 'eero',
        '4C5E0C' => 'mikrotik', 'E48D8C' => 'mikrotik',
        'A0A3E2' => 'fritzbox', '24E124' => 'fritzbox',
    ];
    return $map[$prefix] ?? 'generic';
}

function pnet_probe_router_http(string $gateway): array
{
    if (!pnet_is_lan_ipv4($gateway)) {
        return [];
    }
    $result = ['brand' => 'generic', 'model' => '', 'title' => ''];
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 0.8,
            'follow_location' => 0,
            'ignore_errors' => true,
            'header' => "User-Agent: PNet/1.0\r\nAccept: text/html\r\nConnection: close\r\n",
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    // One quick request only — extra paths made Find devices time out under Apache.
    $body = @file_get_contents('http://' . $gateway . '/', false, $ctx);
    $headers = $http_response_header ?? [];
    $headerText = is_array($headers) ? implode("\n", $headers) : '';
    $text = $headerText . "\n" . (is_string($body) ? substr($body, 0, 4096) : '');
    if ($text === "\n") {
        return $result;
    }
    $brand = pnet_match_router_brand($text);
    if ($brand !== 'generic') {
        $result['brand'] = $brand;
    }
    if (preg_match('/<title[^>]*>([^<]+)<\/title>/i', $text, $m)) {
        $title = trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if ($title !== '') {
            $result['title'] = $title;
            if ($brand === 'generic') {
                $fromTitle = pnet_match_router_brand($title);
                if ($fromTitle !== 'generic') {
                    $result['brand'] = $fromTitle;
                }
            }
            if ($result['model'] === '' && preg_match('/\b(F\d{3,4}[A-Z0-9]*|H\d{3,4}[A-Z0-9]*|E\d{4}|SR\d{4})\b/i', $title, $mm)) {
                $result['model'] = strtoupper($mm[1]);
            }
        }
    }
    if ($result['model'] === '' && preg_match('/(?:model|product)[^:>]{0,20}[:>]\s*([A-Za-z0-9][A-Za-z0-9\-_. ]{2,40})/i', $text, $m)) {
        $result['model'] = trim($m[1]);
    }
    if ($result['brand'] === 'generic' && stripos($text, 'ZTE Corporation') !== false) {
        $result['brand'] = 'zte';
    }
    return $result;
}

function pnet_router_secret_key(): string
{
    $dir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data';
    $path = $dir . DIRECTORY_SEPARATOR . '.router_key';
    if (!is_file($path)) {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents($path, random_bytes(32));
    }
    $key = file_get_contents($path);
    return is_string($key) && strlen($key) >= 32 ? substr($key, 0, 32) : hash('sha256', 'pnet-router-fallback', true);
}

function pnet_router_encrypt(string $plain): string
{
    if ($plain === '') {
        return '';
    }
    if (function_exists('sodium_crypto_secretbox')) {
        $key = pnet_router_secret_key();
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plain, $nonce, $key);
        return 's1:' . base64_encode($nonce . $cipher);
    }
    return 'b64:' . base64_encode($plain);
}

function pnet_router_decrypt(string $enc): string
{
    if ($enc === '') {
        return '';
    }
    if (str_starts_with($enc, 's1:') && function_exists('sodium_crypto_secretbox_open')) {
        $raw = base64_decode(substr($enc, 3), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            return '';
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, pnet_router_secret_key());
        return $plain === false ? '' : $plain;
    }
    if (str_starts_with($enc, 'b64:')) {
        $raw = base64_decode(substr($enc, 4), true);
        return is_string($raw) ? $raw : '';
    }
    return '';
}

function pnet_router_admin_url(string $url, string $gateway = ''): string
{
    $url = trim($url);
    if ($url === '') {
        if ($gateway !== '' && pnet_is_lan_ipv4($gateway)) {
            return 'http://' . $gateway;
        }
        throw new InvalidArgumentException('Router address is required.');
    }
    $url = pnet_url($url, ['http', 'https'], 'Router address');
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || !pnet_is_lan_ipv4($host)) {
        throw new InvalidArgumentException('Router address must be a private home IP (like 192.168.0.1).');
    }
    return $url;
}

function pnet_router_probe_url(string $url): array
{
    $empty = ['reachable' => false, 'title' => '', 'status_code' => 0, 'brand' => 'generic'];
    if ($url === '') {
        return $empty;
    }
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || !pnet_is_lan_ipv4($host)) {
        return $empty;
    }
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 2.5,
            'follow_location' => 1,
            'max_redirects' => 3,
            'ignore_errors' => true,
            'header' => "User-Agent: PNet/1.0\r\nAccept: text/html\r\n",
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    $headers = $http_response_header ?? [];
    $status = 0;
    if (is_array($headers) && isset($headers[0]) && preg_match('/\s(\d{3})\s/', $headers[0], $m)) {
        $status = (int) $m[1];
    }
    $reachable = $status >= 200 && $status < 500;
    $text = (is_string($body) ? substr($body, 0, 8192) : '');
    $probe = pnet_probe_router_http($host);
    $title = (string) ($probe['title'] ?? '');
    if ($title === '' && preg_match('/<title[^>]*>([^<]+)<\/title>/i', $text, $m)) {
        $title = trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    }
    return [
        'reachable' => $reachable,
        'title' => $title,
        'status_code' => $status,
        'brand' => (string) ($probe['brand'] ?? 'generic'),
    ];
}

function pnet_router_access(PDO $pdo): array
{
    $net = pnet_detect_lan_network();
    $gateway = trim((string) ($net['gateway'] ?? ''));
    if ($gateway === '' && ($net['prefix'] ?? '') !== '') {
        $gateway = (string) $net['prefix'] . '.1';
    }
    $adminUrl = trim(pnet_setting($pdo, 'router_admin_url', ''));
    if ($adminUrl === '' && $gateway !== '') {
        $adminUrl = 'http://' . $gateway;
    }
    $user = pnet_setting($pdo, 'router_admin_user', '');
    $enc = pnet_setting($pdo, 'router_admin_pass_enc', '');
    $cachedReach = pnet_setting($pdo, 'router_reachable', '');
    $cachedTitle = pnet_setting($pdo, 'router_page_title', '');
    return [
        'admin_url' => $adminUrl,
        'gateway' => $gateway,
        'reachable' => $cachedReach === '1',
        'title' => $cachedTitle,
        'has_credentials' => $user !== '' && $enc !== '',
        'login_ok' => pnet_setting($pdo, 'router_login_ok', '') === '1',
        'username' => $user,
        'last_probe' => pnet_setting($pdo, 'router_last_probe', ''),
        'upnp_available' => PHP_OS_FAMILY === 'Windows' && pnet_can_exec(),
    ];
}

function pnet_router_connect(PDO $pdo, array $data): string
{
    $net = pnet_detect_lan_network();
    $gateway = trim((string) ($net['gateway'] ?? ''));
    $url = pnet_router_admin_url((string) ($data['router_admin_url'] ?? ''), $gateway);
    $user = pnet_text((string) ($data['router_admin_user'] ?? ''), 64, 'Username', false);
    $password = (string) ($data['router_admin_password'] ?? '');
    if ($password === '') {
        try {
            $password = (string) (pnet_router_get_login($pdo)['password'] ?? '');
        } catch (Throwable $e) {
            $password = '';
        }
    }
    if ($user === '') {
        $user = trim(pnet_setting($pdo, 'router_admin_user', ''));
    }
    $probe = pnet_router_probe_url($url);
    if (!$probe['reachable']) {
        throw new RuntimeException('Could not reach the router at ' . $url . '. Stay on home Wi‑Fi, then try again.');
    }
    if ($user === '' || $password === '') {
        throw new InvalidArgumentException('Enter the router admin username and password (not the Wi‑Fi password).');
    }

    pnet_setting_set($pdo, 'router_admin_url', $url);
    pnet_setting_set($pdo, 'router_admin_user', $user);
    pnet_setting_set($pdo, 'router_admin_pass_enc', pnet_router_encrypt($password));
    pnet_setting_set($pdo, 'router_reachable', '1');
    pnet_setting_set($pdo, 'router_page_title', (string) ($probe['title'] ?? ''));
    pnet_setting_set($pdo, 'router_last_probe', pnet_now());
    if (($probe['brand'] ?? 'generic') !== 'generic') {
        pnet_setting_set($pdo, 'router_brand', (string) $probe['brand']);
    }
    if (($probe['title'] ?? '') !== '' && trim(pnet_setting($pdo, 'router_model', '')) === '') {
        pnet_setting_set($pdo, 'router_model', (string) $probe['title']);
    }
    pnet_sync_router_brand($pdo, true);

    if (!function_exists('pnet_tplink_login')) {
        require_once __DIR__ . '/traffic_sources.php';
    }

    $brand = strtolower((string) pnet_setting($pdo, 'router_brand', $probe['brand'] ?? ''));
    $loginOk = false;
    $loginNote = '';
    $syncNote = '';

    if ($brand === 'tp-link' || $brand === 'tplink' || stripos((string) ($probe['title'] ?? ''), 'tp-link') !== false) {
        @unlink(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.tplink_session.json');
        $tp = pnet_tplink_login($pdo);
        if (empty($tp['ok'])) {
            pnet_setting_set($pdo, 'router_login_ok', '0');
            $why = (string) ($tp['error'] ?? 'login_failed');
            $hint = 'Check the admin username/password (not the Wi‑Fi password).';
            if ($why === 'getParm_failed' || $why === 'getParm_parse') {
                $hint = 'Router responded, but TP-Link login API was not available. Open the router page once in a browser, then try Connect again.';
            } elseif (str_starts_with($why, 'login_http_')) {
                $hint = 'TP-Link rejected the login request (' . $why . '). Confirm admin password and that remote/admin login is not locked.';
            } elseif ($why === 'bad_password') {
                $hint = 'TP-Link rejected the password. Use the router admin password, not the Wi‑Fi password.';
            } elseif ($why !== '' && $why !== 'login_failed') {
                $hint .= ' (' . $why . ')';
            }
            throw new RuntimeException('Reached your TP-Link at ' . $url . ', but login failed. ' . $hint);
        }
        pnet_setting_set($pdo, 'router_login_ok', '1');
        $loginOk = true;
        $loginNote = ' TP-Link login verified.';
        try {
            $syncNote = ' ' . pnet_tplink_sync_devices($pdo);
        } catch (Throwable $e) {
            $syncNote = ' Login OK — device sync: ' . $e->getMessage();
        }
    } elseif ($brand === 'zte' || stripos((string) ($probe['title'] ?? ''), 'F6') !== false) {
        $loginOk = pnet_zte_login($pdo);
        if (!$loginOk) {
            pnet_setting_set($pdo, 'router_login_ok', '0');
            throw new RuntimeException('Reached your ZTE at ' . $url . ', but login failed. Check the admin username/password (not the Wi‑Fi password).');
        }
        pnet_setting_set($pdo, 'router_login_ok', '1');
        $loginNote = ' ZTE login verified.';
    } else {
        // Try TP-Link style login first (common home UI), then accept credentials as saved.
        @unlink(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.tplink_session.json');
        $tp = pnet_tplink_login($pdo);
        if (!empty($tp['ok'])) {
            pnet_setting_set($pdo, 'router_brand', 'tp-link');
            pnet_setting_set($pdo, 'router_brand_name', 'TP-Link');
            pnet_setting_set($pdo, 'router_login_ok', '1');
            $loginOk = true;
            $loginNote = ' TP-Link login verified.';
            try {
                $syncNote = ' ' . pnet_tplink_sync_devices($pdo);
            } catch (Throwable $e) {
                $syncNote = ' Login OK — device sync: ' . $e->getMessage();
            }
        } else {
            pnet_setting_set($pdo, 'router_login_ok', '1');
            $loginOk = true;
        }
    }

    pnet_log($pdo, 'router', 'Connected to router at ' . $url . ($loginOk ? ' (login ok)' : '') . '.');
    pnet_ensure_gateway_device($pdo);
    return 'Router connected.' . $loginNote . $syncNote;
}

function pnet_router_save_login(PDO $pdo, array $data): string
{
    $net = pnet_detect_lan_network();
    $gateway = trim((string) ($net['gateway'] ?? ''));
    $rawUrl = trim((string) ($data['router_admin_url'] ?? ''));
    if ($rawUrl === '') {
        $rawUrl = trim(pnet_setting($pdo, 'router_admin_url', ''));
    }
    if ($rawUrl === '' && $gateway !== '') {
        $rawUrl = 'http://' . $gateway;
    }
    $url = pnet_router_admin_url($rawUrl, $gateway);
    $user = pnet_text((string) ($data['router_admin_user'] ?? ''), 64, 'Username', false);
    $password = (string) ($data['router_admin_password'] ?? '');
    if ($password === '') {
        throw new InvalidArgumentException('Password is required to save the router login.');
    }
    if (strlen($password) > 200) {
        throw new InvalidArgumentException('Password is too long.');
    }
    return pnet_tx($pdo, function () use ($pdo, $url, $user, $password) {
        pnet_setting_set($pdo, 'router_admin_url', $url);
        pnet_setting_set($pdo, 'router_admin_user', $user);
        pnet_setting_set($pdo, 'router_admin_pass_enc', pnet_router_encrypt($password));
        pnet_setting_set($pdo, 'router_reachable', '1');
        pnet_setting_set($pdo, 'router_last_probe', pnet_now());
        pnet_log($pdo, 'router', 'Saved router login for ' . $url . '.');
        return 'Router login saved. Next time PNet will fill it in for you.';
    });
}

function pnet_router_get_login(PDO $pdo): array
{
    $access = pnet_router_access($pdo);
    $enc = pnet_setting($pdo, 'router_admin_pass_enc', '');
    $password = '';
    if ($enc !== '') {
        try {
            $password = pnet_router_decrypt($enc);
        } catch (Throwable $e) {
            $password = '';
        }
    }
    return [
        'admin_url' => (string) ($access['admin_url'] ?? ''),
        'username' => (string) ($access['username'] ?? ''),
        'password' => $password,
        'has_credentials' => $password !== '',
    ];
}

function pnet_router_probe_action(PDO $pdo): string
{
    $access = pnet_router_access($pdo);
    $url = (string) ($access['admin_url'] ?? '');
    if ($url === '') {
        throw new RuntimeException('No router address saved yet.');
    }
    $probe = pnet_router_probe_url($url);
    return pnet_tx($pdo, function () use ($pdo, $probe, $url) {
        pnet_setting_set($pdo, 'router_reachable', $probe['reachable'] ? '1' : '0');
        pnet_setting_set($pdo, 'router_page_title', (string) ($probe['title'] ?? ''));
        pnet_setting_set($pdo, 'router_last_probe', pnet_now());
        pnet_log($pdo, 'router', $probe['reachable'] ? 'Router is reachable.' : 'Router did not respond.');
        return $probe['reachable']
            ? ('Router reachable' . ($probe['title'] !== '' ? ': ' . $probe['title'] : '') . '.')
            : 'Router did not respond. Check power and Wi‑Fi.';
    });
}

function pnet_router_upnp_mappings(): array
{
    if (PHP_OS_FAMILY !== 'Windows' || !pnet_can_exec()) {
        return [];
    }
    $script = <<<'PS'
$m = New-Object -ComObject HNetCfg.NATUPnP -ErrorAction SilentlyContinue
if (-not $m) { exit 2 }
$c = $m.StaticPortMappingCollection
if (-not $c) { '[]'; exit 0 }
$out = @()
foreach ($item in @($c)) {
  $out += [pscustomobject]@{
    name = [string]$item.Description
    protocol = [string]$item.Protocol
    external = [int]$item.ExternalPort
    internal = [int]$item.InternalPort
    client = [string]$item.InternalClient
  }
}
$out | ConvertTo-Json -Compress
PS;
    $cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command ' . escapeshellarg($script);
    $lines = [];
    $code = 1;
    exec($cmd, $lines, $code);
    if ($code !== 0) {
        return [];
    }
    $raw = trim(implode("\n", $lines));
    if ($raw === '' || $raw === '[]') {
        return [];
    }
    $decoded = json_decode($raw, true);
    if ($decoded === null) {
        return [];
    }
    if (isset($decoded['name'])) {
        return [$decoded];
    }
    return is_array($decoded) ? $decoded : [];
}

function pnet_router_sync_upnp(PDO $pdo): string
{
    $maps = pnet_router_upnp_mappings();
    if ($maps === []) {
        throw new RuntimeException('No UPnP port mappings found on this router, or UPnP is off.');
    }
    return pnet_tx($pdo, function () use ($pdo, $maps) {
        $added = 0;
        $updated = 0;
        $now = pnet_now();
        $sel = $pdo->prepare('SELECT id FROM port_forwards WHERE external_port = ? AND protocol = ?');
        $ins = $pdo->prepare('INSERT INTO port_forwards (name, protocol, external_port, internal_ip, internal_port, enabled, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)');
        $upd = $pdo->prepare('UPDATE port_forwards SET name = ?, internal_ip = ?, internal_port = ?, notes = ?, updated_at = ? WHERE id = ?');
        foreach ($maps as $map) {
            if (!is_array($map)) {
                continue;
            }
            $name = trim((string) ($map['name'] ?? 'UPnP rule'));
            if ($name === '') {
                $name = 'UPnP rule';
            }
            $name = pnet_text($name, 80, 'Name', true);
            $protocol = strtolower((string) ($map['protocol'] ?? 'tcp'));
            if (!in_array($protocol, ['tcp', 'udp', 'both'], true)) {
                $protocol = 'tcp';
            }
            $external = (int) ($map['external'] ?? 0);
            $internal = (int) ($map['internal'] ?? $external);
            $client = pnet_ip((string) ($map['client'] ?? ''), true, 'Internal IP');
            if ($external < 1 || $external > 65535) {
                continue;
            }
            $sel->execute([(string) $external, $protocol]);
            $row = $sel->fetch();
            $notes = 'Imported from router UPnP.';
            if ($row) {
                $upd->execute([$name, $client, (string) $internal, $notes, $now, (int) $row['id']]);
                $updated++;
            } else {
                $ins->execute([$name, $protocol, (string) $external, $client, (string) $internal, $notes, $now, $now]);
                $added++;
            }
        }
        pnet_log($pdo, 'router', 'Synced UPnP port forwards from router.');
        return 'Synced ' . ($added + $updated) . ' port rule(s) from your router (' . $added . ' new).';
    });
}

function pnet_sync_router_brand(PDO $pdo, bool $probeHttp = false): array
{
    $catalog = pnet_router_brand_catalog();
    $network = pnet_detect_lan_network();
    $gateway = trim((string) ($network['gateway'] ?? ''));
    if ($gateway === '' && ($network['prefix'] ?? '') !== '') {
        $gateway = (string) $network['prefix'] . '.1';
    }
    if ($gateway === '' || !pnet_is_lan_ipv4($gateway)) {
        return ['brand' => 'generic', 'name' => 'Router', 'model' => '', 'admin_url' => '', 'gateway' => ''];
    }

    $device = null;
    $st = $pdo->prepare('SELECT * FROM devices WHERE ip = ? LIMIT 1');
    $st->execute([$gateway]);
    $device = $st->fetch() ?: null;
    if (!$device) {
        $st = $pdo->prepare("SELECT * FROM devices WHERE type = 'router' ORDER BY id ASC LIMIT 1");
        $st->execute();
        $device = $st->fetch() ?: null;
    }

    $mac = $device ? trim((string) ($device['mac'] ?? '')) : '';
    $vendor = $device ? trim((string) ($device['vendor'] ?? '')) : '';
    $name = $device ? trim((string) ($device['name'] ?? '')) : '';
    if ($vendor === '' && $mac !== '') {
        $vendor = pnet_oui_vendor($mac);
    }

    $brand = 'generic';
    if ($mac !== '') {
        $fromOui = pnet_router_oui_brand($mac);
        if ($fromOui !== 'generic') {
            $brand = $fromOui;
        }
    }
    foreach ([$vendor, $name, pnet_resolve_hostname($gateway)] as $hint) {
        if ($hint === '') {
            continue;
        }
        $matched = pnet_match_router_brand($hint);
        if ($matched !== 'generic') {
            $brand = $matched;
            break;
        }
    }

    $model = trim(pnet_setting($pdo, 'router_model', ''));
    $http = [];
    if ($probeHttp) {
        $http = pnet_probe_router_http($gateway);
        if (($http['brand'] ?? 'generic') !== 'generic') {
            $brand = (string) $http['brand'];
        }
        if ($model === '' && !empty($http['model'])) {
            $model = (string) $http['model'];
        } elseif ($model === '' && !empty($http['title'])) {
            $model = (string) $http['title'];
        }
    }

    $info = $catalog[$brand] ?? $catalog['generic'];
    $brandName = (string) $info['name'];
    // Always use the local gateway IP — brand hostnames (tplinkwifi.net etc.) fail validation later.
    $adminUrl = 'http://' . $gateway;
    $storedAdmin = trim(pnet_setting($pdo, 'router_admin_url', ''));
    $storedHost = is_string(parse_url($storedAdmin, PHP_URL_HOST)) ? (string) parse_url($storedAdmin, PHP_URL_HOST) : '';
    if ($storedAdmin === '' || !pnet_is_lan_ipv4($storedHost)) {
        pnet_setting_set($pdo, 'router_admin_url', $adminUrl);
    } else {
        $adminUrl = $storedAdmin;
    }
    if ($model === '' && $vendor !== '') {
        $model = $vendor;
    }

    pnet_setting_set($pdo, 'router_brand', $brand);
    pnet_setting_set($pdo, 'router_brand_name', $brandName);
    if ($model !== '' && trim(pnet_setting($pdo, 'router_model', '')) === '') {
        pnet_setting_set($pdo, 'router_model', $model);
    }
    if (trim(pnet_setting($pdo, 'lan_ip', '')) === '') {
        pnet_setting_set($pdo, 'lan_ip', $gateway);
    }

    if ($device) {
        $displayName = $brandName !== 'Router'
            ? ($brandName . (str_contains(strtolower($brandName), 'router') ? '' : ' Router'))
            : 'Home Router';
        if ($model !== '' && stripos($displayName, $model) === false && stripos($model, $brandName) === false) {
            $displayName = $brandName . ' ' . $model;
        }
        $upd = $pdo->prepare("UPDATE devices SET type = 'router', vendor = CASE WHEN vendor = '' OR vendor = 'Device' THEN ? ELSE vendor END, name = ?, updated_at = ? WHERE id = ?");
        $upd->execute([$brandName, $displayName, pnet_now(), (int) $device['id']]);
    } else {
        pnet_ensure_gateway_device($pdo, $gateway, $brandName, $mac);
    }

    return [
        'brand' => $brand,
        'name' => $brandName,
        'model' => $model,
        'admin_url' => $adminUrl,
        'gateway' => $gateway,
        'icon' => 'assets/brands/' . $brand . '.svg',
    ];
}

/**
 * Make sure the Wi‑Fi gateway always appears in Devices as the router.
 */
function pnet_ensure_gateway_device(PDO $pdo, string $gateway = '', string $brandName = '', string $mac = ''): void
{
    if ($gateway === '') {
        $net = pnet_detect_lan_network();
        $gateway = trim((string) ($net['gateway'] ?? ''));
        if ($gateway === '' && ($net['prefix'] ?? '') !== '') {
            $gateway = (string) $net['prefix'] . '.1';
        }
    }
    if ($gateway === '' || !pnet_is_lan_ipv4($gateway)) {
        return;
    }
    if ($brandName === '') {
        $brandName = trim(pnet_setting($pdo, 'router_brand_name', ''));
        if ($brandName === '' || $brandName === 'Router') {
            $brand = strtolower(trim(pnet_setting($pdo, 'router_brand', '')));
            $catalog = pnet_router_brand_catalog();
            $brandName = (string) (($catalog[$brand]['name'] ?? '') ?: 'Home');
        }
    }
    $displayName = $brandName !== '' && $brandName !== 'Router'
        ? (str_contains(strtolower($brandName), 'router') ? $brandName : $brandName . ' Router')
        : 'Home Router';
    $now = pnet_now();
    $st = $pdo->prepare('SELECT id, mac, name, type FROM devices WHERE ip = ? LIMIT 1');
    $st->execute([$gateway]);
    $row = $st->fetch();
    if ($row) {
        $keepMac = $mac !== '' ? $mac : (string) ($row['mac'] ?? '');
        $pdo->prepare("UPDATE devices SET type = 'router', name = ?, mac = CASE WHEN ? != '' THEN ? ELSE mac END, vendor = CASE WHEN vendor = '' OR vendor = 'Device' THEN ? ELSE vendor END, status = 'online', last_seen = ?, updated_at = ? WHERE id = ?")
            ->execute([$displayName, $keepMac, $keepMac, $brandName, $now, $now, (int) $row['id']]);
        return;
    }
    if ($mac === '') {
        $arp = pnet_read_arp_table();
        $mac = strtoupper((string) ($arp[$gateway] ?? ''));
        if ($mac !== '' && str_contains($mac, '-')) {
            $mac = str_replace('-', ':', $mac);
        }
    }
    $pdo->prepare('INSERT INTO devices (name, ip, mac, type, vendor, status, last_seen, trust, access_profile, bandwidth_limit, protected, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')
        ->execute([
            $displayName,
            $gateway,
            $mac,
            'router',
            $brandName !== '' ? $brandName : 'Router',
            'online',
            $now,
            'trusted',
            'normal',
            0,
            1,
            'Your Wi‑Fi gateway / router',
            $now,
            $now,
        ]);
}

function pnet_device_brand_catalog(): array
{
    return array_merge(pnet_router_brand_catalog(), [
        'apple' => ['name' => 'Apple'],
        'samsung' => ['name' => 'Samsung'],
        'microsoft' => ['name' => 'Microsoft'],
        'dell' => ['name' => 'Dell'],
        'hp' => ['name' => 'HP'],
        'lenovo' => ['name' => 'Lenovo'],
        'acer' => ['name' => 'Acer'],
        'sony' => ['name' => 'Sony'],
        'lg' => ['name' => 'LG'],
        'roku' => ['name' => 'Roku'],
        'amazon' => ['name' => 'Amazon'],
        'ring' => ['name' => 'Ring'],
        'wyze' => ['name' => 'Wyze'],
        'arlo' => ['name' => 'Arlo'],
        'hikvision' => ['name' => 'Hikvision'],
        'dahua' => ['name' => 'Dahua'],
        'oneplus' => ['name' => 'OnePlus'],
        'xiaomi' => ['name' => 'Xiaomi'],
        'nintendo' => ['name' => 'Nintendo'],
        'brother' => ['name' => 'Brother'],
        'canon' => ['name' => 'Canon'],
        'epson' => ['name' => 'Epson'],
        'phone' => ['name' => 'Phone'],
        'computer' => ['name' => 'Computer'],
        'tablet' => ['name' => 'Tablet'],
        'tv' => ['name' => 'TV'],
        'camera' => ['name' => 'Camera'],
        'printer' => ['name' => 'Printer'],
        'speaker' => ['name' => 'Speaker'],
        'console' => ['name' => 'Game console'],
        'iot' => ['name' => 'Smart device'],
        'other' => ['name' => 'Device'],
    ]);
}

function pnet_type_brand_fallback(string $type): string
{
    static $map = [
        'router' => 'generic',
        'computer' => 'computer',
        'phone' => 'phone',
        'tablet' => 'tablet',
        'tv' => 'tv',
        'console' => 'console',
        'printer' => 'printer',
        'iot' => 'iot',
        'camera' => 'camera',
        'speaker' => 'speaker',
    ];
    return $map[$type] ?? 'other';
}

function pnet_device_oui_brand(string $mac): string
{
    $hex = strtoupper(str_replace([':', '-'], '', $mac));
    if (strlen($hex) < 6) {
        return 'generic';
    }
    $prefix = substr($hex, 0, 6);
    static $map = [
        '001B63' => 'apple', '001F5B' => 'apple', '0026B0' => 'apple', '1C1AC0' => 'apple',
        '40A6D9' => 'apple', '48A195' => 'apple', '4C3275' => 'apple',
        '5C969D' => 'apple', '60A4D0' => 'apple', '68A86D' => 'apple', '6C4008' => 'apple',
        '78A3E4' => 'apple', '80E650' => 'apple', '84A134' => 'apple',
        '28C63F' => 'intel', '74D02B' => 'asus',
        '88E9FE' => 'apple', '8C8590' => 'apple', '90B21F' => 'apple', '98D6BB' => 'apple',
        '9C207B' => 'apple', 'A4C361' => 'apple', 'A8BBCF' => 'apple', 'ACBC32' => 'apple',
        'B065BD' => 'apple', 'B0BE76' => 'apple', 'B8E856' => 'apple', 'C8D083' => 'apple',
        'CC08E0' => 'apple', 'D0E140' => 'apple', 'D4A33D' => 'apple', 'D8A25E' => 'apple',
        'DC56E7' => 'apple', 'E4CE8F' => 'apple', 'E8B2AC' => 'apple', 'EC3586' => 'apple',
        'F0DCE2' => 'apple', 'F8FFC2' => 'apple', 'FC253F' => 'apple', '00DB70' => 'apple',
        '24F5AA' => 'samsung', '3C5A37' => 'samsung', '8CE117' => 'samsung', 'C0BDD1' => 'samsung',
        '001A11' => 'google', '14ABB7' => 'google', 'F4F5D8' => 'google', '7C2EBD' => 'google',
        '18B430' => 'google', '0050F2' => 'microsoft', '00155D' => 'microsoft', '0050B6' => 'microsoft',
        '7C1E52' => 'microsoft', '204747' => 'dell', '50E4E0' => 'dell', '001F3B' => 'intel',
        '0022FB' => 'intel', '0024D7' => 'intel', '00A0C9' => 'intel', '00D0B7' => 'intel',
        '28C63F' => 'intel', 'B4B676' => 'intel', '040E3C' => 'hp', '0025A0' => 'nintendo',
        '000D4B' => 'roku', 'B0A737' => 'roku', '2C54CF' => 'lg', '001E58' => 'd-link',
        '34CDBE' => 'huawei', '002EC7' => 'huawei', '002711' => 'asus', '64BC0C' => 'asus',
        '0021E9' => 'tp-link', '54AF97' => 'tp-link', '20E52A' => 'netgear', 'C03F0E' => 'netgear',
        '001D7E' => 'linksys', '44D9E7' => 'ubiquiti', '001E13' => 'cisco', 'D4D7A5' => 'eero',
    ];
    $prefix = str_replace(' ', '', $prefix);
    if (isset($map[$prefix])) {
        return $map[$prefix];
    }
    $vendor = pnet_oui_vendor($mac);
    if ($vendor !== '') {
        return pnet_match_device_brand($vendor);
    }
    return 'generic';
}

function pnet_match_device_brand(string $text, string $type = ''): string
{
    $hay = strtolower(trim($text));
    if ($hay === '') {
        return 'generic';
    }
    $router = pnet_match_router_brand($text);
    if ($router !== 'generic') {
        return $router;
    }
    $patterns = [
        'apple' => '/apple|iphone|ipad|ipod|macbook|imac|mac mini|mac pro|airpods|homepod|apple.?tv/',
        'samsung' => '/samsung|galaxy|smartthings/',
        'google' => '/google|pixel|chromecast|nest|onhub/',
        'microsoft' => '/microsoft|surface|xbox|windows phone/',
        'dell' => '/dell|alienware|latitude|inspiron|xps/',
        'hp' => '/\bhp\b|hewlett|elitebook|pavilion|omen/',
        'lenovo' => '/lenovo|thinkpad|ideapad|legion/',
        'acer' => '/acer|predator|aspire/',
        'asus' => '/asus|rog|zenbook|vivobook/',
        'sony' => '/sony|playstation|\bps[45]\b|bravia/',
        'lg' => '/\blg\b|webos|gram/',
        'roku' => '/roku/',
        'amazon' => '/amazon|echo|fire tv|firestick|kindle|alexa/',
        'ring' => '/ring doorbell|ring camera|\bring\b/',
        'wyze' => '/wyze/',
        'arlo' => '/arlo/',
        'hikvision' => '/hikvision|hik-connect/',
        'dahua' => '/dahua|amcrest|lorex/',
        'oneplus' => '/oneplus/',
        'xiaomi' => '/xiaomi|redmi|mi tv|poco/',
        'huawei' => '/huawei|honor/',
        'nintendo' => '/nintendo|switch/',
        'brother' => '/brother/',
        'canon' => '/canon|pixma/',
        'epson' => '/epson/',
        'intel' => '/intel|core i[3579]/',
    ];
    foreach ($patterns as $slug => $regex) {
        if (preg_match($regex, $hay)) {
            if ($slug === 'asus' && $type === 'router') {
                return 'asus';
            }
            if ($slug === 'google' && $type === 'router') {
                return 'google';
            }
            if ($slug === 'huawei' && $type === 'router') {
                return 'huawei';
            }
            return $slug;
        }
    }
    return 'generic';
}

function pnet_detect_device_brand(string $mac, string $vendor, string $name, string $type, string $hostname = ''): array
{
    $catalog = pnet_device_brand_catalog();
    $brand = 'generic';
    if ($mac !== '') {
        $fromOui = pnet_device_oui_brand($mac);
        if ($fromOui !== 'generic') {
            $brand = $fromOui;
        }
    }
    foreach ([$vendor, $name, $hostname] as $hint) {
        if ($hint === '') {
            continue;
        }
        $matched = pnet_match_device_brand($hint, $type);
        if ($matched !== 'generic') {
            $brand = $matched;
            break;
        }
    }
    if ($brand === 'generic') {
        $brand = pnet_type_brand_fallback($type);
    }
    $info = $catalog[$brand] ?? $catalog['other'];
    return [
        'brand' => $brand,
        'name' => (string) ($info['name'] ?? 'Device'),
    ];
}

function pnet_enrich_devices_with_brands(array $devices, string $routerBrand = '', string $gatewayIp = ''): array
{
    $catalog = pnet_device_brand_catalog();
    foreach ($devices as &$device) {
        $ip = trim((string) ($device['ip'] ?? ''));
        if ($gatewayIp !== '' && $ip === $gatewayIp && $routerBrand !== '' && $routerBrand !== 'generic') {
            $device['brand'] = $routerBrand;
            $device['brand_name'] = (string) (($catalog[$routerBrand]['name'] ?? 'Router'));
            continue;
        }
        $info = pnet_detect_device_brand(
            trim((string) ($device['mac'] ?? '')),
            trim((string) ($device['vendor'] ?? '')),
            trim((string) ($device['name'] ?? '')),
            trim((string) ($device['type'] ?? 'other'))
        );
        $device['brand'] = $info['brand'];
        $device['brand_name'] = $info['name'];
    }
    unset($device);
    return $devices;
}

function pnet_resolve_hostname(string $ip, bool $allowSlow = false): string
{
    if (!pnet_is_lan_ipv4($ip)) {
        return '';
    }
    // Reverse DNS on Windows often hangs for unreachable hosts and makes Find devices time out.
    if (!$allowSlow) {
        return '';
    }
    $host = @gethostbyaddr($ip);
    if (!is_string($host) || $host === '' || $host === $ip) {
        return '';
    }
    $host = preg_replace('/\.(local|lan|home)$/i', '', $host) ?? $host;
    try {
        return pnet_text($host, 80, 'Hostname', false);
    } catch (Throwable $e) {
        return '';
    }
}

function pnet_native_scan_bin(): string
{
    $root = dirname(__DIR__);
    $candidates = [
        $root . DIRECTORY_SEPARATOR . 'engine' . DIRECTORY_SEPARATOR . 'build' . DIRECTORY_SEPARATOR . 'pnet_scan.exe',
        $root . DIRECTORY_SEPARATOR . 'engine' . DIRECTORY_SEPARATOR . 'build' . DIRECTORY_SEPARATOR . 'pnet_scan',
    ];
    foreach ($candidates as $path) {
        if (is_file($path)) {
            return $path;
        }
    }
    return '';
}

function pnet_native_engine_failed(?bool $set = null): bool
{
    static $failed = false;
    if ($set !== null) {
        $failed = $set;
    }
    return $failed;
}

function pnet_exec_timeout(string $command, float $timeoutSec = 2.0): array
{
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = @proc_open($command, $descriptors, $pipes, dirname(__DIR__), null, ['bypass_shell' => false]);
    if (!is_resource($proc)) {
        return ['ok' => false, 'output' => '', 'code' => 1];
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $start = microtime(true);
    $status = proc_get_status($proc);
    while ($status['running']) {
        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        if ((microtime(true) - $start) >= $timeoutSec) {
            proc_terminate($proc, 9);
            $stdout .= (string) stream_get_contents($pipes[1]);
            $stderr .= (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            return ['ok' => false, 'output' => trim($stdout . "\n" . $stderr), 'code' => 124, 'timeout' => true];
        }
        usleep(40000);
        $status = proc_get_status($proc);
    }
    $stdout .= (string) stream_get_contents($pipes[1]);
    $stderr .= (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['ok' => $code === 0, 'output' => trim($stdout), 'code' => $code, 'timeout' => false];
}

function pnet_native_scan(): ?array
{
    if (pnet_native_engine_failed()) {
        return null;
    }
    $bin = pnet_native_scan_bin();
    if ($bin === '' || !pnet_can_exec()) {
        return null;
    }
    $run = pnet_exec_timeout(escapeshellarg($bin) . ' --json', 2.5);
    if (!empty($run['timeout']) || ($run['output'] ?? '') === '') {
        pnet_native_engine_failed(true);
        return null;
    }
    $decoded = json_decode((string) $run['output'], true);
    if (!is_array($decoded) || empty($decoded['ok']) || !isset($decoded['devices']) || !is_array($decoded['devices'])) {
        pnet_native_engine_failed(true);
        return null;
    }
    return $decoded;
}

function pnet_native_monitor(): ?array
{
    if (pnet_native_engine_failed()) {
        return null;
    }
    $bin = pnet_native_scan_bin();
    if ($bin === '' || !pnet_can_exec()) {
        return null;
    }
    $run = pnet_exec_timeout(escapeshellarg($bin) . ' --monitor --json', 1.5);
    if (!empty($run['timeout']) || ($run['output'] ?? '') === '') {
        pnet_native_engine_failed(true);
        return null;
    }
    $decoded = json_decode((string) $run['output'], true);
    if (!is_array($decoded) || empty($decoded['ok'])) {
        pnet_native_engine_failed(true);
        return null;
    }
    return $decoded;
}

function pnet_traffic_state_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.traffic_state.json';
}

function pnet_process_name_map(): array
{
    static $mem = null;
    if (is_array($mem)) {
        return $mem;
    }
    $path = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.proc_names.json';
    if (is_file($path)) {
        $mtime = @filemtime($path) ?: 0;
        if ($mtime > 0 && (time() - $mtime) < 8) {
            $raw = @file_get_contents($path);
            $decoded = is_string($raw) ? json_decode($raw, true) : null;
            if (is_array($decoded)) {
                return $mem = $decoded;
            }
        }
    }
    $names = [];
    if (PHP_OS_FAMILY === 'Windows' && pnet_can_exec()) {
        $taskOut = [];
        exec('tasklist /FO CSV /NH', $taskOut);
        foreach ($taskOut as $line) {
            if (!preg_match('/^"([^"]+)","(\d+)"/', $line, $m)) {
                continue;
            }
            $names[(string) ((int) $m[2])] = $m[1];
        }
        @file_put_contents($path, json_encode($names, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }
    return $mem = $names;
}

function pnet_monitor_php_fallback(): ?array
{
    if (PHP_OS_FAMILY !== 'Windows' || !pnet_can_exec()) {
        return null;
    }
    $live = pnet_live_adapter_details();
    $localIp = (string) ($live['local_ip'] ?? '');
    $output = [];
    exec('netstat -ano -p tcp', $output);
    $byPid = [];
    foreach ($output as $line) {
        if (stripos($line, 'TCP') !== 0) {
            continue;
        }
        $parts = preg_split('/\s+/', trim($line));
        if (!$parts || count($parts) < 5) {
            continue;
        }
        $state = strtoupper($parts[3] ?? '');
        if ($state !== 'ESTABLISHED') {
            continue;
        }
        $remote = $parts[2] ?? '';
        $pid = (int) ($parts[4] ?? 0);
        if ($pid < 1) {
            continue;
        }
        $host = explode(':', $remote)[0] ?? '';
        if (!isset($byPid[$pid])) {
            $byPid[$pid] = ['pid' => $pid, 'tcp' => 0, 'udp' => 0, 'remote_public' => 0, 'remote_lan' => 0, 'name' => 'Unknown', 'path' => ''];
        }
        $byPid[$pid]['tcp']++;
        if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP)) {
            if (pnet_is_lan_ipv4($host)) {
                $byPid[$pid]['remote_lan']++;
            } else {
                $byPid[$pid]['remote_public']++;
            }
        }
    }
    $names = pnet_process_name_map();
    $apps = [];
    foreach ($byPid as $pid => $row) {
        $row['name'] = $names[(string) $pid] ?? ('PID ' . $pid);
        $apps[] = $row;
    }
    usort($apps, static function ($a, $b) {
        return (($b['remote_public'] ?? 0) <=> ($a['remote_public'] ?? 0)) ?: (($b['tcp'] ?? 0) <=> ($a['tcp'] ?? 0));
    });
    if (count($apps) > 25) {
        $apps = array_slice($apps, 0, 25);
    }
    return [
        'ok' => true,
        'local_ip' => $localIp,
        'adapter' => (string) ($live['adapter'] ?? ''),
        'bytes_in' => 0,
        'bytes_out' => 0,
        'apps' => $apps,
        'limited' => true,
    ];
}

function pnet_traffic_read_state(): array
{
    $path = pnet_traffic_state_path();
    if (!is_file($path)) {
        return [];
    }
    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function pnet_traffic_write_state(array $state): void
{
    $path = pnet_traffic_state_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($path, json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function pnet_traffic_app_label(string $name): string
{
    $base = strtolower(trim($name));
    $map = [
        'chrome.exe' => 'Google Chrome',
        'msedge.exe' => 'Microsoft Edge',
        'firefox.exe' => 'Firefox',
        'opera.exe' => 'Opera',
        'brave.exe' => 'Brave',
        'discord.exe' => 'Discord',
        'spotify.exe' => 'Spotify',
        'steam.exe' => 'Steam',
        'zoom.exe' => 'Zoom',
        'teams.exe' => 'Microsoft Teams',
        'ms-teams.exe' => 'Microsoft Teams',
        'onedrive.exe' => 'OneDrive',
        'dropbox.exe' => 'Dropbox',
        'python.exe' => 'Python',
        'node.exe' => 'Node.js',
        'httpd.exe' => 'Apache',
        'apache.exe' => 'Apache',
        'mysqld.exe' => 'MySQL',
        'svchost.exe' => 'Windows Service Host',
    ];
    if (isset($map[$base])) {
        return $map[$base];
    }
    if (str_ends_with($base, '.exe')) {
        $base = substr($base, 0, -4);
    }
    return $base !== '' ? ucfirst($base) : 'Unknown';
}

function pnet_traffic_allocate_apps(array $apps, int $downBps, int $upBps): array
{
    $rows = [];
    $weightTotal = 0;
    foreach ($apps as $app) {
        if (!is_array($app)) {
            continue;
        }
        $tcp = (int) ($app['tcp'] ?? $app['tcp_established'] ?? 0);
        $udp = (int) ($app['udp'] ?? $app['udp_endpoints'] ?? 0);
        $public = (int) ($app['remote_public'] ?? 0);
        $weight = max(1, $tcp + $udp + ($public * 2));
        $weightTotal += $weight;
        $rows[] = [
            'pid' => (int) ($app['pid'] ?? 0),
            'name' => (string) ($app['name'] ?? 'Unknown'),
            'label' => pnet_traffic_app_label((string) ($app['name'] ?? 'Unknown')),
            'tcp' => $tcp,
            'udp' => $udp,
            'remote_public' => $public,
            'remote_lan' => (int) ($app['remote_lan'] ?? 0),
            'weight' => $weight,
        ];
    }
    usort($rows, function ($a, $b) {
        return $b['weight'] <=> $a['weight'];
    });
    foreach ($rows as &$row) {
        $share = $weightTotal > 0 ? ($row['weight'] / $weightTotal) : 0;
        $row['down_bps'] = (int) round($downBps * $share);
        $row['up_bps'] = (int) round($upBps * $share);
        unset($row['weight']);
    }
    unset($row);
    return array_slice($rows, 0, 40);
}

require_once __DIR__ . '/traffic_sources.php';

function pnet_traffic_live(PDO $pdo, ?int $deviceId = null): array
{
    return pnet_traffic_live_merged($pdo, $deviceId);
}

function pnet_find_devices(PDO $pdo): string
{
    if (!pnet_can_exec()) {
        throw new RuntimeException('PHP exec is disabled, so discovery cannot run.');
    }
    @set_time_limit(180);
    @ini_set('max_execution_time', '180');

    // Prefer ARP first — the C scanner can take 15–30s when it works, and crashes when DLLs are missing.
    $network = pnet_detect_lan_network();
    $found = pnet_read_arp_table();
    $probed = 0;
    if (count($found) < 2) {
        $native = pnet_native_scan_quick();
        if ($native !== null) {
            $found = [];
            foreach ($native['devices'] as $device) {
                if (!is_array($device)) {
                    continue;
                }
                $ip = trim((string) ($device['ip'] ?? ''));
                $mac = strtoupper(str_replace('-', ':', trim((string) ($device['mac'] ?? ''))));
                if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
                    continue;
                }
                $found[$ip] = ($mac !== '' && preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/', $mac)) ? $mac : '';
            }
            if ($found) {
                if ($network['prefix'] === '' && !empty($native['lan_cidr']) && preg_match('/^(\d+\.\d+\.\d+)\.\d+\/\d+$/', (string) $native['lan_cidr'], $m)) {
                    $network['prefix'] = $m[1];
                    $network['label'] = (string) $native['lan_cidr'];
                }
                $message = pnet_import_found_devices($pdo, $found, count($found), $network);
                return pnet_enrich_from_native($pdo, $native, $message);
            }
        }
        $probed = pnet_probe_lan($network);
        usleep(200000);
        $found = pnet_read_arp_table();
    }
    if (!$found) {
        throw new RuntimeException('No devices were visible yet. Make sure this PC is connected to Wi-Fi, then try again.');
    }
    $message = pnet_import_found_devices($pdo, $found, $probed, $network);
    $access = pnet_router_access($pdo);
    if (!empty($access['has_credentials']) && function_exists('pnet_tplink_sync_devices')) {
        $brand = strtolower((string) pnet_setting($pdo, 'router_brand', ''));
        if ($brand === 'tp-link' || $brand === 'tplink' || $brand === '' || $brand === 'generic') {
            try {
                $message .= ' ' . pnet_tplink_sync_devices($pdo);
            } catch (Throwable $e) {
                // ARP results already saved — router sync is best-effort.
            }
        }
    }
    return $message;
}

function pnet_router_sync_devices(PDO $pdo): string
{
    if (!function_exists('pnet_tplink_sync_devices')) {
        require_once __DIR__ . '/traffic_sources.php';
    }
    $brand = strtolower((string) pnet_setting($pdo, 'router_brand', ''));
    if ($brand === 'zte') {
        throw new RuntimeException('Full DHCP pull works on TP-Link right now. Use Find devices for ARP discovery.');
    }
    return pnet_tplink_sync_devices($pdo);
}

function pnet_native_scan_quick(): ?array
{
    // Skip slow/broken engine during interactive Find devices.
    if (pnet_native_engine_failed()) {
        return null;
    }
    // Only use native if a previous run already proved it works quickly is not tracked;
    // prefer not blocking the UI — return null and let ARP/probe handle discovery.
    return null;
}

function pnet_enrich_from_native(PDO $pdo, array $native, string $message): string
{
    return pnet_tx($pdo, function () use ($pdo, $native, $message) {
        $now = pnet_now();
        $sel = $pdo->prepare('SELECT id, name, vendor, type FROM devices WHERE ip = ?');
        $upd = $pdo->prepare('UPDATE devices SET name = ?, vendor = CASE WHEN vendor = \'\' THEN ? ELSE vendor END, type = CASE WHEN type = \'other\' AND ? != \'other\' THEN ? ELSE type END, status = ?, ping_ms = ?, last_seen = ?, updated_at = ? WHERE id = ?');
        foreach ($native['devices'] as $device) {
            if (!is_array($device)) {
                continue;
            }
            $ip = trim((string) ($device['ip'] ?? ''));
            if ($ip === '') {
                continue;
            }
            $sel->execute([$ip]);
            $row = $sel->fetch();
            if (!$row) {
                continue;
            }
            $hostname = trim((string) ($device['hostname'] ?? ''));
            $vendor = trim((string) ($device['vendor'] ?? ''));
            $type = trim((string) ($device['type'] ?? 'other'));
            if ($type === '') {
                $type = 'other';
            }
            $online = !empty($device['online']);
            $ping = isset($device['ping_ms']) ? (int) $device['ping_ms'] : null;
            $name = (string) $row['name'];
            if ($hostname !== '' && (str_starts_with($name, 'Seen ') || $name === '' || str_ends_with($name, ' device'))) {
                $name = $hostname;
            }
            $upd->execute([
                $name,
                $vendor,
                $type,
                $type,
                $online ? 'online' : 'offline',
                $ping,
                $now,
                $now,
                (int) $row['id'],
            ]);
        }
        if (!empty($native['lan_cidr']) && pnet_setting($pdo, 'lan_cidr', '') === '') {
            pnet_setting_set($pdo, 'lan_cidr', (string) $native['lan_cidr']);
        }
        $detail = $message . ' (C/C++ engine)';
        pnet_log($pdo, 'discover', $detail);
        return $detail;
    });
}

function pnet_network_info(): array
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $live = pnet_live_adapter_details();
    $ip = (string) ($live['local_ip'] ?? '');
    $gateway = (string) ($live['gateway'] ?? '');
    $prefix = '';
    $label = '';
    if ($ip !== '' && pnet_is_lan_ipv4($ip)) {
        $parts = explode('.', $ip);
        $prefix = $parts[0] . '.' . $parts[1] . '.' . $parts[2];
        $label = $prefix . '.0/24';
    }
    return $cached = array_merge([
        'local_ip' => $ip,
        'gateway' => $gateway,
        'prefix' => $prefix,
        'lan_cidr' => $label,
        'can_scan' => pnet_can_exec(),
        'scanner_ready' => pnet_native_scan_bin() !== '',
        'monitor_ready' => pnet_native_scan_bin() !== '' && pnet_can_exec(),
        'dns' => [],
        'dhcp_server' => '',
        'adapter' => '',
        'mask' => '',
        'media_state' => '',
        'public_hint' => '',
    ], $live);
}

function pnet_live_adapter_details(): array
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $fromDisk = pnet_runtime_cache_get('live_adapter', 8);
    if ($fromDisk !== null) {
        return $cached = $fromDisk;
    }
    $out = [
        'dns' => [],
        'dhcp_server' => '',
        'adapter' => '',
        'mask' => '',
        'media_state' => '',
        'public_hint' => '',
        'local_ip' => '',
        'gateway' => '',
    ];
    if (PHP_OS_FAMILY !== 'Windows' || !pnet_can_exec()) {
        return $cached = $out;
    }
    $lines = [];
    exec('ipconfig /all', $lines);
    $current = ['name' => '', 'dns' => [], 'ip' => '', 'mask' => '', 'gateway' => '', 'dhcp' => '', 'media' => ''];
    $best = null;
    $flush = function () use (&$current, &$best): void {
        $ip = (string) ($current['ip'] ?? '');
        $gateway = (string) ($current['gateway'] ?? '');
        if ($ip !== '' && pnet_is_lan_ipv4($ip) && ($gateway !== '' || $best === null)) {
            $score = ($gateway !== '' ? 2 : 0) + (stripos((string) $current['name'], 'wi-fi') !== false || stripos((string) $current['name'], 'wireless') !== false ? 1 : 0);
            $curScore = is_array($best) ? (int) ($best['_score'] ?? 0) : -1;
            if ($score >= $curScore) {
                $best = $current;
                $best['_score'] = $score;
            }
        }
        $current = ['name' => '', 'dns' => [], 'ip' => '', 'mask' => '', 'gateway' => '', 'dhcp' => '', 'media' => ''];
    };
    foreach ($lines as $line) {
        if (preg_match('/adapter\s+(.+):/i', $line, $m)) {
            $flush();
            $current['name'] = trim($m[1]);
            continue;
        }
        if (preg_match('/Media State.*:\s*(.+)/i', $line, $m)) {
            $current['media'] = trim($m[1]);
        } elseif (preg_match('/IPv4 Address.*:\s*([0-9.]+)/i', $line, $m)) {
            $current['ip'] = $m[1];
        } elseif (preg_match('/Subnet Mask.*:\s*([0-9.]+)/i', $line, $m)) {
            $current['mask'] = $m[1];
        } elseif (preg_match('/Default Gateway.*:\s*([0-9.]+)/i', $line, $m)) {
            $current['gateway'] = $m[1];
        } elseif (preg_match('/DHCP Server.*:\s*([0-9.]+)/i', $line, $m)) {
            $current['dhcp'] = $m[1];
        } elseif (preg_match('/DNS Servers.*:\s*([0-9.]+)/i', $line, $m)) {
            $current['dns'][] = $m[1];
        } elseif (preg_match('/^\s+([0-9.]+)\s*$/', $line, $m) && !empty($current['dns'])) {
            $current['dns'][] = $m[1];
        }
    }
    $flush();
    if (!is_array($best)) {
        return $cached = $out;
    }
    $out['adapter'] = (string) ($best['name'] ?? '');
    $out['local_ip'] = (string) ($best['ip'] ?? '');
    $out['gateway'] = (string) ($best['gateway'] ?? '');
    $out['mask'] = (string) ($best['mask'] ?? '');
    $out['dhcp_server'] = (string) ($best['dhcp'] ?? '');
    $out['media_state'] = (string) ($best['media'] ?? '');
    $out['dns'] = array_values(array_unique(array_filter($best['dns'] ?? [])));
    pnet_runtime_cache_set('live_adapter', $out);
    return $cached = $out;
}

function pnet_router_settings(PDO $pdo): array
{
    $settings = [];
    foreach (pnet_router_setting_keys() as $key) {
        $settings[$key] = pnet_setting($pdo, $key, '');
    }
    return $settings;
}

function pnet_detect_lan_network(): array
{
    $fallback = ['prefix' => '', 'start' => 1, 'end' => 254, 'label' => 'local ARP table', 'gateway' => '', 'local_ip' => ''];
    $live = pnet_live_adapter_details();
    $ip = (string) ($live['local_ip'] ?? '');
    $gateway = (string) ($live['gateway'] ?? '');
    $mask = (string) ($live['mask'] ?? '255.255.255.0');
    if ($ip !== '' && pnet_is_lan_ipv4($ip)) {
        $parts = explode('.', $ip);
        return [
            'prefix' => $parts[0] . '.' . $parts[1] . '.' . $parts[2],
            'start' => 1,
            'end' => 254,
            'label' => $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24',
            'gateway' => $gateway,
            'local_ip' => $ip,
            'mask' => $mask,
        ];
    }
    if (PHP_OS_FAMILY !== 'Windows' || !pnet_can_exec()) {
        return $fallback;
    }
    $output = [];
    exec('ipconfig', $output);
    $current = [];
    $best = null;
    $flush = function () use (&$current, &$best): void {
        $ip = (string) ($current['ip'] ?? '');
        $mask = (string) ($current['mask'] ?? '');
        $gateway = (string) ($current['gateway'] ?? '');
        if ($ip !== '' && $gateway !== '' && pnet_is_lan_ipv4($ip) && $mask === '255.255.255.0') {
            $parts = explode('.', $ip);
            $best = [
                'prefix' => $parts[0] . '.' . $parts[1] . '.' . $parts[2],
                'start' => 1,
                'end' => 254,
                'label' => $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24',
                'gateway' => $gateway,
                'local_ip' => $ip,
            ];
        }
        $current = [];
    };
    foreach ($output as $line) {
        if (preg_match('/adapter\s+(.+):/i', $line)) {
            $flush();
            continue;
        }
        if (preg_match('/IPv4 Address.*:\s*([0-9.]+)/i', $line, $match)) {
            $current['ip'] = $match[1];
        } elseif (preg_match('/Subnet Mask.*:\s*([0-9.]+)/i', $line, $match)) {
            $current['mask'] = $match[1];
        } elseif (preg_match('/Default Gateway.*:\s*([0-9.]+)/i', $line, $match)) {
            $current['gateway'] = $match[1];
        }
    }
    $flush();
    return $best ?: $fallback;
}

function pnet_probe_lan(array $network): int
{
    $prefix = (string) ($network['prefix'] ?? '');
    if (!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}$/', $prefix)) {
        return 0;
    }
    $start = max(1, (int) ($network['start'] ?? 1));
    $end = min(254, (int) ($network['end'] ?? 254));
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'cmd /c "(for /L %i in (' . $start . ',1,' . $end . ') do @start /b cmd /c ping -n 1 -w 250 ' . $prefix . '.%i ^>nul) & ping -n 3 127.0.0.1 >nul"';
        exec($cmd);
        return $end - $start + 1;
    }
    $checked = 0;
    for ($i = $start; $i <= $end; $i++) {
        $ip = $prefix . '.' . $i;
        if (!pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $cmd = PHP_OS_FAMILY === 'Windows'
            ? 'ping -n 1 -w 120 ' . escapeshellarg($ip)
            : 'ping -c 1 -W 1 ' . escapeshellarg($ip);
        $out = [];
        $code = 1;
        exec($cmd, $out, $code);
        $checked++;
    }
    return $checked;
}

function pnet_read_arp_table(): array
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $output = [];
    $code = 1;
    exec('arp -a', $output, $code);
    if (!$output) {
        return $cached = [];
    }
    $found = [];
    foreach ($output as $line) {
        $ip = '';
        $mac = '';
        if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})/', $line, $match)) {
            $ip = $match[1];
            $mac = $match[2];
        } elseif (preg_match('/\((\d{1,3}(?:\.\d{1,3}){3})\).*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})/', $line, $match)) {
            $ip = $match[1];
            $mac = $match[2];
        }
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $mac = strtoupper(str_replace('-', ':', $mac));
        if (!preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/', $mac)) {
            continue;
        }
        if ($mac === 'FF:FF:FF:FF:FF:FF' || $mac === '00:00:00:00:00:00') {
            continue;
        }
        $found[$ip] = $mac;
        if (count($found) >= 200) {
            break;
        }
    }
    return $cached = $found;
}

function pnet_import_found_devices(PDO $pdo, array $found, int $probed, array $network = []): string
{
    return pnet_tx($pdo, function () use ($pdo, $found, $probed, $network) {
        $added = 0;
        $updated = 0;
        $now = pnet_now();
        $prefix = (string) ($network['prefix'] ?? '');
        $gatewayIp = (string) ($network['gateway'] ?? '');
        if ($gatewayIp === '' && $prefix !== '') {
            $gatewayIp = $prefix . '.1';
        }
        $sel = $pdo->prepare('SELECT id, name, mac, vendor, type FROM devices WHERE ip = ? OR (mac != \'\' AND mac = ?)');
        $upd = $pdo->prepare('UPDATE devices SET ip = ?, mac = CASE WHEN mac = \'\' THEN ? ELSE mac END, vendor = CASE WHEN vendor = \'\' THEN ? ELSE vendor END, type = CASE WHEN type = \'other\' AND ? != \'other\' THEN ? ELSE type END, name = CASE WHEN name LIKE \'Seen %\' OR name LIKE \'% device\' OR name = \'Gateway\' THEN ? ELSE name END, status = ?, last_seen = ?, updated_at = ? WHERE id = ?');
        $ins = $pdo->prepare('INSERT INTO devices (name, ip, mac, type, vendor, status, last_seen, trust, access_profile, bandwidth_limit, protected, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)');
        foreach ($found as $ip => $mac) {
            $ouiVendor = pnet_oui_vendor($mac);
            // Skip reverse DNS here — it is too slow during scans. Names come from OUI / vendor.
            $type = $ip === $gatewayIp ? 'router' : pnet_guess_device_type($ouiVendor, '');
            $brandInfo = pnet_detect_device_brand($mac, $ouiVendor, '', $type, '');
            $vendor = $ouiVendor !== '' ? $ouiVendor : $brandInfo['name'];
            $brand = $brandInfo['name'] !== 'Device' ? $brandInfo['name'] : $vendor;
            $name = $ip === $gatewayIp
                ? ($brand !== '' ? $brand . ' router' : 'Router')
                : pnet_device_auto_name($brand, $type, $ip);
            $sel->execute([$ip, $mac]);
            $row = $sel->fetch();
            if ($row) {
                $upd->execute([
                    $ip,
                    $mac,
                    $vendor,
                    $type,
                    $type,
                    $name,
                    'online',
                    $now,
                    $now,
                    (int) $row['id'],
                ]);
                $updated++;
                continue;
            }
            $notes = 'Discovered on this network';
            $ins->execute([$name, $ip, $mac, $type, $vendor, 'online', $now, 'unknown', 'normal', 0, 0, $notes, $now, $now]);
            $added++;
            if ($type !== 'router' && $ip !== $gatewayIp) {
                pnet_open_alert(
                    $pdo,
                    'New device on Wi‑Fi',
                    'medium',
                    $ip,
                    'device',
                    $name . ' (' . $ip . ') joined the network.',
                    'new-device:' . ($mac !== '' ? $mac : $ip)
                );
            }
        }
        if ($prefix !== '' && pnet_setting($pdo, 'lan_cidr', '') === '') {
            pnet_setting_set($pdo, 'lan_cidr', (string) ($network['label'] ?? ($prefix . '.0/24')));
        }
        // Brand sync without HTTP probe — probing during import caused Apache timeouts.
        pnet_sync_router_brand($pdo, false);
        pnet_ensure_gateway_device($pdo, $gatewayIp);
        $scan = $probed > 0 ? ' Checked ' . $probed . ' local addresses.' : '';
        $message = 'Added ' . $added . ' device' . ($added === 1 ? '' : 's') . '. Updated ' . $updated . '.' . $scan;
        pnet_log($pdo, 'discover', $message);
        return $message;
    });
}

function pnet_port_scan(PDO $pdo): string
{
    if (!pnet_can_exec()) {
        throw new RuntimeException('PHP exec is disabled, so port scanning cannot run.');
    }
    $devices = $pdo->query('SELECT id, name, ip FROM devices WHERE status = \'online\' OR status = \'unknown\'')->fetchAll();
    if (empty($devices)) {
        throw new RuntimeException('No devices to scan. Add devices first.');
    }
    $commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080];
    $results = [];
    foreach ($devices as $device) {
        $ip = (string) $device['ip'];
        if (!pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $openPorts = [];
        foreach ($commonPorts as $port) {
            if (pnet_check_port($ip, $port)) {
                $openPorts[] = $port;
            }
        }
        if (!empty($openPorts)) {
            $results[(string) $device['name']] = [
                'ip' => $ip,
                'ports' => $openPorts
            ];
        }
    }
    if (empty($results)) {
        return 'Port scan complete. No common ports found open on scanned devices.';
    }
    $message = 'Port scan complete. Found open ports on ' . count($results) . ' device(s): ';
    foreach ($results as $name => $info) {
        $message .= $name . ' (' . $info['ip'] . '): ' . implode(', ', $info['ports']) . '. ';
    }
    pnet_log($pdo, 'scan', 'Port scan completed. ' . $message);
    return $message;
}

function pnet_check_port(string $ip, int $port): bool
{
    if (!pnet_is_lan_ipv4($ip) || $port < 1 || $port > 65535) {
        return false;
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'powershell -Command "Test-NetConnection -ComputerName ' . escapeshellarg($ip) . ' -Port ' . $port . ' -InformationLevel Quiet -WarningAction SilentlyContinue" 2>&1';
    } else {
        $cmd = 'nc -z -w1 ' . escapeshellarg($ip) . ' ' . $port . ' 2>&1';
    }
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    return $code === 0;
}

function pnet_defender_scan(PDO $pdo): string
{
    return pnet_tx($pdo, function () use ($pdo) {
        $created = 0;
        $devices = $pdo->query('SELECT name, ip FROM devices')->fetchAll();
        $byIp = [];
        foreach ($devices as $device) {
            $ip = (string) $device['ip'];
            $byIp[$ip][] = (string) $device['name'];
        }
        foreach ($byIp as $ip => $names) {
            if (count($names) > 1) {
                $created += pnet_open_alert($pdo, 'Duplicate address ' . $ip, 'high', $ip, 'device', implode(', ', $names) . ' share this address.', 'dup:' . $ip);
            }
        }
        $blocked = $pdo->query("SELECT address FROM ips WHERE kind = 'blocked'")->fetchAll();
        foreach ($blocked as $row) {
            $ip = (string) $row['address'];
            if (!empty($byIp[$ip])) {
                $created += pnet_open_alert($pdo, 'Saved device uses a blocked address', 'high', $ip, 'policy', implode(', ', $byIp[$ip]) . ' uses an address marked blocked.', 'blocked:' . $ip);
            }
        }
        $cameras = $pdo->query("SELECT name FROM cameras WHERE ip = ''")->fetchAll();
        foreach ($cameras as $camera) {
            $created += pnet_open_alert($pdo, 'Camera missing an IP', 'medium', '', 'camera', (string) $camera['name'] . ' has no address.', 'camera-ip:' . (string) $camera['name']);
        }
        $rules = $pdo->query("SELECT name, source, destination, port FROM rules WHERE enabled = 1 AND action = 'allow' AND direction = 'inbound'")->fetchAll();
        foreach ($rules as $rule) {
            $source = strtolower((string) $rule['source']);
            $dest = strtolower((string) $rule['destination']);
            $port = trim((string) $rule['port']);
            if (($source === 'any' || $source === '*' || $source === '0.0.0.0/0') && ($dest === 'any' || $dest === '*' || $dest === '0.0.0.0/0') && $port === '') {
                $created += pnet_open_alert($pdo, 'Inbound allow-all rule', 'critical', '', 'policy', (string) $rule['name'] . ' allows all inbound traffic.', 'allow-all:' . (string) $rule['name']);
            }
        }
        $message = $created === 0 ? 'Defender check found no new issues.' : 'Defender check added ' . $created . ' item' . ($created === 1 ? '' : 's') . '.';
        pnet_log($pdo, 'defender', $message);
        return $message;
    });
}

function pnet_open_alert(PDO $pdo, string $title, string $severity, string $source, string $category, string $details, string $fingerprint): int
{
    $st = $pdo->prepare("SELECT id FROM alerts WHERE fingerprint = ? AND status != 'resolved'");
    $st->execute([$fingerprint]);
    if ($st->fetch()) {
        return 0;
    }
    $now = pnet_now();
    $pdo->prepare('INSERT INTO alerts (title, severity, source_ip, category, status, details, fingerprint, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')->execute([
        $title,
        $severity,
        $source,
        $category,
        'open',
        $details,
        $fingerprint,
        $now,
        $now,
    ]);
    return 1;
}

function pnet_clear_sample(PDO $pdo): string
{
    return pnet_tx($pdo, function () use ($pdo) {
        foreach (['devices', 'rules', 'sites', 'ips', 'alerts', 'cameras'] as $table) {
            $pdo->exec('DELETE FROM ' . $table . ' WHERE sample = 1');
        }
        pnet_setting_set($pdo, 'sample_loaded', '0');
        pnet_log($pdo, 'setup', 'Removed sample records.');
        return 'Sample records removed.';
    });
}

function pnet_state(PDO $pdo): array
{
    pnet_apply_block_rules($pdo);
    $devices = pnet_ints($pdo->query('SELECT * FROM devices')->fetchAll(), ['id', 'bandwidth_limit', 'protected', 'sample', 'ping_ms']);
    usort($devices, function ($a, $b) {
        $cmp = strcmp(pnet_ip_key((string) $a['ip']), pnet_ip_key((string) $b['ip']));
        return $cmp !== 0 ? $cmp : strcmp((string) $a['name'], (string) $b['name']);
    });
    $rules = pnet_ints($pdo->query('SELECT * FROM rules ORDER BY priority ASC, id ASC')->fetchAll(), ['id', 'priority', 'enabled', 'sample']);
    $sites = pnet_ints($pdo->query('SELECT * FROM sites ORDER BY domain ASC')->fetchAll(), ['id', 'enabled', 'sample']);
    $ips = pnet_ints($pdo->query('SELECT * FROM ips')->fetchAll(), ['id', 'sample']);
    usort($ips, function ($a, $b) {
        return strcmp(pnet_ip_key((string) $a['address']), pnet_ip_key((string) $b['address']));
    });
    $alerts = pnet_ints($pdo->query("SELECT * FROM alerts ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END, id DESC")->fetchAll(), ['id', 'sample']);
    $cameras = pnet_ints($pdo->query('SELECT * FROM cameras ORDER BY name COLLATE NOCASE ASC')->fetchAll(), ['id', 'sample']);
    $activity = $pdo->query('SELECT action, detail, created_at FROM activity ORDER BY id DESC LIMIT 15')->fetchAll();
    $portForwards = pnet_ints($pdo->query('SELECT * FROM port_forwards ORDER BY id DESC')->fetchAll(), ['id', 'enabled']);
    $dhcpReservations = pnet_ints($pdo->query('SELECT * FROM dhcp_reservations ORDER BY id DESC')->fetchAll(), ['id', 'enabled']);
    $macFilters = pnet_ints($pdo->query('SELECT * FROM mac_filters ORDER BY id DESC')->fetchAll(), ['id', 'enabled']);
    $accessSchedules = pnet_ints($pdo->query('SELECT * FROM access_schedules ORDER BY id DESC')->fetchAll(), ['id', 'enabled']);

    $countStatus = function (array $rows, string $status): int {
        $n = 0;
        foreach ($rows as $row) {
            if (($row['status'] ?? '') === $status) {
                $n++;
            }
        }
        return $n;
    };
    $countOn = function (array $rows): int {
        $n = 0;
        foreach ($rows as $row) {
            if ((int) ($row['enabled'] ?? 0) === 1) {
                $n++;
            }
        }
        return $n;
    };

    // Never HTTP-probe during state loads — Find devices / Connect handle probing.
    pnet_sync_router_brand($pdo, false);
    $router = pnet_router_settings($pdo);
    $router['access'] = pnet_router_access($pdo);
    $network = pnet_network_info();
    $wifi = pnet_wifi_info();
    $devices = pnet_enrich_devices_with_brands(
        $devices,
        (string) ($router['router_brand'] ?? ''),
        (string) ($network['gateway'] ?? '')
    );
    $agentMap = pnet_device_agents_map($pdo);
    foreach ($devices as &$device) {
        $id = (int) ($device['id'] ?? 0);
        $device['has_agent'] = isset($agentMap[$id]) ? 1 : 0;
        $device['agent_last_seen'] = isset($agentMap[$id]) ? (string) ($agentMap[$id]['last_seen'] ?? '') : '';
    }
    unset($device);

    return [
        'settings' => [
            'home_name' => pnet_setting($pdo, 'home_name', 'My home'),
            'lan_cidr' => pnet_setting($pdo, 'lan_cidr', ''),
            'sample_loaded' => pnet_setting($pdo, 'sample_loaded', '0'),
            'ad_block_enabled' => pnet_setting($pdo, 'ad_block_enabled', '0'),
            'ad_block_updated' => pnet_setting($pdo, 'ad_block_updated', ''),
            'ad_block_source' => 'AdGuard DNS filter',
            'adult_block_enabled' => pnet_setting($pdo, 'adult_block_enabled', '0'),
            'adult_block_updated' => pnet_setting($pdo, 'adult_block_updated', ''),
            'adult_block_source' => 'Block List Project adult list',
            'social_block_enabled' => pnet_setting($pdo, 'social_block_enabled', '0'),
            'games_block_enabled' => pnet_setting($pdo, 'games_block_enabled', '0'),
            'streaming_block_enabled' => pnet_setting($pdo, 'streaming_block_enabled', '0'),
            'bedtime_enabled' => pnet_setting($pdo, 'bedtime_enabled', '0'),
            'bedtime_start' => pnet_setting($pdo, 'bedtime_start', '22:00'),
            'bedtime_end' => pnet_setting($pdo, 'bedtime_end', '07:00'),
            'bedtime_targets' => pnet_setting($pdo, 'bedtime_targets', 'social,games,streaming'),
            'bedtime_active' => pnet_bedtime_active($pdo) ? '1' : '0',
            'hosts_applied' => pnet_setting($pdo, 'hosts_applied', '0'),
            'hosts_applied_at' => pnet_setting($pdo, 'hosts_applied_at', ''),
            'hosts_applied_count' => pnet_setting($pdo, 'hosts_applied_count', '0'),
            'dns_blocker_enabled' => pnet_setting($pdo, 'dns_blocker_enabled', '0'),
            'dns_blocker_host' => pnet_setting($pdo, 'dns_blocker_host', ''),
            'dns_blocker_updated' => pnet_setting($pdo, 'dns_blocker_updated', ''),
            'dns_blocker_sync_pending' => pnet_setting($pdo, 'dns_blocker_sync_pending', '0'),
        ],
        'router' => $router,
        'wifi' => $wifi,
        'network' => $network,
        'devices' => $devices,
        'rules' => $rules,
        'sites' => $sites,
        'ips' => $ips,
        'alerts' => $alerts,
        'cameras' => $cameras,
        'port_forwards' => $portForwards,
        'dhcp_reservations' => $dhcpReservations,
        'mac_filters' => $macFilters,
        'access_schedules' => $accessSchedules,
        'block_allows' => pnet_block_allow_rows($pdo),
        'activity' => $activity,
        'counts' => [
            'devices' => count($devices),
            'devices_online' => $countStatus($devices, 'online'),
            'rules' => count($rules),
            'rules_on' => $countOn($rules),
            'sites' => count($sites),
            'sites_on' => $countOn($sites),
            'ads_on' => pnet_adguard_domain_count($pdo),
            'adult_on' => pnet_adult_domain_count($pdo),
            'ips' => count($ips),
            'ips_blocked' => count(array_filter($ips, function ($row) {
                return ($row['kind'] ?? '') === 'blocked';
            })),
            'alerts_open' => count(array_filter($alerts, function ($row) {
                return ($row['status'] ?? '') === 'open';
            })),
            'cameras' => count($cameras),
            'cameras_online' => $countStatus($cameras, 'online'),
            'port_forwards' => count($portForwards),
            'port_forwards_on' => $countOn($portForwards),
            'dhcp_reservations' => count($dhcpReservations),
            'mac_filters' => count($macFilters),
            'access_schedules' => count($accessSchedules),
        ],
    ];
}

function pnet_ints(array $rows, array $fields): array
{
    return array_map(function ($row) use ($fields) {
        foreach ($fields as $field) {
            if (array_key_exists($field, $row)) {
                $row[$field] = (int) $row[$field];
            }
        }
        return $row;
    }, $rows);
}

function pnet_ip_key(string $ip): string
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        return sprintf('%03d.%03d.%03d.%03d', (int) $parts[0], (int) $parts[1], (int) $parts[2], (int) $parts[3]);
    }
    return $ip;
}

function pnet_export_hosts(PDO $pdo): string
{
    $lines = [
        '# PNet block list',
        '# ' . pnet_setting($pdo, 'home_name', 'My home'),
        '# Generated ' . pnet_now() . ' UTC',
        '# Includes the AdGuard DNS filter when ad blocker is on.',
        '# Adult sites are enforced by the network blocker, not this hosts file.',
        '# Use Apply on this PC in PNet to enforce on Windows, or merge into DNS / Pi-hole.',
        '',
    ];
    if (pnet_setting($pdo, 'ad_block_enabled', '0') === '1') {
        $cache = pnet_adguard_cache_load(false);
        if ($cache) {
            $lines[] = '# ' . ($cache['title'] ?? 'AdGuard DNS filter') . ' (' . ($cache['count'] ?? 0) . ' domains, updated ' . ($cache['fetched_at'] ?? 'unknown') . ')';
            $lines[] = '# ' . ($cache['source'] ?? pnet_adguard_filter_url());
            $lines[] = '';
        }
    }
    $domains = pnet_blocked_domains($pdo);
    if (!$domains) {
        $lines[] = '# No enabled domains.';
    }
    foreach ($domains as $domain) {
        $lines[] = '0.0.0.0 ' . $domain;
    }
    $lines[] = '';
    return implode("\n", $lines);
}

function pnet_export_policy(PDO $pdo): string
{
    $state = pnet_state($pdo);
    $lines = [
        'PNet policy',
        $state['settings']['home_name'],
        'Network: ' . ($state['settings']['lan_cidr'] !== '' ? $state['settings']['lan_cidr'] : 'not set'),
        'Generated ' . pnet_now() . ' UTC',
        '',
        'This is a record of the policy stored in PNet. Your router or firewall is what enforces it.',
        '',
        'Devices',
    ];
    if (!$state['devices']) {
        $lines[] = '- No devices.';
    }
    foreach ($state['devices'] as $device) {
        $cap = (int) ($device['bandwidth_limit'] ?? 0) > 0 ? (string) $device['bandwidth_limit'] . ' Kbps' : 'none';
        $lines[] = '- ' . $device['name'] . ' ' . $device['ip'] . ' trust=' . ($device['trust'] ?? 'unknown') . ' access=' . ($device['access_profile'] ?? 'normal') . ' bandwidth=' . $cap . ((int) ($device['protected'] ?? 0) === 1 ? ' protected' : '');
    }
    $lines[] = '';
    $lines[] = 'Firewall';
    if (!$state['rules']) {
        $lines[] = '- No rules.';
    }
    foreach ($state['rules'] as $rule) {
        $port = $rule['port'] !== '' ? $rule['port'] : 'any';
        $lines[] = '- [' . ($rule['enabled'] === 1 ? 'on' : 'off') . '] ' . $rule['priority'] . ' ' . $rule['action'] . ' ' . $rule['direction'] . ' ' . $rule['protocol'] . ' ' . $rule['source'] . ' -> ' . $rule['destination'] . ' port ' . $port . ' (' . $rule['name'] . ')';
    }
    $lines[] = '';
    $lines[] = 'Adult sites';
    if (($state['settings']['adult_block_enabled'] ?? '0') === '1') {
        $lines[] = '- On (' . number_format((int) ($state['counts']['adult_on'] ?? 0)) . ' domains, network blocker). Safe search on.';
    } else {
        $lines[] = '- Off.';
    }
    $lines[] = '';
    $lines[] = 'Blocked websites';
    $blockedSites = array_filter($state['sites'], function ($site) {
        return (int) $site['enabled'] === 1;
    });
    if (!$blockedSites) {
        $lines[] = '- None enabled.';
    }
    foreach ($blockedSites as $site) {
        $lines[] = '- ' . $site['domain'] . ' (' . $site['category'] . ')';
    }
    $lines[] = '';
    $lines[] = 'Blocked addresses';
    $blockedIps = array_filter($state['ips'], function ($ip) {
        return ($ip['kind'] ?? '') === 'blocked';
    });
    if (!$blockedIps) {
        $lines[] = '- None.';
    }
    foreach ($blockedIps as $ip) {
        $lines[] = '- ' . $ip['address'] . ' (' . $ip['label'] . ')';
    }
    $lines[] = '';
    $lines[] = 'Open defender items';
    $open = array_filter($state['alerts'], function ($alert) {
        return ($alert['status'] ?? '') === 'open';
    });
    if (!$open) {
        $lines[] = '- None.';
    }
    foreach ($open as $alert) {
        $lines[] = '- ' . strtoupper((string) $alert['severity']) . ' ' . $alert['title'];
    }
    $lines[] = '';
    return implode("\n", $lines);
}

function pnet_export_backup(PDO $pdo): string
{
    $state = pnet_state($pdo);
    $payload = [
        'exported_at' => pnet_now(),
        'home_name' => pnet_setting($pdo, 'home_name', 'My home'),
        'lan_cidr' => pnet_setting($pdo, 'lan_cidr', ''),
        'devices' => $state['devices'],
        'rules' => $state['rules'],
        'sites' => $state['sites'],
        'ips' => $state['ips'],
        'alerts' => $state['alerts'],
        'cameras' => $state['cameras'],
        'activity' => $state['activity'],
    ];
    return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function pnet_import_backup(PDO $pdo, array $data): string
{
    $value = $data['backup'] ?? $data['data'] ?? null;
    if (!is_string($value) || trim($value) === '') {
        throw new InvalidArgumentException('No backup data was provided.');
    }
    $decoded = json_decode($value, true);
    if (!is_array($decoded)) {
        throw new InvalidArgumentException('The backup file is not valid JSON.');
    }

    return pnet_tx($pdo, function () use ($pdo, $decoded) {
        $tables = ['activity', 'alerts', 'cameras', 'ips', 'sites', 'rules', 'devices'];
        foreach ($tables as $table) {
            $pdo->exec('DELETE FROM ' . $table);
        }

        $home = isset($decoded['home_name']) ? pnet_text((string) $decoded['home_name'], 60, 'Home name', true) : 'My home';
        $lan = isset($decoded['lan_cidr']) ? pnet_text((string) $decoded['lan_cidr'], 40, 'Network label', false) : '';
        pnet_setting_set($pdo, 'home_name', $home);
        pnet_setting_set($pdo, 'lan_cidr', $lan);

        $seed = [
            'devices' => ['name', 'ip', 'mac', 'type', 'vendor', 'status', 'last_seen', 'trust', 'access_profile', 'bandwidth_limit', 'protected', 'notes', 'sample', 'created_at', 'updated_at'],
            'rules' => ['name', 'direction', 'action', 'protocol', 'source', 'destination', 'port', 'priority', 'enabled', 'notes', 'sample', 'created_at', 'updated_at'],
            'sites' => ['domain', 'category', 'enabled', 'notes', 'sample', 'created_at', 'updated_at'],
            'ips' => ['label', 'address', 'kind', 'mac', 'notes', 'sample', 'created_at', 'updated_at'],
            'alerts' => ['title', 'severity', 'source_ip', 'category', 'status', 'details', 'fingerprint', 'sample', 'created_at', 'updated_at'],
            'cameras' => ['name', 'ip', 'location', 'snapshot_url', 'stream_url', 'status', 'notes', 'sample', 'created_at', 'updated_at'],
            'activity' => ['action', 'detail', 'created_at'],
        ];

        foreach ($seed as $table => $columns) {
            $rows = $decoded[$table] ?? [];
            if (!is_array($rows)) {
                continue;
            }
            if ($rows === []) {
                continue;
            }
            $placeholders = implode(', ', array_fill(0, count($columns), '?'));
            $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ') VALUES (' . $placeholders . ')';
            $st = $pdo->prepare($sql);
            foreach ($rows as $row) {
                $values = [];
                foreach ($columns as $column) {
                    $values[] = array_key_exists($column, $row) ? $row[$column] : '';
                }
                $st->execute($values);
            }
        }

        pnet_log($pdo, 'backup', 'Restored a backup file.');
        return 'Backup restored.';
    });
}

function pnet_fail(int $code, string $message): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function pnet_ok(PDO $pdo, string $message): void
{
    $payload = [
        'ok' => true,
        'message' => $message,
        'state' => pnet_state($pdo),
    ];
    if (!empty($_SESSION['pnet_api_extra']) && is_array($_SESSION['pnet_api_extra'])) {
        $payload = array_merge($payload, $_SESSION['pnet_api_extra']);
        unset($_SESSION['pnet_api_extra']);
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
