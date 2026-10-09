<?php
declare(strict_types=1);

function pnet_router_traffic_state_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.router_traffic_state.json';
}

function pnet_router_traffic_read_state(): array
{
    $path = pnet_router_traffic_state_path();
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

function pnet_router_traffic_write_state(array $state): void
{
    $path = pnet_router_traffic_state_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($path, json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function pnet_router_http_raw(PDO $pdo, string $path, int $timeout = 6): ?string
{
    $access = pnet_router_access($pdo);
    $base = rtrim((string) ($access['admin_url'] ?? ''), '/');
    if ($base === '' || empty($access['has_credentials'])) {
        return null;
    }
    $login = pnet_router_get_login($pdo);
    $user = (string) ($login['username'] ?? '');
    $pass = (string) ($login['password'] ?? '');
    if ($user === '' || $pass === '') {
        return null;
    }
    $url = $base . $path;
    $auth = base64_encode($user . ':' . $pass);
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => $timeout,
            'ignore_errors' => true,
            'header' => "Authorization: Basic {$auth}\r\nUser-Agent: PNet/1.0\r\nAccept: application/json,text/plain,*/*\r\nConnection: close\r\n",
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    return is_string($body) && $body !== '' ? $body : null;
}

function pnet_router_cookie_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.router_cookies.txt';
}

function pnet_router_curl_available(): bool
{
    return function_exists('curl_init');
}

/**
 * @return array{ok:bool,body:string,code:int,error:string}
 */
function pnet_router_session_request(string $url, string $method = 'GET', array $form = [], int $timeout = 8, array $extraHeaders = []): array
{
    if (!pnet_router_curl_available()) {
        return ['ok' => false, 'body' => '', 'code' => 0, 'error' => 'curl_missing'];
    }
    $cookie = pnet_router_cookie_path();
    $dir = dirname($cookie);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $ch = curl_init($url);
    $headers = [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PNet/1.0',
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection: close',
    ];
    foreach ($extraHeaders as $h) {
        if (is_string($h) && $h !== '') {
            $headers[] = $h;
        }
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_0,
        CURLOPT_COOKIEJAR => $cookie,
        CURLOPT_COOKIEFILE => $cookie,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
    ]);
    if (strtoupper($method) === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        return ['ok' => false, 'body' => '', 'code' => $code, 'error' => $err !== '' ? $err : 'request_failed'];
    }
    return ['ok' => $code >= 200 && $code < 400, 'body' => (string) $body, 'code' => $code, 'error' => ''];
}

function pnet_zte_parse_speed_to_bps(string $val): int
{
    $val = trim(html_entity_decode($val, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    if ($val === '' || $val === '-' || strcasecmp($val, 'N/A') === 0) {
        return 0;
    }
    if (preg_match('/^\d+$/', $val)) {
        // Many ZTE pages already report bit/s or byte totals as integers.
        $n = (int) $val;
        return $n > 0 && $n < 100000000000 ? $n : 0;
    }
    if (!preg_match('/([\d.]+)\s*([KMG]?)\s*(?:b|bit|bps|B|Byte)?s?\/?s?/i', $val, $m)) {
        return 0;
    }
    $n = (float) $m[1];
    $unit = strtoupper($m[2] ?? '');
    $mult = 1.0;
    if ($unit === 'K') {
        $mult = 1000.0;
    } elseif ($unit === 'M') {
        $mult = 1000000.0;
    } elseif ($unit === 'G') {
        $mult = 1000000000.0;
    }
    // Prefer treating as bits/s for rate strings like "1.2 Mbps".
    if (preg_match('/\b[bB](?:it)?s?\b|\bbps\b/i', $val) && !preg_match('/\b[Bb]yte/i', $val)) {
        return (int) max(0, round($n * $mult));
    }
    // Byte rates → bits.
    return (int) max(0, round($n * $mult * 8));
}

function pnet_zte_parse_instances(string $xmlOrHtml): array
{
    $samples = [];
    // Vue/menu XML: <ParaName>IPAddress</ParaName><ParaValue>...</ParaValue>
    if (stripos($xmlOrHtml, '<ParaName>') !== false || stripos($xmlOrHtml, 'OBJ_') !== false) {
        if (preg_match_all('/<(?:Instance|OBJ_[A-Z0-9_]+(?:\s[^>]*)?)>(.*?)<\/(?:Instance|OBJ_[A-Z0-9_]+)>/is', $xmlOrHtml, $blocks)) {
            foreach ($blocks[1] as $block) {
                $fields = [];
                if (preg_match_all('/<ParaName>([^<]+)<\/ParaName>\s*<ParaValue>([^<]*)<\/ParaValue>/i', $block, $pm, PREG_SET_ORDER)) {
                    foreach ($pm as $row) {
                        $fields[trim($row[1])] = trim(html_entity_decode($row[2], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                    }
                }
                $ip = (string) ($fields['IPAddress'] ?? $fields['IpAddr'] ?? $fields['ip'] ?? '');
                if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
                    continue;
                }
                $down = 0;
                $up = 0;
                foreach (['DownRate', 'RxRate', 'DownloadRate', 'rx_rate'] as $k) {
                    if (!empty($fields[$k])) {
                        $down = pnet_zte_parse_speed_to_bps((string) $fields[$k]);
                        break;
                    }
                }
                foreach (['UpRate', 'TxRate', 'UploadRate', 'tx_rate'] as $k) {
                    if (!empty($fields[$k])) {
                        $up = pnet_zte_parse_speed_to_bps((string) $fields[$k]);
                        break;
                    }
                }
                $bytesIn = (int) ($fields['DownThroughput'] ?? $fields['RxBytes'] ?? $fields['BytesReceived'] ?? 0);
                $bytesOut = (int) ($fields['UpThroughput'] ?? $fields['TxBytes'] ?? $fields['BytesSent'] ?? 0);
                // Some firmwares store throughput in KB.
                if ($bytesIn > 0 && $bytesIn < 1000000000 && isset($fields['DownThroughput'])) {
                    $bytesIn = (int) round($bytesIn * 1024);
                }
                if ($bytesOut > 0 && $bytesOut < 1000000000 && isset($fields['UpThroughput'])) {
                    $bytesOut = (int) round($bytesOut * 1024);
                }
                $samples[$ip] = [
                    'bytes_in' => $bytesIn,
                    'bytes_out' => $bytesOut,
                    'down_bps' => $down,
                    'up_bps' => $up,
                    'name' => (string) ($fields['HostName'] ?? $fields['AliasName'] ?? $fields['MACAddress'] ?? ''),
                    'has_rate' => ($down + $up) > 0,
                ];
            }
        }
    }

    // Classic .gch pages: Transfer_meaning('IPAddress0','192.168.1.2');
    if (preg_match_all("/Transfer_meaning\\('([^']+)'\\s*,\\s*'([^']*)'\\)/i", $xmlOrHtml, $tm, PREG_SET_ORDER)) {
        $indexed = [];
        foreach ($tm as $row) {
            $key = $row[1];
            $val = html_entity_decode($row[2], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if (preg_match('/^(IPAddress|IpAddr|HostName|MACAddress|AliasName|RxRate|TxRate|DownRate|UpRate|RxBytes|TxBytes|BytesReceived|BytesSent)(\\d+)$/i', $key, $km)) {
                $field = strtolower($km[1]);
                $idx = (int) $km[2];
                $indexed[$idx][$field] = $val;
            }
        }
        foreach ($indexed as $row) {
            $ip = (string) ($row['ipaddress'] ?? $row['ipaddr'] ?? '');
            if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
                continue;
            }
            $down = pnet_zte_parse_speed_to_bps((string) ($row['downrate'] ?? $row['rxrate'] ?? ''));
            $up = pnet_zte_parse_speed_to_bps((string) ($row['uprate'] ?? $row['txrate'] ?? ''));
            $samples[$ip] = [
                'bytes_in' => (int) ($row['rxbytes'] ?? $row['bytesreceived'] ?? 0),
                'bytes_out' => (int) ($row['txbytes'] ?? $row['bytessent'] ?? 0),
                'down_bps' => $down,
                'up_bps' => $up,
                'name' => (string) ($row['hostname'] ?? $row['aliasname'] ?? $row['macaddress'] ?? ''),
                'has_rate' => ($down + $up) > 0,
            ];
        }
    }

    // Fallback: scrape IPv4 + nearby hostname from HTML tables.
    if (!$samples && preg_match_all('/\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/', $xmlOrHtml, $ips)) {
        foreach (array_unique($ips[1]) as $ip) {
            if (!pnet_is_lan_ipv4($ip) || preg_match('/\.(0|1|255)$/', $ip)) {
                continue;
            }
            $samples[$ip] = [
                'bytes_in' => 0,
                'bytes_out' => 0,
                'down_bps' => 0,
                'up_bps' => 0,
                'name' => '',
                'has_rate' => false,
            ];
        }
    }
    return $samples;
}

function pnet_zte_login_classic(string $base, string $user, string $pass): bool
{
    @unlink(pnet_router_cookie_path());
    $home = pnet_router_session_request($base . '/', 'GET');
    if ($home['body'] === '') {
        return false;
    }
    $token = '1';
    if (preg_match('/Frm_Logintoken["\'\)\.value\s=]+["\'](\d+)["\']/i', $home['body'], $m)) {
        $token = $m[1];
    } elseif (preg_match('/name=["\']Frm_Logintoken["\'][^>]*value=["\']([^"\']*)["\']/i', $home['body'], $m) && $m[1] !== '') {
        $token = $m[1];
    }
    $login = pnet_router_session_request($base . '/', 'POST', [
        'frashnum' => '',
        'action' => 'login',
        'Frm_Logintoken' => $token,
        'Username' => $user,
        'Password' => $pass,
    ]);
    if (!$login['ok'] && $login['code'] === 0) {
        return false;
    }
    // Success usually redirects away from the login form.
    $check = pnet_router_session_request($base . '/template.gch', 'GET');
    if ($check['ok'] && stripos($check['body'], 'Frm_Password') === false && stripos($check['body'], 'session_token') !== false) {
        return true;
    }
    $status = pnet_router_session_request($base . '/getpage.gch?pid=1002&nextpage=status_dev_info_t.gch', 'GET');
    return $status['ok'] && stripos($status['body'], 'Frm_Password') === false && strlen($status['body']) > 400;
}

function pnet_zte_login_modern(string $base, string $user, string $pass): bool
{
    @unlink(pnet_router_cookie_path());
    $entry = pnet_router_session_request($base . '/?_type=loginData&_tag=login_entry', 'GET');
    if ($entry['body'] === '') {
        return false;
    }
    $sessionToken = '';
    if (preg_match('/"_sessionTOKEN"\s*:\s*"([^"]+)"/', $entry['body'], $m)) {
        $sessionToken = $m[1];
    } elseif (preg_match('/sess_token["\']?\s*[:=]\s*["\']([^"\']+)/i', $entry['body'], $m)) {
        $sessionToken = $m[1];
    }
    $tok = pnet_router_session_request($base . '/?_type=loginData&_tag=login_token&_=' . (int) round(microtime(true) * 1000), 'GET');
    $loginToken = '';
    if (preg_match('/<ajax_response_xml_root>([^<]+)<\/ajax_response_xml_root>/i', $tok['body'], $m)) {
        $loginToken = trim($m[1]);
    } else {
        $loginToken = trim(strip_tags($tok['body']));
    }
    if ($loginToken === '') {
        return false;
    }
    $hash = hash('sha256', $pass . $loginToken);
    $login = pnet_router_session_request($base . '/?_type=loginData&_tag=login_entry', 'POST', [
        'action' => 'login',
        'Username' => $user,
        'Password' => $hash,
        '_sessionTOKEN' => $sessionToken,
    ]);
    if (!$login['ok']) {
        return false;
    }
    $json = json_decode($login['body'], true);
    if (is_array($json) && !empty($json['loginErrMsg'])) {
        return false;
    }
    if (is_array($json) && isset($json['lockingTime']) && (int) $json['lockingTime'] !== 0) {
        return false;
    }
    return true;
}

function pnet_zte_login(PDO $pdo): bool
{
    $access = pnet_router_access($pdo);
    $base = rtrim((string) ($access['admin_url'] ?? ''), '/');
    $login = pnet_router_get_login($pdo);
    $user = (string) ($login['username'] ?? '');
    $pass = (string) ($login['password'] ?? '');
    if ($base === '' || $user === '' || $pass === '') {
        return false;
    }
    // F627 and older F6xx use classic form login.
    if (pnet_zte_login_classic($base, $user, $pass)) {
        return true;
    }
    return pnet_zte_login_modern($base, $user, $pass);
}

function pnet_router_traffic_zte(PDO $pdo, float $now): array
{
    if (!pnet_router_curl_available()) {
        return ['clients' => [], 'source' => '', 'error' => 'curl_missing', 'has_rates' => false];
    }
    $access = pnet_router_access($pdo);
    $base = rtrim((string) ($access['admin_url'] ?? ''), '/');
    if ($base === '') {
        return ['clients' => [], 'source' => '', 'error' => 'no_url', 'has_rates' => false];
    }
    if (!pnet_zte_login($pdo)) {
        return ['clients' => [], 'source' => '', 'error' => 'login_failed', 'has_rates' => false];
    }

    $paths = [
        '/?_type=vueData&_tag=vue_client_data&_=' . (int) round($now * 1000),
        '/?_type=menuData&_tag=wlan_client_stat_lua.lua&_=' . (int) round($now * 1000),
        '/?_type=menuData&_tag=accessdev_ssiddev_lua.lua&_=' . (int) round($now * 1000),
        '/?_type=menuData&_tag=accessdev_landevs_lua.lua&_=' . (int) round($now * 1000),
        '/getpage.gch?pid=1002&nextpage=status_user_info_t.gch',
        '/getpage.gch?pid=1002&nextpage=status_lan_info_t.gch',
        '/getpage.gch?pid=1002&nextpage=status_dev_info_t.gch',
        '/getpage.gch?pid=1002&nextpage=net_dhcpv4_t.gch',
        '/getpage.gch?pid=1002&nextpage=wlan_assoc_t.gch',
        '/getpage.gch?pid=1002&nextpage=net_wlan_assoc_t.gch',
        '/getpage.gch?pid=1002&nextpage=pon_status_link_info_t.gch',
    ];
    $merged = [];
    $hasRates = false;
    foreach ($paths as $path) {
        $res = pnet_router_session_request($base . $path, 'GET');
        if ($res['body'] === '' || stripos($res['body'], 'Frm_Password') !== false) {
            continue;
        }
        $parsed = pnet_zte_parse_instances($res['body']);
        foreach ($parsed as $ip => $sample) {
            if (!isset($merged[$ip]) || (!empty($sample['has_rate']) && empty($merged[$ip]['has_rate']))) {
                $merged[$ip] = $sample;
            } else {
                if ($merged[$ip]['name'] === '' && $sample['name'] !== '') {
                    $merged[$ip]['name'] = $sample['name'];
                }
                if (empty($merged[$ip]['has_rate']) && !empty($sample['has_rate'])) {
                    $merged[$ip] = $sample;
                }
            }
            if (!empty($sample['has_rate'])) {
                $hasRates = true;
            }
        }
        // Stop early once we have several clients with rates.
        if ($hasRates && count($merged) >= 2) {
            break;
        }
    }

    if (!$merged) {
        return ['clients' => [], 'source' => '', 'error' => 'no_clients', 'has_rates' => false];
    }

    // Prefer live rates when firmware provides them; otherwise derive from byte counters.
    $withCounters = [];
    $out = [];
    foreach ($merged as $ip => $sample) {
        if (!empty($sample['has_rate'])) {
            $out[$ip] = [
                'down_bps' => (int) ($sample['down_bps'] ?? 0),
                'up_bps' => (int) ($sample['up_bps'] ?? 0),
                'bytes_in' => (int) ($sample['bytes_in'] ?? 0),
                'bytes_out' => (int) ($sample['bytes_out'] ?? 0),
                'name' => (string) ($sample['name'] ?? ''),
            ];
        } elseif (((int) ($sample['bytes_in'] ?? 0) + (int) ($sample['bytes_out'] ?? 0)) > 0) {
            $withCounters[$ip] = $sample;
        } else {
            $out[$ip] = [
                'down_bps' => 0,
                'up_bps' => 0,
                'bytes_in' => 0,
                'bytes_out' => 0,
                'name' => (string) ($sample['name'] ?? ''),
            ];
        }
    }
    if ($withCounters) {
        $rated = pnet_router_traffic_rates($withCounters, $now);
        foreach ($rated as $ip => $row) {
            $out[$ip] = $row;
            if (((int) $row['down_bps'] + (int) $row['up_bps']) > 0) {
                $hasRates = true;
            }
        }
    }

    return [
        'clients' => $out,
        'source' => 'zte',
        'error' => '',
        'has_rates' => $hasRates,
    ];
}

function pnet_router_traffic_rates(array $samples, float $now): array
{
    $prev = pnet_router_traffic_read_state();
    $next = ['ts' => $now, 'clients' => []];
    $out = [];
    foreach ($samples as $ip => $sample) {
        if (!pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $rx = (int) ($sample['bytes_in'] ?? 0);
        $tx = (int) ($sample['bytes_out'] ?? 0);
        $next['clients'][$ip] = ['bytes_in' => $rx, 'bytes_out' => $tx];
        $downBps = 0;
        $upBps = 0;
        if (isset($prev['clients'][$ip], $prev['ts'])) {
            $dt = max(0.5, $now - (float) $prev['ts']);
            $prx = (int) ($prev['clients'][$ip]['bytes_in'] ?? 0);
            $ptx = (int) ($prev['clients'][$ip]['bytes_out'] ?? 0);
            if ($rx >= $prx) {
                $downBps = (int) max(0, (($rx - $prx) * 8) / $dt);
            }
            if ($tx >= $ptx) {
                $upBps = (int) max(0, (($tx - $ptx) * 8) / $dt);
            }
        }
        $out[$ip] = [
            'down_bps' => $downBps,
            'up_bps' => $upBps,
            'bytes_in' => $rx,
            'bytes_out' => $tx,
            'name' => (string) ($sample['name'] ?? ''),
        ];
    }
    pnet_router_traffic_write_state($next);
    return $out;
}

function pnet_tplink_session_path(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . '.tplink_session.json';
}

function pnet_tplink_auth_header(string $user, string $pass): string
{
    // Classic TP-Link: Cookie Authorization=Basic%20base64(user:md5(password))
    $token = base64_encode($user . ':' . md5($pass));
    return 'Cookie: Authorization=Basic%20' . rawurlencode($token);
}

function pnet_tplink_cookie_header(string $host): string
{
    $path = pnet_router_cookie_path();
    if (!is_file($path)) {
        return '';
    }
    $pairs = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (str_starts_with($line, '#HttpOnly_')) {
            $line = substr($line, 10);
        } elseif ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = explode("\t", $line);
        if (count($parts) < 7) {
            continue;
        }
        if ($parts[0] !== $host) {
            continue;
        }
        $pairs[$parts[5]] = $parts[6];
    }
    $out = [];
    foreach ($pairs as $name => $value) {
        $out[] = $name . '=' . $value;
    }
    return implode('; ', $out);
}

function pnet_tplink_store_set_cookie(string $host, string $setCookie): void
{
    if (!preg_match('/^\s*([^=;\s]+)=([^;]*)/', $setCookie, $m)) {
        return;
    }
    $name = $m[1];
    $value = $m[2];
    $path = pnet_router_cookie_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $lines = is_file($path) ? (file($path, FILE_IGNORE_NEW_LINES) ?: []) : ['# Netscape HTTP Cookie File'];
    $kept = [];
    $replaced = false;
    foreach ($lines as $line) {
        $cookieLine = $line;
        if (str_starts_with($cookieLine, '#HttpOnly_')) {
            $cookieLine = substr($cookieLine, 10);
        } elseif ($line === '' || str_starts_with($line, '#')) {
            $kept[] = $line;
            continue;
        }
        $parts = explode("\t", $cookieLine);
        if (count($parts) >= 7 && $parts[5] === $name && $parts[0] === $host) {
            $replaced = true;
            if (strcasecmp($value, 'deleted') === 0) {
                continue;
            }
            $parts[6] = $value;
            $kept[] = '#HttpOnly_' . implode("\t", $parts);
            continue;
        }
        $kept[] = $line;
    }
    if (!$replaced && strcasecmp($value, 'deleted') !== 0) {
        $kept[] = '#HttpOnly_' . $host . "\tFALSE\t/\tFALSE\t0\t" . $name . "\t" . $value;
    }
    file_put_contents($path, implode("\n", $kept) . "\n", LOCK_EX);
}

function pnet_tplink_decode_chunked(string $body): string
{
    $out = '';
    $rest = $body;
    while ($rest !== '') {
        $nl = strpos($rest, "\n");
        if ($nl === false) {
            return '';
        }
        $sizeLine = trim(substr($rest, 0, $nl));
        if (!preg_match('/^([0-9A-Fa-f]+)/', $sizeLine, $m)) {
            return '';
        }
        $size = hexdec($m[1]);
        $rest = substr($rest, $nl + 1);
        if ($size === 0) {
            return $out;
        }
        if (strlen($rest) < $size) {
            return '';
        }
        $out .= substr($rest, 0, $size);
        $rest = substr($rest, $size);
        if (str_starts_with($rest, "\r\n")) {
            $rest = substr($rest, 2);
        } elseif (str_starts_with($rest, "\n")) {
            $rest = substr($rest, 1);
        }
    }
    return $out;
}

/**
 * HTTP/1.0 socket client. This firmware answers cgi_gdpr with a chunked body
 * curl rejects, so the DHCP list never arrives.
 *
 * @return array{ok:bool,body:string,code:int,headers:list<string>,error:string}
 */
function pnet_tplink_http_socket(string $url, string $method = 'GET', string $rawBody = '', array $extraHeaders = [], int $timeout = 10): array
{
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['host'])) {
        return ['ok' => false, 'body' => '', 'code' => 0, 'headers' => [], 'error' => 'bad_url'];
    }
    $host = (string) $parts['host'];
    $scheme = strtolower((string) ($parts['scheme'] ?? 'http'));
    $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
    $path = (string) ($parts['path'] ?? '/');
    if (!empty($parts['query'])) {
        $path .= '?' . $parts['query'];
    }
    $remote = ($scheme === 'https' ? 'ssl://' : '') . $host . ':' . $port;
    $errno = 0;
    $errstr = '';
    $fp = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    if (!is_resource($fp)) {
        return ['ok' => false, 'body' => '', 'code' => 0, 'headers' => [], 'error' => $errstr !== '' ? $errstr : 'connect_failed'];
    }
    stream_set_timeout($fp, $timeout);
    $method = strtoupper($method);
    $lines = [
        $method . ' ' . $path . ' HTTP/1.0',
        'Host: ' . $host,
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PNet/1.0',
        'Accept: */*',
        'Connection: close',
    ];
    $cookie = pnet_tplink_cookie_header($host);
    if ($cookie !== '') {
        $lines[] = 'Cookie: ' . $cookie;
    }
    foreach ($extraHeaders as $header) {
        if (is_string($header) && $header !== '' && !str_starts_with(strtolower($header), 'cookie:')) {
            $lines[] = $header;
        }
    }
    if ($method === 'POST') {
        $lines[] = 'Content-Length: ' . strlen($rawBody);
    }
    $payload = implode("\r\n", $lines) . "\r\n\r\n" . ($method === 'POST' ? $rawBody : '');
    fwrite($fp, $payload);
    $raw = (string) stream_get_contents($fp);
    fclose($fp);
    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return ['ok' => false, 'body' => '', 'code' => 0, 'headers' => [], 'error' => 'short_response'];
    }
    $head = substr($raw, 0, $split);
    $body = substr($raw, $split + 4);
    $headerLines = preg_split('/\r\n/', $head) ?: [];
    $code = 0;
    if (isset($headerLines[0]) && preg_match('/\s(\d{3})\s/', $headerLines[0], $m)) {
        $code = (int) $m[1];
    }
    $chunked = false;
    foreach ($headerLines as $header) {
        if (stripos($header, 'Set-Cookie:') === 0) {
            pnet_tplink_store_set_cookie($host, trim(substr($header, 11)));
        }
        if (stripos($header, 'Transfer-Encoding:') === 0 && stripos($header, 'chunked') !== false) {
            $chunked = true;
        }
    }
    if ($chunked) {
        $decoded = pnet_tplink_decode_chunked($body);
        if ($decoded !== '') {
            $body = $decoded;
        }
    }
    return [
        'ok' => $code >= 200 && $code < 400 && $body !== '',
        'body' => $body,
        'code' => $code,
        'headers' => $headerLines,
        'error' => '',
    ];
}

/** @return array{ok:bool,body:string,code:int,headers:list<string>,error:string} */
function pnet_tplink_http(string $url, string $method = 'GET', string $rawBody = '', array $extraHeaders = [], int $timeout = 10): array
{
    $socket = pnet_tplink_http_socket($url, $method, $rawBody, $extraHeaders, $timeout);
    if ($socket['body'] !== '' || $socket['code'] > 0) {
        return $socket;
    }
    if (!function_exists('curl_init')) {
        return $socket;
    }
    $cookie = pnet_router_cookie_path();
    $dir = dirname($cookie);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $headers = array_merge([
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PNet/1.0',
        'Accept: */*',
        'Connection: close',
    ], $extraHeaders);
    $ch = curl_init($url);
    $headerLines = [];
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_0,
        CURLOPT_COOKIEJAR => $cookie,
        CURLOPT_COOKIEFILE => $cookie,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headerLines): int {
            $headerLines[] = trim($line);
            return strlen($line);
        },
    ]);
    if (strtoupper($method) === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
    }
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        return ['ok' => false, 'body' => '', 'code' => $code, 'headers' => $headerLines, 'error' => $err !== '' ? $err : 'request_failed'];
    }
    return [
        'ok' => $code >= 200 && $code < 400,
        'body' => (string) $body,
        'code' => $code,
        'headers' => $headerLines,
        'error' => '',
    ];
}

function pnet_tplink_rsa_encrypt(string $plaintext, string $nnHex, string $eeHex): string
{
    // TP-Link login JS uses jsbn RSAKey.encrypt (PKCS#1 v1.5), split so each
    // chunk fits the key. Raw 64-byte blocks are rejected even with the right password.
    $pem = pnet_tplink_rsa_public_key_pem($nnHex, $eeHex);
    $key = openssl_pkey_get_public($pem);
    if ($key === false) {
        throw new RuntimeException('TP-Link RSA public key invalid.');
    }
    $details = openssl_pkey_get_details($key);
    $modBytes = isset($details['bits']) ? (int) (($details['bits'] + 7) / 8) : 128;
    if ($modBytes < 64) {
        $modBytes = 64;
    }
    $maxChunk = $modBytes - 11;
    $out = '';
    $len = strlen($plaintext);
    for ($i = 0; $i < $len; $i += $maxChunk) {
        $chunk = substr($plaintext, $i, $maxChunk);
        $encrypted = '';
        if (!openssl_public_encrypt($chunk, $encrypted, $key, OPENSSL_PKCS1_PADDING)) {
            throw new RuntimeException('TP-Link RSA encrypt failed.');
        }
        $out .= bin2hex($encrypted);
    }
    return $out;
}

function pnet_tplink_rsa_public_key_pem(string $nnHex, string $eeHex): string
{
    $modulus = hex2bin(strlen($nnHex) % 2 === 1 ? ('0' . $nnHex) : $nnHex);
    $exponent = hex2bin(strlen($eeHex) % 2 === 1 ? ('0' . $eeHex) : $eeHex);
    if ($modulus === false || $exponent === false) {
        throw new RuntimeException('TP-Link RSA key parse failed.');
    }
    if (ord($modulus[0]) > 0x7f) {
        $modulus = "\0" . $modulus;
    }
    if (ord($exponent[0]) > 0x7f) {
        $exponent = "\0" . $exponent;
    }
    $encode = static function (string $data): string {
        $len = strlen($data);
        if ($len < 0x80) {
            return chr($len) . $data;
        }
        if ($len <= 0xff) {
            return "\x81" . chr($len) . $data;
        }
        return "\x82" . chr(($len >> 8) & 0xff) . chr($len & 0xff) . $data;
    };
    $mod = "\x02" . $encode($modulus);
    $exp = "\x02" . $encode($exponent);
    $seq = "\x30" . $encode($mod . $exp);
    $bitString = "\x03" . $encode("\0" . $seq);
    $rsaOid = hex2bin('300d06092a864886f70d0101010500');
    if ($rsaOid === false) {
        throw new RuntimeException('TP-Link RSA OID failed.');
    }
    $spki = "\x30" . $encode($rsaOid . $bitString);
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
}


function pnet_tplink_aes_encrypt(string $plaintext, string $key, string $iv): string
{
    $raw = openssl_encrypt($plaintext, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($raw === false) {
        throw new RuntimeException('TP-Link AES encrypt failed.');
    }
    return base64_encode($raw);
}

function pnet_tplink_aes_decrypt(string $ciphertextB64, string $key, string $iv): string
{
    $raw = base64_decode($ciphertextB64, true);
    if ($raw === false) {
        return '';
    }
    $plain = openssl_decrypt($raw, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return is_string($plain) ? $plain : '';
}

function pnet_tplink_random_digits(int $len): string
{
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        $out .= (string) random_int(0, 9);
    }
    return $out;
}

/** @return array{ok:bool,nn?:string,ee?:string,seq?:int,error?:string} */
function pnet_tplink_get_parm(string $base): array
{
    $res = pnet_tplink_http($base . '/cgi/getParm', 'GET', '', [
        'Referer: ' . $base . '/',
    ]);
    if (!$res['ok'] || $res['body'] === '') {
        $res = pnet_tplink_http($base . '/cgi?8', 'POST', "[/cgi/getParm#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n", [
            'Content-Type: text/plain',
            'Referer: ' . $base . '/',
            'Origin: ' . $base,
        ]);
    }
    if (!$res['ok'] || $res['body'] === '') {
        return ['ok' => false, 'error' => 'getParm_failed'];
    }
    if (!preg_match('/\bnn\s*=\s*"?([0-9A-Fa-f]{16,})"?/', $res['body'], $nn)
        || !preg_match('/\bee\s*=\s*"?([0-9A-Fa-f]+)"?/', $res['body'], $ee)
        || !preg_match('/\bseq\s*=\s*"?(\d+)"?/', $res['body'], $seq)
    ) {
        return ['ok' => false, 'error' => 'getParm_parse'];
    }
    return [
        'ok' => true,
        'nn' => $nn[1],
        'ee' => $ee[1],
        'seq' => (int) $seq[1],
    ];
}

function pnet_tplink_supports_gdpr(string $base): bool
{
    $home = pnet_tplink_http($base . '/', 'GET', '', ['Referer: ' . $base . '/']);
    if (stripos($home['body'], 'INCLUDE_LOGIN_GDPR_ENCRYPT') !== false) {
        return true;
    }
    $parm = pnet_tplink_get_parm($base);
    return !empty($parm['ok']);
}

/** @return array{ok:bool,session:string,base:string,error:string,mode?:string,aes_key?:string,aes_iv?:string,hash?:string,seq?:int} */
function pnet_tplink_login_gdpr(string $base, string $user, string $pass): array
{
    $parm = pnet_tplink_get_parm($base);
    if (empty($parm['ok'])) {
        return ['ok' => false, 'session' => '', 'base' => $base, 'error' => (string) ($parm['error'] ?? 'getParm_failed')];
    }
    $key = pnet_tplink_random_digits(16);
    $iv = pnet_tplink_random_digits(16);
    $hash = md5($user . $pass);
    $loginData = "8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername={$user}\r\npassword={$pass}\r\n";
    $dataB64 = pnet_tplink_aes_encrypt($loginData, $key, $iv);
    // The page keeps the getParm sequence and adds only this request's ciphertext length.
    $seqBase = (int) $parm['seq'];
    $seq = $seqBase + strlen($dataB64);
    $signPlain = 'key=' . $key . '&iv=' . $iv . '&h=' . $hash . '&s=' . $seq;
    $signHex = pnet_tplink_rsa_encrypt($signPlain, (string) $parm['nn'], (string) $parm['ee']);
    $body = 'sign=' . $signHex . "\r\ndata=" . $dataB64 . "\r\n";
    $res = pnet_tplink_http($base . '/cgi_gdpr', 'POST', $body, [
        'Content-Type: text/plain',
        'Referer: ' . $base . '/',
        'Origin: ' . $base,
    ]);
    if (!$res['ok'] || $res['body'] === '') {
        return ['ok' => false, 'session' => '', 'base' => $base, 'error' => 'login_http_' . $res['code']];
    }
    $decoded = pnet_tplink_aes_decrypt(trim($res['body']), $key, $iv);
    $ok = $decoded !== '' && (
        str_contains($decoded, '$.ret=0')
        || str_contains($decoded, '[error]0')
        || str_contains($decoded, '[cgi]0')
    );
    if (!$ok && (str_contains($decoded, 'login failed') || str_contains(strtolower($decoded), 'password'))) {
        return ['ok' => false, 'session' => '', 'base' => $base, 'error' => 'bad_password'];
    }
    if (!$ok) {
        return ['ok' => false, 'session' => '', 'base' => $base, 'error' => 'login_failed'];
    }
    $jsession = '';
    foreach ($res['headers'] as $h) {
        if (preg_match('/JSESSIONID=([A-Za-z0-9]+)/', $h, $m) && strcasecmp($m[1], 'deleted') !== 0) {
            $jsession = $m[1];
            break;
        }
    }
    $session = $jsession !== '' ? $jsession : 'gdpr';
    $path = pnet_tplink_session_path();
    file_put_contents($path, json_encode([
        'base' => $base,
        'session' => $session,
        'mode' => 'gdpr',
        'aes_key' => $key,
        'aes_iv' => $iv,
        'hash' => $hash,
        'seq' => $seqBase,
        'nn' => $parm['nn'],
        'ee' => $parm['ee'],
        'ts' => microtime(true),
    ], JSON_UNESCAPED_SLASHES), LOCK_EX);

    return [
        'ok' => true,
        'session' => $session,
        'base' => $base,
        'error' => '',
        'mode' => 'gdpr',
        'aes_key' => $key,
        'aes_iv' => $iv,
        'hash' => $hash,
        'seq' => $seqBase,
    ];
}

function pnet_tplink_parse_js_array(string $html, string $varName): array
{
    if (!preg_match('/(?:var\s+)?' . preg_quote($varName, '/') . '\s*=\s*new\s+Array\s*\((.*?)\)\s*;/is', $html, $m)) {
        return [];
    }
    $raw = trim($m[1]);
    if ($raw === '' || $raw === '0,0') {
        return [];
    }
    $flat = [];
    if (preg_match_all('/"([^"]*)"|(-?\d+)/', $raw, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $item) {
            if (isset($item[0][0]) && $item[0][0] === '"') {
                $flat[] = $item[1];
            } else {
                $flat[] = $item[2];
            }
        }
    }
    return $flat;
}

function pnet_tplink_parse_named_rows(string $html, string $varName, int $fieldsPerRow): array
{
    $flat = pnet_tplink_parse_js_array($html, $varName);
    if (!$flat || $fieldsPerRow < 1) {
        return [];
    }
    $rows = [];
    for ($i = 0; $i + $fieldsPerRow - 1 < count($flat); $i += $fieldsPerRow) {
        $chunk = array_slice($flat, $i, $fieldsPerRow);
        // Trailing 0,0 terminator on some pages
        if (count($chunk) >= 2 && $chunk[0] === '0' && $chunk[1] === '0' && count(array_filter($chunk, fn($v) => $v !== '' && $v !== '0')) <= 2) {
            break;
        }
        $rows[] = $chunk;
    }
    return $rows;
}

function pnet_tplink_login(PDO $pdo): array
{
    $access = pnet_router_access($pdo);
    $base = rtrim((string) ($access['admin_url'] ?? ''), '/');
    $login = pnet_router_get_login($pdo);
    $user = (string) ($login['username'] ?? 'admin');
    $pass = (string) ($login['password'] ?? '');
    if ($base === '' || $pass === '') {
        return ['ok' => false, 'session' => '', 'error' => 'no_login'];
    }
    if ($user === '') {
        $user = 'admin';
    }

    $path = pnet_tplink_session_path();
    if (is_file($path)) {
        $cached = json_decode((string) file_get_contents($path), true);
        if (is_array($cached)
            && ($cached['base'] ?? '') === $base
            && ($cached['session'] ?? '') !== ''
            && (microtime(true) - (float) ($cached['ts'] ?? 0)) < 120
        ) {
            return [
                'ok' => true,
                'session' => (string) $cached['session'],
                'base' => $base,
                'error' => '',
                'mode' => (string) ($cached['mode'] ?? 'classic'),
            ];
        }
    }

    // Archer C50 / modern TP-Link: GDPR RSA+AES login.
    if (pnet_tplink_supports_gdpr($base)) {
        try {
            $gdpr = pnet_tplink_login_gdpr($base, $user, $pass);
        } catch (Throwable $e) {
            $gdpr = ['ok' => false, 'session' => '', 'base' => $base, 'error' => 'crypto_' . $e->getMessage()];
        }
        if (empty($gdpr['ok'])) {
            @unlink(pnet_router_cookie_path());
            @unlink($path);
            try {
                $gdpr = pnet_tplink_login_gdpr($base, $user, $pass);
            } catch (Throwable $e) {
                $gdpr = ['ok' => false, 'session' => '', 'base' => $base, 'error' => 'crypto_' . $e->getMessage()];
            }
        }
        if (!empty($gdpr['ok'])) {
            return $gdpr;
        }
        // Keep GDPR error if classic is 403 on this firmware.
        $classicProbe = pnet_tplink_http($base . '/userRpm/LoginRpm.htm?Save=Save', 'GET', '', [
            'Referer: ' . $base . '/',
        ]);
        if ($classicProbe['code'] === 403 || $classicProbe['code'] === 404) {
            return $gdpr;
        }
    }

    $auth = pnet_tplink_auth_header($user, $pass);
    $loginUrl = $base . '/userRpm/LoginRpm.htm?Save=Save';
    $res = pnet_router_session_request($loginUrl, 'GET', [], 10, [
        $auth,
        'Referer: ' . $base . '/',
    ]);
    if ($res['body'] === '') {
        return ['ok' => false, 'session' => '', 'error' => 'login_failed'];
    }
    $session = '';
    if (preg_match('#https?://[^/]+/([A-Za-z0-9]+)/userRpm/#', $res['body'], $m)) {
        $session = $m[1];
    } elseif (preg_match('#/([A-Za-z0-9]{8,})/userRpm/#', $res['body'], $m)) {
        $session = $m[1];
    } elseif (preg_match('#href\s*=\s*["\']([^"\']*Index\.htm)["\']#i', $res['body'], $m)) {
        if (preg_match('#/([A-Za-z0-9]+)/userRpm/#', $m[1], $mm)) {
            $session = $mm[1];
        }
    }
    if ($session === '' || stripos($res['body'], 'no authority') !== false || stripos($res['body'], 'login') !== false && stripos($res['body'], 'Index.htm') === false) {
        // Some firmwares keep login page text even after success; require session token.
        if ($session === '') {
            return ['ok' => false, 'session' => '', 'error' => 'login_failed'];
        }
    }

    file_put_contents($path, json_encode([
        'base' => $base,
        'session' => $session,
        'mode' => 'classic',
        'ts' => microtime(true),
    ], JSON_UNESCAPED_SLASHES), LOCK_EX);

    return ['ok' => true, 'session' => $session, 'base' => $base, 'error' => '', 'mode' => 'classic'];
}

function pnet_tplink_get(PDO $pdo, string $page, array $query = []): string
{
    $login = pnet_tplink_login($pdo);
    if (empty($login['ok'])) {
        return '';
    }
    $base = (string) $login['base'];
    $session = (string) $login['session'];
    $user = (string) (pnet_router_get_login($pdo)['username'] ?? 'admin');
    $pass = (string) (pnet_router_get_login($pdo)['password'] ?? '');
    $auth = pnet_tplink_auth_header($user !== '' ? $user : 'admin', $pass);
    $url = $base . '/' . $session . '/userRpm/' . $page;
    if ($query) {
        $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($query);
    }
    $referer = $base . '/' . $session . '/userRpm/MenuRpm.htm';
    $res = pnet_router_session_request($url, 'GET', [], 10, [
        $auth,
        'Referer: ' . $referer,
    ]);
    if ($res['body'] === '' || stripos($res['body'], 'no authority') !== false) {
        @unlink(pnet_tplink_session_path());
        $login = pnet_tplink_login($pdo);
        if (empty($login['ok'])) {
            return '';
        }
        $session = (string) $login['session'];
        $url = $base . '/' . $session . '/userRpm/' . $page;
        if ($query) {
            $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($query);
        }
        $referer = $base . '/' . $session . '/userRpm/MenuRpm.htm';
        $res = pnet_router_session_request($url, 'GET', [], 10, [
            $auth,
            'Referer: ' . $referer,
        ]);
    }
    return (string) ($res['body'] ?? '');
}

/** @return array<string,mixed>|null */
function pnet_tplink_session_load(): ?array
{
    $path = pnet_tplink_session_path();
    if (!is_file($path)) {
        return null;
    }
    $data = json_decode((string) file_get_contents($path), true);
    return is_array($data) ? $data : null;
}

function pnet_tplink_session_save(array $session): void
{
    file_put_contents(pnet_tplink_session_path(), json_encode($session, JSON_UNESCAPED_SLASHES), LOCK_EX);
}

/**
 * Encrypted CGI used by current TP-Link admin pages (not the old userRpm UI).
 */
function pnet_tplink_cgi(PDO $pdo, string $plain): string
{
    $login = pnet_tplink_login($pdo);
    if (empty($login['ok'])) {
        return '';
    }
    $session = pnet_tplink_session_load();
    if (!$session || ($session['mode'] ?? '') !== 'gdpr') {
        return '';
    }
    $base = rtrim((string) ($session['base'] ?? $login['base'] ?? ''), '/');
    $key = (string) ($session['aes_key'] ?? '');
    $iv = (string) ($session['aes_iv'] ?? '');
    $hash = (string) ($session['hash'] ?? '');
    $nn = (string) ($session['nn'] ?? '');
    $ee = (string) ($session['ee'] ?? '');
    if ($base === '' || $key === '' || $iv === '' || $hash === '' || $nn === '' || $ee === '') {
        return '';
    }
    if (!str_ends_with($plain, "\n")) {
        $plain .= "\r\n";
    }
    $dataB64 = pnet_tplink_aes_encrypt($plain, $key, $iv);
    $seq = (int) ($session['seq'] ?? 0) + strlen($dataB64);
    $signHex = pnet_tplink_rsa_encrypt('h=' . $hash . '&s=' . $seq, $nn, $ee);
    $body = 'sign=' . $signHex . "\r\ndata=" . $dataB64 . "\r\n";
    $res = pnet_tplink_http($base . '/cgi_gdpr', 'POST', $body, [
        'Content-Type: text/plain',
        'Referer: ' . $base . '/',
        'Origin: ' . $base,
    ]);
    $decoded = $res['body'] !== '' ? pnet_tplink_aes_decrypt(trim($res['body']), $key, $iv) : '';
    return $decoded !== '' ? $decoded : (string) $res['body'];
}

/** @return array<string,array{ip:string,mac:string,name:string,lease:string,source:string}> */
function pnet_tplink_clients_from_cgi(string $text, string $source): array
{
    $clients = [];
    if ($text === '') {
        return $clients;
    }
    $blocks = preg_split('/\r?\n(?=\[)/', $text) ?: [$text];
    foreach ($blocks as $block) {
        $ip = '';
        $mac = '';
        $name = '';
        $lease = '';
        if (preg_match('/(?:^|[\r\n])\s*(?:IPAddress|ip|IP|ipAddr)\d*\s*=\s*([0-9.]+)/i', $block, $m)) {
            $ip = $m[1];
        }
        if (preg_match('/(?:^|[\r\n])\s*(?:MACAddress|mac|MAC|macAddr)\d*\s*=\s*([0-9A-Fa-f:\-]+)/i', $block, $m)) {
            $mac = pnet_tplink_norm_mac($m[1]);
        }
        if (preg_match('/(?:^|[\r\n])\s*(?:hostName|hostname|deviceName|name)\d*\s*=\s*([^\r\n]+)/i', $block, $m)) {
            $name = trim($m[1]);
        }
        if (preg_match('/(?:^|[\r\n])\s*(?:leaseTime|lease|expires)\d*\s*=\s*([^\r\n]+)/i', $block, $m)) {
            $lease = trim($m[1]);
        }
        if ($ip === '' || !function_exists('pnet_is_lan_ipv4') || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $clients[$ip] = [
            'ip' => $ip,
            'mac' => $mac,
            'name' => $name,
            'lease' => $lease,
            'source' => $source,
        ];
    }
    if ($clients) {
        return $clients;
    }
    $indexed = [];
    if (preg_match_all('/(?:^|[\r\n])\s*(IPAddress|ip|MACAddress|mac|hostName|hostname|deviceName)(\d+)\s*=\s*([^\r\n]+)/i', $text, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $hit) {
            $field = strtolower($hit[1]);
            $idx = $hit[2];
            $val = trim($hit[3]);
            if (!isset($indexed[$idx])) {
                $indexed[$idx] = ['ip' => '', 'mac' => '', 'name' => '', 'lease' => '', 'source' => $source];
            }
            if (str_contains($field, 'mac')) {
                $indexed[$idx]['mac'] = pnet_tplink_norm_mac($val);
            } elseif (str_contains($field, 'ip')) {
                $indexed[$idx]['ip'] = $val;
            } else {
                $indexed[$idx]['name'] = $val;
            }
        }
        foreach ($indexed as $row) {
            if ($row['ip'] !== '' && pnet_is_lan_ipv4($row['ip'])) {
                $clients[$row['ip']] = $row;
            }
        }
    }
    return $clients;
}

function pnet_tplink_norm_mac(string $mac): string
{
    $mac = strtoupper(str_replace('-', ':', trim($mac)));
    if (preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/', $mac)) {
        return $mac;
    }
    return '';
}

/**
 * Pull DHCP clients, Wi‑Fi stations, and traffic counters from classic TP-Link userRpm UI.
 */
function pnet_tplink_pull(PDO $pdo): array
{
    $out = [
        'ok' => false,
        'clients' => [],
        'stats' => [],
        'wifi' => [],
        'status' => [],
        'error' => '',
    ];
    $login = pnet_tplink_login($pdo);
    if (empty($login['ok'])) {
        $out['error'] = (string) ($login['error'] ?? 'login_failed');
        return $out;
    }

    $session = pnet_tplink_session_load();
    if (($session['mode'] ?? $login['mode'] ?? '') === 'gdpr') {
        $clients = [];
        $queries = [
            "5\r\n[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nMACAddress\r\nIPAddress\r\nhostName\r\nleaseTimeRemaining\r\n" => 'dhcp',
            "5\r\n[LAN_WLAN_ASSOC_DEV#1,1,0,0,0,0#0,0,0,0,0,0]0,3\r\nMACAddress\r\nIPAddress\r\nX_TP_HostName\r\n" => 'wifi',
            "5\r\n[LAN_WLAN_ASSOC_DEV#1,2,0,0,0,0#0,0,0,0,0,0]0,3\r\nMACAddress\r\nIPAddress\r\nX_TP_HostName\r\n" => 'wifi',
        ];
        foreach ($queries as $query => $source) {
            $text = pnet_tplink_cgi($pdo, $query);
            foreach (pnet_tplink_clients_from_cgi($text, $source) as $ip => $row) {
                if (!isset($clients[$ip])) {
                    $clients[$ip] = $row;
                    continue;
                }
                if (($clients[$ip]['mac'] ?? '') === '' && ($row['mac'] ?? '') !== '') {
                    $clients[$ip]['mac'] = $row['mac'];
                }
                if (($clients[$ip]['name'] ?? '') === '' && ($row['name'] ?? '') !== '') {
                    $clients[$ip]['name'] = $row['name'];
                }
            }
        }
        $info = pnet_tplink_cgi($pdo, "1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nsoftwareVersion\r\n");
        $status = [];
        if (preg_match('/(?:lanIp|LANIPAddress|ipAddr)\s*=\s*([0-9.]+)/i', $info, $m)) {
            $status['lan_ip'] = $m[1];
        }
        if (preg_match('/(?:wanIp|X_TP_ExternalIPAddress|externalIPAddress)\s*=\s*([0-9.]+)/i', $info, $m)) {
            $status['wan_ip'] = $m[1];
        }
        if (preg_match('/(?:SSID|ssid)\s*=\s*([^\r\n]+)/', $info, $m)) {
            $status['ssid'] = trim($m[1]);
        }
        if ($clients) {
            $out['ok'] = true;
            $out['clients'] = array_values($clients);
            $out['status'] = $status;
            return $out;
        }
    }

    $dhcpHtml = pnet_tplink_get($pdo, 'AssignedIpAddrListRpm.htm', ['Refresh' => 'Refresh']);
    $clients = [];
    // DHCPDynList: name, mac, ip, lease
    foreach (pnet_tplink_parse_named_rows($dhcpHtml, 'DHCPDynList', 4) as $row) {
        $name = trim((string) ($row[0] ?? ''));
        $mac = pnet_tplink_norm_mac((string) ($row[1] ?? ''));
        $ip = trim((string) ($row[2] ?? ''));
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $clients[$ip] = [
            'ip' => $ip,
            'mac' => $mac,
            'name' => $name,
            'lease' => trim((string) ($row[3] ?? '')),
            'source' => 'dhcp',
        ];
    }

    foreach (['WlanStationRpm.htm', 'WlanStationRpm_5g.htm', 'WlanStationRpm.htm?Page=1'] as $wlanPage) {
        $page = $wlanPage;
        $query = [];
        if (str_contains($wlanPage, '?')) {
            [$page, $qs] = explode('?', $wlanPage, 2);
            parse_str($qs, $query);
        }
        $wlanHtml = pnet_tplink_get($pdo, $page, $query ?: ['Page' => '1']);
        // hostList / wlanHostList often: mac, ?, ?, ?, ?, ip? — varies by firmware
        foreach (['hostList', 'wlanHostList', 'wlanList'] as $var) {
            $rows = pnet_tplink_parse_named_rows($wlanHtml, $var, 6);
            if (!$rows) {
                $rows = pnet_tplink_parse_named_rows($wlanHtml, $var, 4);
            }
            foreach ($rows as $row) {
                $mac = '';
                $ip = '';
                foreach ($row as $cell) {
                    $cell = trim((string) $cell);
                    if ($mac === '' && pnet_tplink_norm_mac($cell) !== '') {
                        $mac = pnet_tplink_norm_mac($cell);
                    } elseif ($ip === '' && pnet_is_lan_ipv4($cell)) {
                        $ip = $cell;
                    }
                }
                if ($ip === '' && $mac !== '') {
                    foreach ($clients as $c) {
                        if (($c['mac'] ?? '') === $mac) {
                            $ip = $c['ip'];
                            break;
                        }
                    }
                }
                if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
                    continue;
                }
                if (!isset($clients[$ip])) {
                    $clients[$ip] = ['ip' => $ip, 'mac' => $mac, 'name' => '', 'lease' => '', 'source' => 'wifi'];
                } else {
                    if ($mac !== '' && ($clients[$ip]['mac'] ?? '') === '') {
                        $clients[$ip]['mac'] = $mac;
                    }
                    $clients[$ip]['wifi'] = true;
                }
            }
        }
    }

    $statsHtml = pnet_tplink_get($pdo, 'SystemStatisticRpm.htm', [
        'interval' => 10,
        'autoRefresh' => 0,
        'sortType' => 1,
        'Num_per_page' => 100,
        'Goto_page' => 1,
    ]);
    $stats = [];
    // statList typically: idx, ip, mac, packets, bytes, ...
    foreach (pnet_tplink_parse_named_rows($statsHtml, 'statList', 5) as $row) {
        $ip = '';
        $mac = '';
        $bytes = 0;
        $packets = 0;
        foreach ($row as $i => $cell) {
            $cell = trim((string) $cell);
            if ($ip === '' && pnet_is_lan_ipv4($cell)) {
                $ip = $cell;
            } elseif ($mac === '' && pnet_tplink_norm_mac($cell) !== '') {
                $mac = pnet_tplink_norm_mac($cell);
            } elseif (ctype_digit($cell)) {
                if ($packets === 0) {
                    $packets = (int) $cell;
                } else {
                    $bytes = (int) $cell;
                }
            }
        }
        // Prefer last large number as bytes
        $nums = [];
        foreach ($row as $cell) {
            if (ctype_digit(trim((string) $cell))) {
                $nums[] = (int) trim((string) $cell);
            }
        }
        if (count($nums) >= 2) {
            $packets = $nums[count($nums) - 2];
            $bytes = $nums[count($nums) - 1];
        } elseif (count($nums) === 1) {
            $bytes = $nums[0];
        }
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $stats[$ip] = [
            'ip' => $ip,
            'mac' => $mac,
            'bytes' => $bytes,
            'packets' => $packets,
        ];
        if (!isset($clients[$ip])) {
            $clients[$ip] = ['ip' => $ip, 'mac' => $mac, 'name' => '', 'lease' => '', 'source' => 'stats'];
        } elseif ($mac !== '' && ($clients[$ip]['mac'] ?? '') === '') {
            $clients[$ip]['mac'] = $mac;
        }
    }

    $statusHtml = pnet_tplink_get($pdo, 'StatusRpm.htm');
    $status = [];
    if (preg_match('/lanIp\s*=\s*"([^"]+)"/i', $statusHtml, $m) || preg_match('/lanIP\s*=\s*"([^"]+)"/i', $statusHtml, $m)) {
        $status['lan_ip'] = $m[1];
    }
    if (preg_match('/wanIp\s*=\s*"([^"]+)"/i', $statusHtml, $m) || preg_match('/wanIP\s*=\s*"([^"]+)"/i', $statusHtml, $m)) {
        $status['wan_ip'] = $m[1];
    }
    foreach (['ssid', 'SSID', 'wlanSsid', 'wlanssid'] as $k) {
        if (preg_match('/\b' . $k . '\s*=\s*"([^"]+)"/i', $statusHtml, $m) && $m[1] !== '') {
            $status['ssid'] = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            break;
        }
    }
    $wlanNet = pnet_tplink_get($pdo, 'WlanNetworkRpm.htm');
    if (empty($status['ssid']) && preg_match('/ssid\s*=\s*"([^"]+)"/i', $wlanNet, $m)) {
        $status['ssid'] = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    $out['ok'] = count($clients) > 0 || count($stats) > 0;
    $out['clients'] = array_values($clients);
    $out['stats'] = $stats;
    $out['status'] = $status;
    $out['error'] = $out['ok'] ? '' : 'no_clients';
    return $out;
}

function pnet_router_traffic_tplink(PDO $pdo, float $now): array
{
    $pull = pnet_tplink_pull($pdo);
    if (empty($pull['ok']) && empty($pull['clients']) && empty($pull['stats'])) {
        return [
            'clients' => [],
            'source' => '',
            'error' => (string) ($pull['error'] ?? 'unsupported'),
            'has_rates' => false,
            'meta' => $pull,
        ];
    }

    $samples = [];
    $hasRates = false;
    $stats = is_array($pull['stats'] ?? null) ? $pull['stats'] : [];
    foreach ($pull['clients'] as $c) {
        $ip = (string) ($c['ip'] ?? '');
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $bytes = (int) ($stats[$ip]['bytes'] ?? 0);
        $samples[$ip] = [
            'bytes_in' => $bytes,
            'bytes_out' => 0,
            'name' => (string) ($c['name'] ?? ''),
        ];
    }
    foreach ($stats as $ip => $s) {
        if (!isset($samples[$ip])) {
            $samples[$ip] = [
                'bytes_in' => (int) ($s['bytes'] ?? 0),
                'bytes_out' => 0,
                'name' => '',
            ];
        }
    }

    $rated = pnet_router_traffic_rates($samples, $now);
    foreach ($rated as $row) {
        if (((int) ($row['down_bps'] ?? 0) + (int) ($row['up_bps'] ?? 0)) > 0) {
            $hasRates = true;
            break;
        }
    }

    return [
        'clients' => $rated,
        'source' => 'tplink',
        'error' => '',
        'has_rates' => $hasRates,
        'meta' => [
            'client_count' => count($pull['clients']),
            'status' => $pull['status'] ?? [],
        ],
    ];
}

function pnet_tplink_sync_devices(PDO $pdo): string
{
    $pull = pnet_tplink_pull($pdo);
    if (empty($pull['clients'])) {
        throw new RuntimeException(
            ($pull['error'] ?? '') === 'login_failed'
                ? 'Could not log into the TP-Link. Check admin username/password under Router.'
                : 'TP-Link login worked but no DHCP clients were returned. Open DHCP Clients List in the router to confirm.'
        );
    }
    $found = [];
    foreach ($pull['clients'] as $c) {
        $ip = (string) ($c['ip'] ?? '');
        $mac = pnet_tplink_norm_mac((string) ($c['mac'] ?? ''));
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        if ($mac === '') {
            $mac = '00:00:00:00:00:00'; // import still accepts; will skip invalid below
        }
        if ($mac === '00:00:00:00:00:00') {
            // Keep IP-only clients from stats/wifi without inventing MAC — use placeholder that import skips? Better upsert by IP.
            continue;
        }
        $found[$ip] = $mac;
    }

    $network = pnet_detect_lan_network();
    $msg = pnet_import_found_devices($pdo, $found, count($found), $network);

    // Enrich names from DHCP hostnames
    $now = pnet_now();
    $upd = $pdo->prepare("UPDATE devices SET name = ?, updated_at = ? WHERE ip = ? AND (name LIKE 'Seen %' OR name LIKE '% device' OR name = '' OR name LIKE 'Device%')");
    $named = 0;
    foreach ($pull['clients'] as $c) {
        $ip = (string) ($c['ip'] ?? '');
        $name = trim((string) ($c['name'] ?? ''));
        if ($ip === '' || $name === '' || preg_match('/^(\*|unknown|android|iphone|ipad)$/i', $name)) {
            continue;
        }
        $upd->execute([$name, $now, $ip]);
        if ($upd->rowCount() > 0) {
            $named++;
        }
    }

    // Also upsert IP-only clients missing MAC
    $sel = $pdo->prepare('SELECT id FROM devices WHERE ip = ? LIMIT 1');
    $ins = $pdo->prepare('INSERT INTO devices (name, ip, mac, type, vendor, status, last_seen, trust, access_profile, bandwidth_limit, protected, notes, sample, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)');
    $addedIpOnly = 0;
    foreach ($pull['clients'] as $c) {
        $ip = (string) ($c['ip'] ?? '');
        $mac = pnet_tplink_norm_mac((string) ($c['mac'] ?? ''));
        if ($ip === '' || !pnet_is_lan_ipv4($ip) || $mac !== '') {
            continue;
        }
        $sel->execute([$ip]);
        if ($sel->fetch()) {
            continue;
        }
        $name = trim((string) ($c['name'] ?? ''));
        if ($name === '') {
            $name = 'Seen ' . $ip;
        }
        $ins->execute([$name, $ip, '', 'other', '', 'online', $now, 'unknown', 'normal', 0, 0, 'From TP-Link DHCP/stats', $now, $now]);
        $addedIpOnly++;
    }

    if (!empty($pull['status']['ssid'])) {
        pnet_setting_set($pdo, 'wifi_ssid', (string) $pull['status']['ssid']);
    }
    if (!empty($pull['status']['lan_ip'])) {
        pnet_setting_set($pdo, 'lan_ip', (string) $pull['status']['lan_ip']);
    }
    if (!empty($pull['status']['wan_ip'])) {
        pnet_setting_set($pdo, 'wan_ip', (string) $pull['status']['wan_ip']);
    }

    pnet_ensure_gateway_device($pdo);
    pnet_log($pdo, 'router', 'Synced ' . count($pull['clients']) . ' clients from TP-Link.');
    $extra = $named ? " Named {$named}." : '';
    $extra .= $addedIpOnly ? " Added {$addedIpOnly} without MAC." : '';
    return 'Pulled ' . count($pull['clients']) . ' devices from TP-Link. ' . $msg . $extra;
}

function pnet_router_traffic_asus(PDO $pdo, float $now): array
{
    $raw = pnet_router_http_raw($pdo, '/appGet.cgi?hook=get_clientlist()');
    if ($raw === null) {
        return [];
    }
    $json = json_decode($raw, true);
    if (!is_array($json)) {
        return [];
    }
    $clients = $json['get_clientlist'] ?? $json['clientlist'] ?? null;
    if ($clients === null) {
        return [];
    }
    if (is_object($clients)) {
        $clients = (array) $clients;
    }
    $samples = [];
    foreach ($clients as $client) {
        if (!is_array($client)) {
            continue;
        }
        $ip = trim((string) ($client['ip'] ?? $client['ipaddr'] ?? ''));
        if ($ip === '' || !pnet_is_lan_ipv4($ip)) {
            continue;
        }
        $samples[$ip] = [
            'bytes_in' => (int) ($client['rx'] ?? $client['download'] ?? $client['total_rx'] ?? 0),
            'bytes_out' => (int) ($client['tx'] ?? $client['upload'] ?? $client['total_tx'] ?? 0),
            'name' => (string) ($client['name'] ?? $client['hostname'] ?? ''),
        ];
    }
    return pnet_router_traffic_rates($samples, $now);
}

function pnet_router_traffic_fetch(PDO $pdo, float $now): array
{
    if (pnet_setting($pdo, 'router_traffic_enabled', '1') !== '1') {
        return ['clients' => [], 'source' => '', 'error' => 'disabled', 'has_rates' => false];
    }
    $access = pnet_router_access($pdo);
    if (empty($access['has_credentials'])) {
        return ['clients' => [], 'source' => '', 'error' => 'no_login', 'has_rates' => false];
    }

    $brand = strtolower((string) pnet_setting($pdo, 'router_brand', ''));
    $model = strtoupper((string) pnet_setting($pdo, 'router_model', ''));
    $preferZte = $brand === 'zte' || preg_match('/F6\d{2}|H2\d{2}|H3\d{2}|E26|SR7/i', $model);
    $preferTplink = $brand === 'tp-link' || $brand === 'tplink';

    if ($preferTplink) {
        $tp = pnet_router_traffic_tplink($pdo, $now);
        if (!empty($tp['clients']) || ($tp['source'] ?? '') === 'tplink') {
            return $tp;
        }
    }

    if ($preferZte) {
        $zte = pnet_router_traffic_zte($pdo, $now);
        if (!empty($zte['clients'])) {
            return $zte;
        }
    }

    if (!$preferTplink) {
        $tp = pnet_router_traffic_tplink($pdo, $now);
        if (!empty($tp['clients'])) {
            return $tp;
        }
    }

    $asus = pnet_router_traffic_asus($pdo, $now);
    if ($asus) {
        return [
            'clients' => $asus,
            'source' => 'asus',
            'error' => '',
            'has_rates' => true,
        ];
    }

    if (!$preferZte) {
        $zte = pnet_router_traffic_zte($pdo, $now);
        if (!empty($zte['clients'])) {
            return $zte;
        }
    }

    return [
        'clients' => [],
        'source' => '',
        'error' => 'unsupported',
        'has_rates' => false,
    ];
}

function pnet_device_agents_map(PDO $pdo): array
{
    $rows = $pdo->query('SELECT device_id, token, name, last_seen FROM device_agents')->fetchAll();
    $map = [];
    foreach ($rows as $row) {
        $map[(int) $row['device_id']] = $row;
    }
    return $map;
}

function pnet_device_traffic_map(PDO $pdo, float $now): array
{
    $rows = $pdo->query('SELECT device_id, source, ip, down_bps, up_bps, bytes_in, bytes_out, apps_json, updated_at FROM device_traffic')->fetchAll();
    $map = [];
    foreach ($rows as $row) {
        if ($now - (float) ($row['updated_at'] ?? 0) > 45) {
            continue;
        }
        $apps = json_decode((string) ($row['apps_json'] ?? '[]'), true);
        $map[(int) $row['device_id']] = [
            'down_bps' => (int) ($row['down_bps'] ?? 0),
            'up_bps' => (int) ($row['up_bps'] ?? 0),
            'apps' => is_array($apps) ? $apps : [],
        ];
    }
    return $map;
}

function pnet_agent_token(): string
{
    return bin2hex(random_bytes(24));
}

function pnet_create_device_agent(PDO $pdo, array $data): string
{
    $deviceId = pnet_id($data);
    $st = $pdo->prepare('SELECT id, name, ip FROM devices WHERE id = ?');
    $st->execute([$deviceId]);
    $device = $st->fetch();
    if (!$device) {
        throw new InvalidArgumentException('That device was not found.');
    }
    return pnet_tx($pdo, function () use ($pdo, $deviceId, $device) {
        $pdo->prepare('DELETE FROM device_agents WHERE device_id = ?')->execute([$deviceId]);
        $token = pnet_agent_token();
        $pdo->prepare('INSERT INTO device_agents (device_id, token, name, created_at, last_seen) VALUES (?, ?, ?, ?, ?)')->execute([
            $deviceId,
            $token,
            (string) $device['name'],
            pnet_now(),
            '',
        ]);
        pnet_log($pdo, 'agent', 'Created traffic agent for ' . (string) $device['name'] . '.');
        $_SESSION['pnet_api_extra'] = [
            'agent' => [
                'device_id' => $deviceId,
                'token' => $token,
                'device_name' => (string) $device['name'],
            ],
        ];
        return 'Agent ready for ' . (string) $device['name'] . '.';
    });
}

function pnet_revoke_device_agent(PDO $pdo, array $data): string
{
    $deviceId = pnet_id($data);
    return pnet_tx($pdo, function () use ($pdo, $deviceId) {
        $pdo->prepare('DELETE FROM device_agents WHERE device_id = ?')->execute([$deviceId]);
        $pdo->prepare('DELETE FROM device_traffic WHERE device_id = ?')->execute([$deviceId]);
        pnet_log($pdo, 'agent', 'Removed traffic agent for device #' . $deviceId . '.');
        return 'Agent removed.';
    });
}

function pnet_agent_by_token(PDO $pdo, string $token): ?array
{
    $token = trim($token);
    if ($token === '' || !preg_match('/^[a-f0-9]{48}$/', $token)) {
        return null;
    }
    $st = $pdo->prepare('SELECT a.device_id, a.token, a.name, d.ip, d.name AS device_name FROM device_agents a JOIN devices d ON d.id = a.device_id WHERE a.token = ?');
    $st->execute([$token]);
    $row = $st->fetch();
    return $row ?: null;
}

function pnet_agent_report(PDO $pdo, string $token, array $data): array
{
    $agent = pnet_agent_by_token($pdo, $token);
    if (!$agent) {
        throw new InvalidArgumentException('Invalid agent token.');
    }
    $deviceId = (int) $agent['device_id'];
    $now = microtime(true);
    $ip = pnet_ip((string) ($data['ip'] ?? $agent['ip'] ?? ''), false, 'IP');
    if ($ip === '') {
        $ip = (string) ($agent['ip'] ?? '');
    }
    $bytesIn = max(0, (int) ($data['bytes_in'] ?? 0));
    $bytesOut = max(0, (int) ($data['bytes_out'] ?? 0));
    $downBps = max(0, (int) ($data['down_bps'] ?? 0));
    $upBps = max(0, (int) ($data['up_bps'] ?? 0));
    $appsIn = is_array($data['apps'] ?? null) ? $data['apps'] : [];

    $st = $pdo->prepare('SELECT bytes_in, bytes_out, updated_at FROM device_traffic WHERE device_id = ?');
    $st->execute([$deviceId]);
    $prev = $st->fetch();
    if ($downBps === 0 && $upBps === 0 && $bytesIn > 0 && $prev && isset($prev['updated_at'])) {
        $dt = max(0.5, $now - (float) $prev['updated_at']);
        $prevIn = (int) ($prev['bytes_in'] ?? 0);
        $prevOut = (int) ($prev['bytes_out'] ?? 0);
        if ($bytesIn >= $prevIn) {
            $downBps = (int) max(0, (($bytesIn - $prevIn) * 8) / $dt);
        }
        if ($bytesOut >= $prevOut) {
            $upBps = (int) max(0, (($bytesOut - $prevOut) * 8) / $dt);
        }
    }

    $apps = [];
    foreach (array_slice($appsIn, 0, 40) as $app) {
        if (!is_array($app)) {
            continue;
        }
        $name = pnet_text((string) ($app['name'] ?? $app['label'] ?? 'Unknown'), 120, 'App name', false);
        if ($name === '') {
            $name = 'Unknown';
        }
        $apps[] = [
            'name' => $name,
            'label' => pnet_traffic_app_label($name),
            'down_bps' => max(0, (int) ($app['down_bps'] ?? 0)),
            'up_bps' => max(0, (int) ($app['up_bps'] ?? 0)),
            'tcp' => max(0, (int) ($app['tcp'] ?? 0)),
            'udp' => max(0, (int) ($app['udp'] ?? 0)),
            'remote_public' => max(0, (int) ($app['remote_public'] ?? 0)),
        ];
    }
    if (!$apps && ($downBps > 0 || $upBps > 0)) {
        $apps = pnet_traffic_allocate_apps($appsIn, $downBps, $upBps);
    }

    $pdo->prepare('INSERT OR REPLACE INTO device_traffic (device_id, source, ip, down_bps, up_bps, bytes_in, bytes_out, apps_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')->execute([
        $deviceId, 'agent', $ip, $downBps, $upBps, $bytesIn, $bytesOut,
        json_encode($apps, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $now,
    ]);
    $pdo->prepare('UPDATE device_agents SET last_seen = ? WHERE device_id = ?')->execute([pnet_now(), $deviceId]);

    return ['ok' => true, 'device_id' => $deviceId, 'down_bps' => $downBps, 'up_bps' => $upBps];
}

function pnet_traffic_source_label(string $source): string
{
    return match ($source) {
        'local' => 'This PC',
        'agent' => 'PNet agent',
        'router' => 'Router',
        default => '',
    };
}

function pnet_traffic_live_merged(PDO $pdo, ?int $deviceId = null): array
{
    $now = microtime(true);
    $snapshot = pnet_native_monitor();
    if ($snapshot === null) {
        $snapshot = pnet_monitor_php_fallback();
    }
    $monitorReady = $snapshot !== null;
    $live = pnet_live_adapter_details();
    $localIp = (string) ($snapshot['local_ip'] ?? $live['local_ip'] ?? '');
    $prev = pnet_traffic_read_state();
    $bytesIn = (int) ($snapshot['bytes_in'] ?? 0);
    $bytesOut = (int) ($snapshot['bytes_out'] ?? 0);
    $downBps = 0;
    $upBps = 0;
    $warming = true;
    if ($monitorReady && $bytesIn > 0 && isset($prev['bytes_in'], $prev['bytes_out'], $prev['ts'])) {
        $dt = max(0.5, $now - (float) $prev['ts']);
        if ($bytesIn >= (int) $prev['bytes_in'] && $bytesOut >= (int) $prev['bytes_out']) {
            $downBps = (int) max(0, (($bytesIn - (int) $prev['bytes_in']) * 8) / $dt);
            $upBps = (int) max(0, (($bytesOut - (int) $prev['bytes_out']) * 8) / $dt);
            $warming = false;
        }
    }
    if ($monitorReady && ($bytesIn > 0 || $bytesOut > 0)) {
        pnet_traffic_write_state(['ts' => $now, 'bytes_in' => $bytesIn, 'bytes_out' => $bytesOut]);
    }
    $localApps = pnet_traffic_allocate_apps(is_array($snapshot['apps'] ?? null) ? $snapshot['apps'] : [], $downBps, $upBps);
    $routerFetch = pnet_router_traffic_fetch($pdo, $now);
    $routerClients = is_array($routerFetch['clients'] ?? null) ? $routerFetch['clients'] : [];
    $agentTraffic = pnet_device_traffic_map($pdo, $now);
    $agentMeta = pnet_device_agents_map($pdo);

    $devices = pnet_ints($pdo->query('SELECT id, name, ip, type, status FROM devices ORDER BY name COLLATE NOCASE ASC')->fetchAll(), ['id']);
    $deviceRows = [];
    $totalDown = 0;
    $totalUp = 0;
    foreach ($devices as $device) {
        $id = (int) $device['id'];
        $ip = (string) ($device['ip'] ?? '');
        $isLocal = $localIp !== '' && $ip === $localIp;
        $source = '';
        $rowDown = null;
        $rowUp = null;
        $apps = [];
        $note = '';

        if ($isLocal) {
            $source = 'local';
            $rowDown = $downBps;
            $rowUp = $upBps;
            $apps = $localApps;
            if (!empty($snapshot['limited'])) {
                $note = 'Speed totals need engine/build/pnet_scan.exe. Apps still come from active connections.';
            } elseif ($warming) {
                $note = 'Measuring speed… keep this page open for a few seconds.';
            }
        } elseif (isset($agentTraffic[$id])) {
            $source = 'agent';
            $rowDown = (int) $agentTraffic[$id]['down_bps'];
            $rowUp = (int) $agentTraffic[$id]['up_bps'];
            $apps = $agentTraffic[$id]['apps'];
            $note = 'Live from PNet agent on this device.';
        } elseif ($ip !== '' && isset($routerClients[$ip])) {
            $source = 'router';
            $rowDown = (int) ($routerClients[$ip]['down_bps'] ?? 0);
            $rowUp = (int) ($routerClients[$ip]['up_bps'] ?? 0);
            if (!empty($routerFetch['has_rates'])) {
                $note = 'Speed from your ZTE/router. Install a PNet agent to see app names.';
            } else {
                $note = 'Seen on your router. This ZTE model often does not expose live per-device speed — install a PNet agent for usage + apps.';
            }
        } elseif (isset($agentMeta[$id])) {
            $note = 'Agent installed but not reporting yet. Run the agent script on that device.';
        } else {
            $note = 'Install a PNet agent on a Windows PC for live speed. This router does not report phone or TV usage.';
        }

        if ($rowDown !== null) {
            $totalDown += max(0, (int) $rowDown);
        }
        if ($rowUp !== null) {
            $totalUp += max(0, (int) $rowUp);
        }

        $deviceRows[] = [
            'id' => $id,
            'name' => (string) $device['name'],
            'ip' => $ip,
            'type' => (string) ($device['type'] ?? 'other'),
            'status' => (string) ($device['status'] ?? 'unknown'),
            'is_local' => $isLocal,
            'source' => $source,
            'source_label' => pnet_traffic_source_label($source),
            'has_agent' => isset($agentMeta[$id]),
            'down_bps' => $rowDown,
            'up_bps' => $rowUp,
            'apps' => $apps,
            'active' => ($device['status'] ?? '') === 'online' || ($rowDown !== null && ((int) $rowDown + (int) $rowUp) > 0),
            'note' => $note,
        ];
    }
    if ($deviceId !== null && $deviceId > 0) {
        $deviceRows = array_values(array_filter($deviceRows, fn($row) => (int) $row['id'] === $deviceId));
    }
    $access = pnet_router_access($pdo);
    return [
        'ok' => true,
        'ts' => (int) round($now),
        'monitor_ready' => $monitorReady,
        'local_ip' => $localIp,
        'adapter' => (string) ($snapshot['adapter'] ?? $live['adapter'] ?? ''),
        'warming' => $warming,
        'router' => [
            'enabled' => pnet_setting($pdo, 'router_traffic_enabled', '1') === '1',
            'has_login' => !empty($access['has_credentials']),
            'source' => (string) ($routerFetch['source'] ?? ''),
            'clients' => count($routerClients),
            'has_rates' => !empty($routerFetch['has_rates']),
            'error' => (string) ($routerFetch['error'] ?? ''),
            'brand' => (string) pnet_setting($pdo, 'router_brand', ''),
            'model' => (string) pnet_setting($pdo, 'router_model', ''),
        ],
        'agents' => ['count' => count($agentMeta), 'reporting' => count($agentTraffic)],
        'total' => ['down_bps' => $totalDown, 'up_bps' => $totalUp],
        'devices' => $deviceRows,
    ];
}
