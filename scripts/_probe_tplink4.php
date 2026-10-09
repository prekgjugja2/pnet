<?php
declare(strict_types=1);

function http_get(string $url, array $headers = []): array
{
    $hdr = "User-Agent: Mozilla/5.0\r\n";
    foreach ($headers as $h) {
        $hdr .= $h . "\r\n";
    }
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 8,
            'ignore_errors' => true,
            'header' => $hdr,
            'follow_location' => 0,
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    return [
        'headers' => $http_response_header ?? [],
        'body' => (string) $body,
    ];
}

$r = http_get('http://192.168.0.1/');
$cookies = [];
foreach ($r['headers'] as $h) {
    if (stripos($h, 'Set-Cookie:') === 0) {
        $cookies[] = trim(substr($h, 11));
    }
}
$html = $r['body'];
$cookieHdr = [];
foreach ($cookies as $c) {
    $cookieHdr[] = 'Cookie: ' . explode(';', $c)[0];
}

$out = "cookies=" . json_encode($cookies) . "\n";
if (preg_match_all('/INCLUDE_[A-Z0-9_]+/ ', $html, $m)) {
    // noop
}
if (preg_match_all('/INCLUDE_[A-Z0-9_]+/', $html, $m)) {
    $out .= "includes=" . implode(',', array_unique($m[0])) . "\n";
}
if (preg_match('/var\s+nn\s*=\s*["\']([^"\']+)/', $html, $m)) {
    $out .= "nn_inline=" . substr($m[1], 0, 40) . "...\n";
}
if (preg_match('/isFirstLogin\s*=\s*["\']?(\d+)/', $html, $m)) {
    $out .= "isFirstLogin={$m[1]}\n";
}

// Try getParm
foreach (['http://192.168.0.1/cgi/getParm', 'http://192.168.0.1/cgi-bin/getParm', 'http://192.168.0.1/cgi?getParm'] as $u) {
    $g = http_get($u, array_merge($cookieHdr, ['Referer: http://192.168.0.1/']));
    $out .= "GET $u status_line=" . ($g['headers'][0] ?? '') . " len=" . strlen($g['body']) . "\n";
    $out .= substr($g['body'], 0, 400) . "\n----\n";
}

// Try common script paths with cookie
foreach (['/js/encrypt.js', '/js/tpEncrypt.js', '/login/js/encrypt.js', '/webpages/js/encrypt.js'] as $p) {
    $g = http_get('http://192.168.0.1' . $p, array_merge($cookieHdr, ['Referer: http://192.168.0.1/']));
    $out .= "JS $p len=" . strlen($g['body']) . " head=" . substr($g['body'], 0, 80) . "\n";
}

file_put_contents(__DIR__ . '/../data/tplink_probe3.txt', $out);
echo $out;
