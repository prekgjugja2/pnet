<?php
declare(strict_types=1);

function grab(string $url, string $method = 'GET', string $body = ''): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => [
            'User-Agent: Mozilla/5.0',
            'Accept: */*',
            'Referer: http://192.168.0.1/',
        ],
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    $raw = is_string($raw) ? $raw : '';
    return ['code' => $code, 'headers' => substr($raw, 0, $headerSize), 'body' => substr($raw, $headerSize)];
}

$out = '';
$home = grab('http://192.168.0.1/');
file_put_contents(__DIR__ . '/../data/tplink_home.html', $home['body']);
preg_match_all('/src=["\']([^"\']+)["\']/', $home['body'], $srcs);
$out .= "HOME code={$home['code']} len=" . strlen($home['body']) . "\n";
$out .= "SRCS:\n" . implode("\n", $srcs[1] ?? []) . "\n";
if (preg_match('/<title>(.*?)<\/title>/is', $home['body'], $t)) {
    $out .= "TITLE=" . trim($t[1]) . "\n";
}
$needles = ['INCLUDE_LOGIN', 'getParm', 'cgi_gdpr', 'encrypt', 'RSA', 'password', 'md5', 'stok', 'login'];
foreach ($needles as $n) {
    $out .= $n . '=' . (stripos($home['body'], $n) !== false ? 'yes' : 'no') . "\n";
}

foreach (['/cgi/getParm', '/cgi?8'] as $path) {
    $res = $path === '/cgi?8'
        ? grab('http://192.168.0.1' . $path, 'POST', "[/cgi/getParm#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        : grab('http://192.168.0.1' . $path);
    $out .= "\nPATH $path code={$res['code']} len=" . strlen($res['body']) . "\n";
    $out .= substr($res['body'], 0, 500) . "\n";
}

file_put_contents(__DIR__ . '/tplink_dump.txt', $out);
echo "ok\n";
