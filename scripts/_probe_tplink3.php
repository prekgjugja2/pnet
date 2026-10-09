<?php
declare(strict_types=1);
$ctx = stream_context_create([
    'http' => [
        'timeout' => 8,
        'ignore_errors' => true,
        'header' => "User-Agent: Mozilla/5.0\r\n",
    ],
]);
$files = [
    'http://192.168.0.1/js/encrypt.js',
    'http://192.168.0.1/js/tpEncrypt.js',
    'http://192.168.0.1/js/lib.js',
    'http://192.168.0.1/js/root.js',
];
$out = '';
foreach ($files as $url) {
    $body = (string) @file_get_contents($url, false, $ctx);
    $out .= "===== $url len=" . strlen($body) . " =====\n";
    // Find login-related snippets
    foreach (['login', 'Login', 'RSA', 'encrypt', 'cgi', '/cgi', 'Auth', 'password', 'getRsa', 'pubkey', 'PC'] as $n) {
        // skip
    }
    if (preg_match_all('/.{0,80}(login|Login|\/cgi|rsa|RSA|encryptPassword|getPassword|Auth|password).{0,120}/s', $body, $m)) {
        $uniq = array_unique($m[0]);
        foreach (array_slice($uniq, 0, 40) as $line) {
            $out .= trim(preg_replace('/\s+/', ' ', $line)) . "\n";
        }
    }
    $out .= "\n";
}
// Also grab login page script inline that posts
$html = (string) @file_get_contents('http://192.168.0.1/', false, $ctx);
if (preg_match_all('/function\s+\w*login\w*\s*\([^)]*\)\s*\{.{0,800}/is', $html, $m)) {
    $out .= "===== inline login funcs =====\n";
    foreach ($m[0] as $fn) {
        $out .= substr(preg_replace('/\s+/', ' ', $fn), 0, 700) . "\n---\n";
    }
}
file_put_contents(__DIR__ . '/../data/tplink_js.txt', $out);
echo "bytes=" . strlen($out) . "\n";
