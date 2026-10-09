<?php
declare(strict_types=1);
$ctx = stream_context_create([
    'http' => [
        'timeout' => 8,
        'ignore_errors' => true,
        'header' => "User-Agent: Mozilla/5.0\r\nReferer: http://192.168.0.1/\r\n",
    ],
]);
$html = file_get_contents(__DIR__ . '/../data/tplink_login.html');
preg_match_all('/src=["\'](\.\.\/js\/[^"\']+)["\']/', $html, $m);
$out = '';
foreach (array_unique($m[1]) as $rel) {
    $path = str_replace('../js/', '/js/', $rel);
    $body = (string) @file_get_contents('http://192.168.0.1' . $path, false, $ctx);
    $file = __DIR__ . '/../data/tplink_' . basename($path);
    file_put_contents($file, $body);
    $out .= basename($path) . '=' . strlen($body);
    foreach (['ACT_CGI', '.exe=', 'function exe', '/cgi/login', 'sign=', 'AESEncrypt', 'username'] as $t) {
        if (stripos($body, $t) !== false) {
            $out .= " [$t]";
        }
    }
    $out .= "\n";
}
file_put_contents(__DIR__ . '/../data/tplink_js_index.txt', $out);
echo $out;
