<?php
declare(strict_types=1);
$ctx = stream_context_create([
    'http' => [
        'timeout' => 8,
        'ignore_errors' => true,
        'header' => "User-Agent: Mozilla/5.0\r\nReferer: http://192.168.0.1/\r\n",
    ],
]);
foreach (['encrypt.js', 'tpEncrypt.js', 'lib.js'] as $f) {
    $body = (string) @file_get_contents('http://192.168.0.1/js/' . $f, false, $ctx);
    file_put_contents(__DIR__ . '/../data/tplink_' . $f, $body);
    echo "$f=" . strlen($body) . "\n";
}
