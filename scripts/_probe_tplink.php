<?php
declare(strict_types=1);
$ctx = stream_context_create([
    'http' => [
        'timeout' => 6,
        'ignore_errors' => true,
        'header' => "User-Agent: Mozilla/5.0\r\n",
    ],
]);
$urls = [
    'http://192.168.0.1/',
    'http://192.168.0.1/webpages/login.html',
    'http://192.168.0.1/webpages/index.html',
    'http://192.168.0.1/cgi-bin/luci',
    'http://192.168.0.1/userRpm/LoginRpm.htm',
];
$out = '';
foreach ($urls as $url) {
    $body = @file_get_contents($url, false, $ctx);
    $headers = $http_response_header ?? [];
    $out .= "URL $url\n";
    $out .= implode("\n", $headers) . "\n";
    $snippet = substr((string) $body, 0, 800);
    $out .= "BODY_LEN=" . strlen((string) $body) . "\n";
    $out .= $snippet . "\n====\n";
}
file_put_contents(__DIR__ . '/../data/tplink_probe.txt', $out);
echo "wrote\n";
