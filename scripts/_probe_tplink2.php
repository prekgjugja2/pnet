<?php
declare(strict_types=1);
$ctx = stream_context_create([
    'http' => [
        'timeout' => 6,
        'ignore_errors' => true,
        'header' => "User-Agent: Mozilla/5.0\r\n",
    ],
]);
$body = (string) @file_get_contents('http://192.168.0.1/', false, $ctx);
file_put_contents(__DIR__ . '/../data/tplink_login.html', $body);
$needles = ['form', 'action=', 'password', 'login', 'cgi', 'Auth', 'RSA', 'encrypt', 'submit', 'script src', 'TP-LINK', 'tp-link', 'ZTE', 'Huawei', 'admin'];
$out = "len=" . strlen($body) . "\n";
foreach ($needles as $n) {
    $out .= "$n=" . (stripos($body, $n) !== false ? 'yes' : 'no') . "\n";
}
if (preg_match_all('/<form[^>]*>.*?<\/form>/is', $body, $m)) {
    $out .= "forms=" . count($m[0]) . "\n";
    foreach ($m[0] as $i => $f) {
        $out .= "FORM$i=" . substr(preg_replace('/\s+/', ' ', $f), 0, 500) . "\n";
    }
}
if (preg_match_all('/src=["\']([^"\']+)["\']/i', $body, $m)) {
    $out .= "scripts=" . implode(', ', array_slice($m[1], 0, 30)) . "\n";
}
if (preg_match_all('/action=["\']([^"\']+)["\']/i', $body, $m)) {
    $out .= "actions=" . implode(', ', $m[1]) . "\n";
}
file_put_contents(__DIR__ . '/../data/tplink_probe2.txt', $out);
echo $out;
