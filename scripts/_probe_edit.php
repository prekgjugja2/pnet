<?php
declare(strict_types=1);
require dirname(__DIR__) . '/lib/app.php';
$pdo = pnet_boot();
@unlink(pnet_tplink_session_path());
$queries = [
    'lan' => "1\r\n[LAN_HOST_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
    'fw' => "1\r\n[FIREWALL#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
    'rules' => "5\r\n[RULE#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
    'url' => "1\r\n[URL_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
    'wlan' => "1\r\n[LAN_WLAN#1,1,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
    'acl' => "1\r\n[ACL_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n",
];
$out = [];
foreach ($queries as $name => $q) {
    $text = pnet_tplink_cgi($pdo, $q);
    $safe = preg_replace('/[^\x20-\x7E\r\n]/', '.', $text) ?? '';
    $out[$name] = substr($safe, 0, 900);
}
file_put_contents(__DIR__ . '/_edit_out.txt', json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "wrote\n";
