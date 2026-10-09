<?php
$js = file_get_contents(__DIR__ . '/../data/tplink_tpEncrypt.js');
// Pretty-print roughly by inserting newlines
$js = preg_replace('/([{};])/', "$1\n", $js);
file_put_contents(__DIR__ . '/../data/tplink_tpEncrypt_pretty.js', $js);

$js2 = file_get_contents(__DIR__ . '/../data/tplink_encrypt.js');
$js2 = preg_replace('/([{};])/', "$1\n", $js2);
file_put_contents(__DIR__ . '/../data/tplink_encrypt_pretty.js', $js2);

// Find Iencryptor / Encryptor definitions in all downloaded files + login html
$html = file_get_contents(__DIR__ . '/../data/tplink_login.html');
foreach (['Iencryptor', 'Encryptor', 'setHash', 'genAESKey', 'newencryptor', 'sign'] as $term) {
    echo $term . '_tp=' . (stripos($js, $term) !== false ? 'y' : 'n')
        . ' enc=' . (stripos($js2, $term) !== false ? 'y' : 'n')
        . ' html=' . (stripos($html, $term) !== false ? 'y' : 'n') . "\n";
}
