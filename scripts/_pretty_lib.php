<?php
$src = __DIR__ . '/../data/tplink_lib.js';
$dst = __DIR__ . '/../data/tplink_lib_pretty.js';
$js = file_get_contents($src);
$js = preg_replace('/([{};])/', "$1\n", $js);
file_put_contents($dst, $js);
echo strlen($js);
