<?php

$method = "AES-256-CBC";
$encrypted = openssl_encrypt("test", $method, "1234", 0, "wwwwwwwwwwwwwwww");
$decrypted = openssl_decrypt($encrypted, $method, "1234", 0, "wwwwwwwwwwwwwwww");
echo $decrypted;

?>
