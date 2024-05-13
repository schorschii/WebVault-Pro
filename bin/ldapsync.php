<?php
(PHP_SAPI !== 'cli' || isset($_SERVER['HTTP_USER_AGENT'])) && die('CLI usage only');

require_once 'vendor/autoload.php';
require_once 'config/settings.php';

$db = new WebVault\Controllers\DatabaseController($settings['db']);

$ldap = new WebVault\Controllers\LdapSyncController($settings['ldapSync'], $db, true);
$ldap->sync();
