<?php
(PHP_SAPI !== 'cli' || isset($_SERVER['HTTP_USER_AGENT'])) && die('CLI usage only');

require_once 'vendor/autoload.php';
require_once 'config/settings.php';

$db = new XVault\Controllers\DatabaseController($settings['db']);

$ldap = new XVault\Controllers\LdapSyncController($settings['ldapSync'], $db, true);
$ldap->sync();
