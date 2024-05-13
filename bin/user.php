<?php
(PHP_SAPI !== 'cli' || isset($_SERVER['HTTP_USER_AGENT'])) && die('CLI usage only');

require_once 'vendor/autoload.php';
require_once 'config/settings.php';

$db = new WebVault\Controllers\DatabaseController($settings['db']);

switch($argv[1] ?? '') {
	case 'list':
		foreach($db->selectAllUser() as $user) {
			echo $user->id."\t".$user->username."\t".$user->display_name."\n";
		}
		break;

	case 'create':
		if(empty($argv[2]) || empty($argv[3]) || empty($argv[4])) {
			die('Usage: php user.php create USERNAME DISPLAY_NAME PASSWORD'."\n");
		}
		$id = $db->insertUser(null, $argv[2], $argv[3], password_hash($argv[4],PASSWORD_DEFAULT), 0/*ldap*/, null/*email*/, null/*description*/, 0);
		echo 'Created user #'.$id."\n";
		break;

	case 'delete':
		if(empty($argv[2])) {
			die('Usage: php user.php delete USER_ID'."\n");
		}
		if($db->deleteUser($argv[2])) {
			echo 'Deleted user #'.$argv[2]."\n";
		} else {
			echo 'No user found with ID #'.$argv[2]."\n";
		}
		break;

	default:
		die('Usage: php user.php list|create|delete <ARGUMENTS>'."\n");
}
