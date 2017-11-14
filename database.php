<?php
	/* please replace the following values with the credentials to your mysql server */
	$db_host = "localhost";
	$db_user = "root";
	$db_password = "PASSWORD";
	$db_databasename = "pwsafe";

	/* ===== DO NOT TOUCH THE FOLLOWING CODE ===== */
	$mysqli = new mysqli($db_host, $db_user, $db_password, $db_databasename);
	if ($mysqli->connect_errno) {
		die("Failed to connect to database server: " . $mysqli->connect_error);
	}

	if (version_compare(phpversion(), '6.9.9', '<')) {
		die("This application requires PHP 7.");
	}
?>
