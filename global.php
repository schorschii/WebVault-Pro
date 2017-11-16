<?php

$method = "AES-256-CBC";
$defaultlang = "en"; // default language

function shortText($longtext) {
	$maxlength = 21;
	return strlen($longtext) > $maxlength ? substr($longtext,0,$maxlength)."..." : $longtext;
}

function generateIV() {
	#$wasItSecure = false;
	#$iv = openssl_random_pseudo_bytes(16, $wasItSecure);
	#if (!$wasItSecure)
	#	echo "PHP failed to generate a secure IV.";
	return substr(base64_encode(md5(microtime())),rand(0,26),16);
}

function correctVaultPassword($vault, $password) {
	global $mysqli;
	global $method;
	$sql = "SELECT title, password_test, iv_test "
		 . "FROM vault "
		 . "WHERE id = ?";
	$statement = $mysqli->prepare($sql);
	$statement->bind_param('i', $vault);
	$statement->execute();
	$result = $statement->get_result();
	while($row = $result->fetch_object()) {
		$test_decrypted = openssl_decrypt($row->password_test, $method, $password, 0, $row->iv_test);
		if($test_decrypted != "" && $test_decrypted == $password) {
			$_SESSION['vaultname'] = $row->title;
			return true;
		}
		break;
	}
	return false;
}

function IsAlreadyEstablished($mysqli) {
	$statement = $mysqli->prepare("SHOW TABLES LIKE 'setting';");
	$statement->execute();
	$statement->store_result();
	return $statement->num_rows > 0;
}

function clearStoredResults($mysqli){
	do {
		if ($res = $mysqli->store_result()) {
			$res->free();
		}
	} while ($mysqli->more_results() && $mysqli->next_result());
}

function startsWith($haystack, $needle)
{
	$length = strlen($needle);
	return (substr($haystack, 0, $length) === $needle);
}

function endsWith($haystack, $needle)
{
	$length = strlen($needle);
	return $length === 0 ||
	(substr($haystack, -$length) === $needle);
}

function escapeOnlyQuotes($string) {
	return str_replace('"', '\"', $string);
}

?>
