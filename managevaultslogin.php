<?php

require_once('database.php');
require_once('global.php');
require_once('lang/.init.php');

if(isset($_POST['managementpassword'])) {
	$sql = "SELECT * FROM setting WHERE title = \"managementpassword\"";
		$statement = $mysqli->prepare($sql);
		$statement->execute();
		$result = $statement->get_result();
		while($row = $result->fetch_object()) {
			if(password_verify($_POST['managementpassword'], $row->value)) {
				$_SESSION['management_auth_ok'] = true;
				break;
			} else {
				sleep(1);
			}
		}
} elseif(isset($_GET['logout']) && $_GET['logout'] == "1") {
	$_SESSION['management_auth_ok'] = false;
}
if(isset($_SESSION['management_auth_ok']) && $_SESSION['management_auth_ok'] == true) {
	header("Location: managevaults.php");
	exit();
}

?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Login'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php $loginmenu = true; require_once("menu.php"); ?>

	<div id="contentcontainer">
		<h1><?php __('Manage Vaults'); ?></h1>
		<form method="POST">
			<?php __('Enter management password'); ?>:<br>
			<input type="password" name="managementpassword">
			<input type="submit" value="<?php __('Login'); ?>">
		</form>
	</div>

	<?php require_once("httpwarn.php"); ?>

</body>
</html>
