<?php

require_once('database.php');
require_once('global.php');
require_once('lang/.init.php');

if(!IsAlreadyEstablished($mysqli)) {
	header("Location: setup.php");
	die();
}


$info = ""; $infotype = "";
$default_vault = "";
if (isset($_POST['vault']) && isset($_POST['password'])) {
	$vault = $_POST['vault']; $password = $_POST['password'];
	if (correctVaultPassword($vault, $password)) {
		$_SESSION['vault'] = $vault;
		$_SESSION['sessionpassword'] = $password;
		header('Location: index.php');
	} else {
		sleep(1); // wait for exacerbate brute force attacks
		$default_vault = $_POST['vault'];
		$info = translate("Invalid password.");
		$infotype = "red";
	}
} elseif (isset($_GET['logout']) || isset($_POST['logout'])) {
	session_unset();
	session_destroy();
	$info = translate("Successfully logged out.");
	$infotype = "green";
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
		<form method="POST" action="login.php">
			<h1><?php __('WebPW'); ?></h1>
			<h2><?php __('web based password safe'); ?></h2>

			<br>
			<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>
			<table class="inputtable">
				<tr>
					<th><?php __('Vault'); ?>:&nbsp;</th>
					<td>
						<div id="vault" class="inputwithimg">
							<select name="vault" autofocus="true" title="<?php __('select vault to unlock'); ?>">
								<?php
								$sql = "SELECT id, title FROM vault;";
								$statement = $mysqli->prepare($sql);
								$statement->execute();
								$result = $statement->get_result();
								$counter = 0;
								while($row = $result->fetch_object()) {
									$counter ++;
									$selected = "";
									if($row->id == $default_vault) $selected = "selected";
									echo "<option $selected value='" . $row->id . "'>" . htmlspecialchars($row->title) . "</option>";
								}
								if($counter == 0) {
									echo "<option>".translate("No vault found")."</option>";
								}
								?>
							</select>
						</div>
					</td>
				</tr>
				<tr>
					<th><?php __('Password'); ?>:&nbsp;</th>
					<td>
						<div id="password" class="inputwithimg">
							<input type="password" name="password" title="<?php __('enter password'); ?>" <?php if($counter==0) echo "disabled"; ?>>
						</div>
					</td>
				</tr>
				<tr>
					<th></th>
					<td><input type="submit" value="<?php __('Open Vault'); ?>" <?php if($counter==0) echo "disabled"; ?>></td>
				</tr>
			</table>
		</form>
	</div>

	<?php require_once("httpwarn.php"); ?>

</body>
</html>
