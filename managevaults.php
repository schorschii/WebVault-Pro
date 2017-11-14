<?php
	#die();

	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	if(!isset($_SESSION['management_auth_ok'])) {
		header("Location: managevaultslogin.php");
		exit();
	} elseif($_SESSION['management_auth_ok'] == false) {
		header("Location: managevaultslogin.php");
		exit();
	}

	$info = "";
	$infotype = "";

	// create new vault if requested
	if(isset($_POST['password']) && isset($_POST['title'])) {
		if($_POST['title'] != "" && $_POST['password'] != "") {
			if($_POST['password'] == $_POST['password2']) {

				$iv = generateIV();
				$encrypted = openssl_encrypt($_POST['password'], $method, $_POST['password'], 0, $iv);

				$sql = "INSERT INTO vault (title, password_test, iv_test) VALUES (?, ?, ?)";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('sss', $_POST['title'], $encrypted, $iv);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				} else {
					$info = translate("New vault created successfully.");
					$infotype = "green";
				}

			} else {
				$info = translate("Passwords are not matching.");
				$infotype = "red";
			}
		} else {
			$info = translate("Title and password must not be empty.");
			$infotype = "red";
		}
	}

	// change vault's password if requested
	if(isset($_POST['changepassword']) && isset($_POST['oldpassword']) && isset($_POST['password']) && isset($_POST['password2'])) {
		if($_POST['password'] != "" && $_POST['password2'] != "") {
			if($_POST['password'] == $_POST['password2']) {

				if(correctVaultPassword($_POST['changepassword'], $_POST['oldpassword'])) {
					$sql = "SELECT id, password, iv FROM password "
					     . "WHERE vault_id = ?";
					$statement = $mysqli->prepare($sql);
					$statement->bind_param('i', $_POST['changepassword']);
					$statement->execute();
					$result = $statement->get_result();
					$counter = 0; $error = false;
					while($row = $result->fetch_object()) {
						$counter ++;
						$decrypted = openssl_decrypt($row->password, $method, $_POST['oldpassword'], 0, $row->iv);

						// update all password entries
						$iv = generateIV();
						$encrypted = openssl_encrypt($decrypted, $method, $_POST['password'], 0, $iv);
						$sql = "UPDATE password SET password = ?, iv = ? WHERE id = ?";
						$statement = $mysqli->prepare($sql);
						$statement->bind_param('ssi', $encrypted, $iv, $row->id);
						if (!$statement->execute()) {
							$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
							$infotype = "red";
							$error = true;
						} else {
							$info = translate("Vault password changed successfully.");
							$infotype = "green";
						}
					}

					// update vault record
					$iv = generateIV();
					$encrypted = openssl_encrypt($_POST['password'], $method, $_POST['password'], 0, $iv);
					$sql = "UPDATE vault SET password_test = ?, iv_test = ? WHERE id = ?";
					$statement = $mysqli->prepare($sql);
					$statement->bind_param('ssi', $encrypted, $iv, $_POST['changepassword']);
					if (!$statement->execute()) {
						$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
						$infotype = "red";
						$error = true;
					} else {
						$info = translate("Vault password changed successfully.");
						$infotype = "green";
					}
				} else {
					$info = translate("Old password is invalid.");
					$infotype = "red";
				}

			} else {
				$info = translate("New passwords are not matching.");
				$infotype = "red";
			}
		} else {
			$info = translate("New password must not be empty.");
			$infotype = "red";
		}
	}

	// remove vault if requested
	if(isset($_POST['remove'])) {
		if($_POST['remove'] != "") {

				$sql = "DELETE FROM password WHERE vault_id = ?;";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('i', $_POST['remove']);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				}
				$sql = "DELETE FROM vault WHERE id = ?;";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('i', $_POST['remove']);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				} else {
					$info = translate("Vault deleted successfully.");
					$infotype = "green";
				}

		} else {
			$info = translate("New password must not be empty.");
			$infotype = "red";
		}
	}
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Manage Vaults'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php $loginmenu = true; require_once("menu.php"); ?>

<div id="contentcontainer">
	<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

	<h1><?php __('Manage Vaults'); ?></h1>

	<h2><?php __('Create Vault'); ?></h2>
	<form method="POST">
		<table class="inputtable">
			<tr>
				<th><?php __('Title'); ?>:&nbsp;</th>
				<td><input type="text" name="title"></td>
			</tr>
			<tr>
				<th><?php __('Choose a Password'); ?>:&nbsp;</th>
				<td><input type="password" name="password"></td>
			</tr>
			<tr>
				<th><?php __('Repeat Password'); ?>:&nbsp;</th>
				<td><input type="password" name="password2"></td>
			</tr>
			<tr>
				<th></th>
				<td><input type="submit" value="<?php __('Create'); ?>"></td>
			</tr>
		</table>
	</form>

	<h2><?php __("Change Vault's Password"); ?></h2>
	<form method="POST" onsubmit='return confirm("Are you sure?")'>
		<table class="inputtable">
			<tr>
				<th><?php __('Vault'); ?>:&nbsp;</th>
				<td>
					<select name="changepassword" autofocus="true">
						<?php
						$sql = "SELECT id, title FROM vault ";
						$statement = $mysqli->prepare($sql);
						$statement->execute();
						$result = $statement->get_result();
						$counter = 0;
						while($row = $result->fetch_object()) {
							$counter ++;
							echo "<option value='" . $row->id . "'>" . $row->title . "</option>";
						}
						if($counter == 0) {
							echo "<option value='-1'>".translate("No vault found")."</option>";
						}
						?>
					</select>
				</td>
			</tr>
			<tr>
				<th><?php __('Old Password'); ?>:&nbsp;</th>
				<td><input type="password" name="oldpassword"></td>
			</tr>
			<tr>
				<th><?php __('New Password'); ?>:&nbsp;</th>
				<td><input type="password" name="password"></td>
			</tr>
			<tr>
				<th><?php __('Repeat New Password'); ?>:&nbsp;</th>
				<td><input type="password" name="password2"></td>
			</tr>
			<tr>
				<th></th>
				<td><input type="submit" value="<?php __('Change Password'); ?>"></td>
			</tr>
		</table>
	</form>

	<h2><?php __('Remove Vaults'); ?></h2>
	<table class="inputtable">
		<tr>
			<th><?php __('Title'); ?></th>
			<th><?php __('Remove'); ?></th>
		</tr>
		<?php
		$sql = "SELECT id, title FROM vault;";
			$statement = $mysqli->prepare($sql);
			$statement->execute();
			$result = $statement->get_result();
			$counter = 0;
			while($row = $result->fetch_object()) {
				$counter ++;
				echo "<tr>";
				echo "<td>" . htmlspecialchars($row->title) . "</td>";
				echo "<td>"
				   . "<form method='POST' onsubmit='return confirm(\"".translate('Remove this entry?'). " " . translate('All password entries will be lost!') ."\")'>"
				   . "<input type='hidden' name='remove' value='" . $row->id . "'>"
				   . "<input type='submit' value='".translate("Remove")."' class='remove'>"
				   . "</form>"
				   . "</td>";
				echo "</tr>";
			}
			if($counter == 0) {
				echo "<tr><td colspan='100'>".translate("No vaults found.")."</td></tr>";
			}
			?>
	</table>

	<h2><?php __('Exit Management Session'); ?></h2>
	<form method="GET" action="managevaultslogin.php">
		<input type="hidden" name="logout" value="1">
		<table class="inputtable">
			<tr><td><input type="submit" value="<?php __('Log Out'); ?>"></td></tr>
		</table>
	</form>
</div>

<?php require_once("httpwarn.php"); ?>

</body>
</html>
