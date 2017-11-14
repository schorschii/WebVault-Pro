<?php
	require_once('session.php');
	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	$info = ""; $infotype = "";
	if(isset($_POST['title']) && isset($_POST['password'])) {
		if($_POST['title'] != "") {

			if(!isset($_POST['doedit'])) {
				// insert new entry
				$iv = generateIV();
				$encrypted = openssl_encrypt($_POST['password'], $method, $_SESSION['sessionpassword'], 0, $iv);
				$insert_group = $_POST['group'];
				if($insert_group == "NULL") $insert_group = NULL;

				$sql = "INSERT INTO password "
					 . "(vault_id, group_id, title, username, password, iv, description, url) "
					 . "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('iissssss',
									   $_SESSION['vault'],
									   $insert_group,
									   $_POST['title'],
									   $_POST['username'],
									   $encrypted,
									   $iv,
									   $_POST['description'],
									   $_POST['url']
				);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				} else {
					$info = translate("Added new entry") . " '".$_POST['title']."'";
					$infotype = "green";
				}
			} else {
				// edit entry
				$iv = generateIV();
				$encrypted = openssl_encrypt($_POST['password'], $method, $_SESSION['sessionpassword'], 0, $iv);
				$insert_group = $_POST['group'];
				if($insert_group == "NULL") $insert_group = NULL;

				$sql = "UPDATE password "
					 . "SET title = ?, username = ?, password = ?, iv = ?, description = ?, url = ?, group_id = ? "
					 . "WHERE id = ?;";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('ssssssii',
									   $_POST['title'],
									   $_POST['username'],
									   $encrypted,
									   $iv,
									   $_POST['description'],
									   $_POST['url'],
									   $insert_group,
									   $_POST['doedit']
				);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				} else {
					$info = translate("Successfully edited entry") . " '".$_POST['title']."'";
					$infotype = "green";
				}
			}

		} else {
			$info = translate("Title should not be empty.");
			$infotype = "red";
		}
	}

	$default_title = "";
	$default_description = "";
	$default_url = "";
	$default_username = "";
	$default_password = "";
	$default_group = "";
	$hiddeninput = "";
	$subtitle = translate("Add Entry");
	if(isset($_POST['edit'])) {
		$sql = "SELECT * FROM password WHERE id = ?;";
		$statement = $mysqli->prepare($sql);
		$statement->bind_param('i', $_POST['edit']);
		if (!$statement->execute()) {
			echo "Execute failed: (" . $statement->errno . ") " . $statement->error;
		}
		$result = $statement->get_result();
		$counter = 0;
		while($row = $result->fetch_object()) {
			$counter ++;
			$default_group = $row->group_id;
			$default_title = $row->title;
			$default_description = $row->description;
			$default_url = $row->url;
			$default_username = $row->username;
			$decrypted = openssl_decrypt($row->password, $method, $_SESSION['sessionpassword'], 0, $row->iv);
			$default_password = $decrypted;
			$subtitle = translate("Edit Entry");
			$hiddeninput = "<input type='hidden' name='doedit' value='".$row->id."'>";
			break;
		}
	}
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Add New Entry'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php require_once("menu.php"); ?>

<div id="contentcontainer">
	<h1><?php echo htmlspecialchars($_SESSION['vaultname']); ?></h1>
	<h2><?php echo htmlspecialchars($subtitle); ?></h2>

	<br>
	<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

	<form method="POST">
		<?php echo $hiddeninput; ?>
		<table class="inputtable">
			<tr>
				<th><?php __('Group'); ?>:&nbsp;</th>
				<td>
					<select name="group">
						<option value='NULL'><?php __("No group"); ?></option>
						<?php
						$sql = "SELECT id, title, description FROM passwordgroup ";
						$statement = $mysqli->prepare($sql);
						$statement->execute();
						$result = $statement->get_result();
						while($row = $result->fetch_object()) {
							$selected = "";
							if($default_group == $row->id) $selected = "selected";
							echo "<option $selected value='" . $row->id . "' title='" . htmlspecialchars($row->description, ENT_QUOTES) . "'>" . htmlspecialchars($row->title, ENT_QUOTES) . "</option>";
						}
						?>
					</select>
				</td>
			</tr>
			<tr>
				<th><?php __('Title'); ?>:&nbsp;</th>
				<td><input type="text" name="title" value="<?php echo htmlspecialchars($default_title); ?>"></td>
			</tr>
			<tr>
				<th><?php __('Description'); ?>:&nbsp;</th>
				<td><input type="text" name="description" value="<?php echo htmlspecialchars($default_description); ?>"></td>
			</tr>
			<tr>
				<th><?php __('URL to service'); ?>:&nbsp;</th>
				<td><input type="text" name="url" value="<?php echo htmlspecialchars($default_url); ?>"></td>
			</tr>
			<tr>
				<th><?php __('Username'); ?>:&nbsp;</th>
				<td><input type="text" name="username" value="<?php echo htmlspecialchars($default_username); ?>"></td>
			</tr>
			<tr>
				<th><?php __('Password'); ?>:&nbsp;</th>
				<td><input type="password" id="password" name="password" value="<?php echo htmlspecialchars($default_password); ?>"></td>
			</tr>
			<tr>
				<td></td>
				<td><button type="button" title='<?php __("show or hide password"); ?>' onclick='toggleView("password");'>&#9678;</button></td>
			</tr>
			<tr>
				<th></th>
				<td><input type="submit" value="<?php __('Save'); ?>"></td>
			</tr>
		</table>
	</form>
</div>

<?php require_once("httpwarn.php"); ?>

</body>
</html>
