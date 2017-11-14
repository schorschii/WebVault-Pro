<?php
	require_once('session.php');
	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	$info = ""; $infotype = "";
	if(isset($_POST['title'])) {
		if($_POST['title'] != "") {

				// insert group
				$sql = "INSERT INTO passwordgroup (title, description) VALUES (?, ?)";
				$statement = $mysqli->prepare($sql);
				$statement->bind_param('ss',
									   $_POST['title'],
									   $_POST['description']
				);
				if (!$statement->execute()) {
					$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
					$infotype = "red";
				} else {
					$info = translate("Successfully created group") . " '".$_POST['title']."'";
					$infotype = "green";
				}

		} else {
			$info = translate("Title should not be empty.");
			$infotype = "red";
		}
	} elseif(isset($_POST['remove'])) {

		// remove group
		$sql = "DELETE FROM passwordgroup WHERE id = ?";
		$statement = $mysqli->prepare($sql);
		$statement->bind_param('i',
							   $_POST['remove']
		);
		if (!$statement->execute()) {
			$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
			$infotype = "red";
		} else {
			$info = translate("Successfully removed group.");
			$infotype = "green";
		}

	}

	$default_title = "";
	$default_description = "";
	$hiddeninput = "";
	$subtitle = translate("Add Group");
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Add New Group'); ?></title>
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
				<th><?php __('Title'); ?>:&nbsp;</th>
				<td><input type="text" name="title" value="<?php echo htmlspecialchars($default_title); ?>"></td>
			</tr>
			<tr>
				<th><?php __('Description'); ?>:&nbsp;</th>
				<td><input type="text" name="description" value="<?php echo htmlspecialchars($default_description); ?>"></td>
			</tr>
			<tr>
				<th></th>
				<td><input type="submit" value="<?php __('Save'); ?>"></td>
			</tr>
		</table>
	</form>

	<h2><?php __('Remove Groups'); ?></h2>
	<table class="inputtable">
		<tr>
			<th><?php __('Title'); ?></th>
			<th><?php __('Remove'); ?></th>
		</tr>
		<?php
		$sql = "SELECT id, title FROM passwordgroup;";
			$statement = $mysqli->prepare($sql);
			$statement->execute();
			$result = $statement->get_result();
			$counter = 0;
			while($row = $result->fetch_object()) {
				$counter ++;
				echo "<tr>";
				echo "<td>" . htmlspecialchars($row->title) . "</td>";
				echo "<td>"
				   . "<form method='POST' onsubmit='return confirm(\"".translate('Remove this entry?') . " " . translate('This will only work if the group is empty.') . "\")'>"
				   . "<input type='hidden' name='remove' value='" . $row->id . "'>"
				   . "<input type='submit' value='".translate("Remove")."' class='remove'>"
				   . "</form>"
				   . "</td>";
				echo "</tr>";
			}
			if($counter == 0) {
				echo "<tr><td colspan='100'>".translate("No groups found.")."</td></tr>";
			}
			?>
	</table>
</div>

<?php require_once("httpwarn.php"); ?>

</body>
</html>
