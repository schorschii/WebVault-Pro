<?php
	require_once('session.php');
	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	if(!IsAlreadyEstablished($mysqli)) {
		header("Location: setup.php");
		die();
	}

	$info = ""; $infotype = "";
	if(isset($_POST['remove']) && $_POST['remove'] != "") {
		$sql = "DELETE FROM password WHERE id = ?;";
		$statement = $mysqli->prepare($sql);
		$statement->bind_param('i', $_POST['remove']);
		if (!$statement->execute()) {
			$info = "Execute failed: (" . $statement->errno . ") " . $statement->error;
			$infotype = "red";
		} else {
			$info = translate("Entry removed.");
			$infotype = "green";
		}
	}
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Vault Overview'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php require_once("menu.php"); ?>

<div id="contentcontainer">
	<h1><?php echo $_SESSION['vaultname']; ?></h1>

	<br>
	<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

	<table class="resulttable">
		<tr>
			<th><?php __('Title'); ?></th>
			<th><?php __('Description'); ?></th>
			<th><?php __('URL to service'); ?></th>
			<th><?php __('Username'); ?></th>
			<th><?php __('Password'); ?></th>
		</tr>

		<?php
		$sql = "SELECT p.id AS 'id', pg.id AS 'group_id', pg.title AS 'group', p.title AS 'title', p.username AS 'username', p.password AS 'password', p.iv AS 'iv', p.description AS 'description', p.url AS 'url' "
		     . "FROM password p LEFT JOIN passwordgroup pg ON p.group_id = pg.id "
		     . "WHERE vault_id = ? ORDER BY group_id";
			$statement = $mysqli->prepare($sql);
			$statement->bind_param('i', $_SESSION['vault']);
			$statement->execute();
			$result = $statement->get_result();
			$counter = 0;
			$last_group = NULL;
			while($row = $result->fetch_object()) {
				$counter ++;
				// display group header, if group changed
				if($last_group != $row->group_id) {
					echo "<tr><th colspan='100'>" . $row->group . "</th></tr>\n";
					$last_group = $row->group_id;
				}

				// display entry
				$decrypted = openssl_decrypt($row->password, $method, $_SESSION['sessionpassword'], 0, $row->iv);
				echo "<tr>\n";
				echo "<td>" . $row->title . "</td>\n";
				echo "<td title='" . $row->description . "'>" . shortText($row->description) . "</td>\n";
				echo "<td>"
				   . "<a target='_blank' href='" . $row->url . "'>" . shortText($row->url) . "</a>"
				   . "</td>\n";
				echo "<td>"
				   . "<input type='text' value='" . $row->username . "' id='userbox".$row->id."' readonly>"
				   . "<button title='".translate("copy username to clipboard")."' onclick='toClipboard(\"userbox".$row->id."\");'>&#9997;</button>"
				   . "</td>\n";
				echo "<td>"
				   . "<input type='password' value='" . $decrypted . "' id='pwbox".$row->id."' readonly>"
				   . "<button title='".translate("show or hide password")."' onclick='toggleView(\"pwbox".$row->id."\");'>&#9678;</button>"
				   . "<button title='".translate("copy password to clipboard")."' onclick='toClipboard(\"pwbox".$row->id."\");'>&#9997;</button>"
				   . "</td>\n";
				echo "<td>"
				   . "<form method='POST' action='new.php'><input type='hidden' name='edit' value='".$row->id."'><button title='".translate("edit this password entry")."' type='submit'>&#9998;</button></form>"
				   . "<form method='POST' onsubmit='return confirm(\"".translate("Remove this entry?")."\");'><input type='hidden' name='remove' value='".$row->id."'><button title='".translate("remove this password entry")."' type='submit' class='remove'>&#10006;</button></form>"
				   . "</td>";
				echo "</tr>\n";
			}

			if($counter == 0) {
				echo "<tr><td colspan='100'>".translate("No entries in this vault.")."</td></tr>";
			}
			?>
		</table>
	</div>

	<?php require_once("httpwarn.php"); ?>

</body>
</html>
