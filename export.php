<?php
	require_once('session.php');
	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	$info = ""; $infotype = "";
	if(isset($_POST['exporttype']) && ($_POST['exporttype'] == "tab" || $_POST['exporttype'] == "csv" || $_POST['exporttype'] == "html")) {
		if(correctVaultPassword($_SESSION['vault'], $_POST['vaultpassword'])) {
			if($_POST['exporttype'] == "csv") {
				header("Content-Type: text/comma-separated-values");
				header("Content-Disposition: attachment; filename=\"pwexport.csv\"");
			} elseif($_POST['exporttype'] == "tab") {
				header("Content-Type: text/tab-separated-values");
				header("Content-Disposition: attachment; filename=\"pwexport.tsv\"");
			} elseif($_POST['exporttype'] == "html") {
				header("Content-Type: text/html");
				header("Content-Disposition: attachment; filename=\"pwexport.html\"");
			}

			$sql = "SELECT p.id AS 'id', pg.id AS 'group_id', pg.title AS 'group', pg.description AS 'group_desc', p.title AS 'title', p.username AS 'username', p.password AS 'password', p.iv AS 'iv', p.description AS 'description', p.url AS 'url' "
			     . "FROM password p LEFT JOIN passwordgroup pg ON p.group_id = pg.id "
			     . "WHERE vault_id = ? ORDER BY group_id";
			$statement = $mysqli->prepare($sql);
			$statement->bind_param('i', $_SESSION['vault']);
			$statement->execute();
			$result = $statement->get_result();
			$last_group = NULL;
			$counter = 0;
			while($row = $result->fetch_object()) {
				$counter ++;

				$decrypted = openssl_decrypt($row->password, $method, $_SESSION['sessionpassword'], 0, $row->iv);

				if($_POST['exporttype'] == "csv") {
					if($row->group != "") echo $row->group.".".$row->title;
					else echo $row->title;
					echo ";";
					echo '"'.escapeOnlyQuotes($row->username).'"' . ";";
					echo '"'.escapeOnlyQuotes($decrypted).'"' . ";";
					echo '"'.escapeOnlyQuotes($row->url).'"' . ";";
					echo "" . ";"; // column "AutoType" not implemented
					echo "" . ";"; // column "Created Time" not implemented
					echo "" . ";"; // column "Password Modified Time" not implemented
					echo "" . ";"; // column "Last Access Time" not implemented
					echo "" . ";"; // column "Password Expiry Date" not implemented
					echo "" . ";"; // column "Record Modified Time" not implemented
					echo "" . ";"; // column "History" not implemented
					echo '"'.escapeOnlyQuotes($row->description).'"' . "\n";
				} elseif($_POST['exporttype'] == "tab") {
					if($row->group != "") echo $row->group.".".$row->title;
					else echo $row->title;
					echo "\t";
					echo '"'.escapeOnlyQuotes($row->username).'"' . "\t";
					echo '"'.escapeOnlyQuotes($decrypted).'"' . "\t";
					echo '"'.escapeOnlyQuotes($row->url).'"' . "\t";
					echo "" . "\t"; // column "AutoType" not implemented
					echo "" . "\t"; // column "Created Time" not implemented
					echo "" . "\t"; // column "Password Modified Time" not implemented
					echo "" . "\t"; // column "Last Access Time" not implemented
					echo "" . "\t"; // column "Password Expiry Date" not implemented
					echo "" . "\t"; // column "Record Modified Time" not implemented
					echo "" . "\t"; // column "History" not implemented
					echo '"'.escapeOnlyQuotes($row->description).'"' . "\n";
				} elseif($_POST['exporttype'] == "html") {
					if($last_group != $row->group_id) {
						echo "<h1>" . htmlspecialchars($row->group) . "</h1>";
						echo "<hr>";
					}
					echo "<h2>" . htmlspecialchars($row->title) . "</h2>";
					echo "<table>";
					echo "<tr><th>".translate('Username')."</th><td>".htmlspecialchars($row->username)."</td></tr>";
					echo "<tr><th>".translate('Password')."</th><td>".htmlspecialchars($decrypted)."</td></tr>";
					echo "<tr><th>".translate('URL to service')."</th><td>".htmlspecialchars($row->url)."</td></tr>";
					echo "<tr><th>".translate('Description')."</th><td>".str_replace("\n", "<br>", htmlspecialchars($row->description))."</td></tr>";
					echo "</table>";
					$last_group = $row->group_id;
				}
			}

			exit(); // just download the export, don't display interface
		} else {
			$info = translate('Vault passwort is not correct.');
			$infotype = "red";
		}
	}
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Export'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php require_once("menu.php"); ?>

	<div id="contentcontainer">
		<h1><?php echo translate('Export from') . " " . htmlspecialchars($_SESSION['vaultname']); ?></h1>
		<br>
		<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>
		<form method="POST">
			<table class="inputtable">
			<tr><th colspan=100><?php __('Please choose a format to export passwords.'); ?></th></tr>
			<tr><td colspan=100><?php __('Passwords will be exported in CLEARTEXT! Please be careful.'); ?></td></tr>
			<tr><td>&nbsp;</td></th>
			<tr>
				<th><?php __('Vault Password'); ?>:&nbsp;</th>
				<td colspan=100><input type="password" name="vaultpassword"></td>
			<tr>
				<td><label><input type="radio" name="exporttype" value="tab">&nbsp;<?php __('Tab-Separated'); ?></label></td>
				<td><label><input type="radio" name="exporttype" value="csv">&nbsp;<?php __('Comma-Separated (CSV)'); ?></label></td>
				<td><label><input type="radio" name="exporttype" value="html">&nbsp;<?php __('HTML (for printing)'); ?></label></td>
			</tr>
			<tr>
				<td colspan=100><input type="submit" value="<?php __('Export'); ?>"></td>
			</tr>
		</form>
	</div>

</body>
</html>
