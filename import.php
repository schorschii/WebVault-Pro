<?php
	require_once('session.php');
	require_once('global.php');
	require_once('database.php');
	require_once('lang/.init.php');

	$is_preview = false; if(isset($_POST['preview']) && $_POST['preview'] == "1") $is_preview = true;
	$info = ""; $infotype = "";
	if(file_exists('components/parsecsv-for-php/parsecsv.lib.php')) {
		require_once('components/parsecsv-for-php/parsecsv.lib.php');
		$csvcontent = "";
		if(isset($_FILES['importfile'])) {
			$csv = new parseCSV();
			$csv->encoding('ISO-8859-1', 'UTF-8');
			$csv->delimiter = "\t";
			$csv->parse($_FILES['importfile']['tmp_name']);
		}
	} else {
		$infotype = "red";
		$info = translate('ParseCSV-Library not found. Please download it from <a href="https://github.com/parsecsv/parsecsv-for-php">Github</a> and move "parsecsv.lib.php"-file into "components/parsecsv-for-php" directory.');
	}
?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Import'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

<?php require_once("menu.php"); ?>

	<div id="contentcontainer">
		<h1><?php echo translate('Import into') . " " . htmlspecialchars($_SESSION['vaultname']); ?></h1>

		<hr>

		<div><?php __('<b>Expected format: tab-separated</b>, field order:'); ?></div>
		<ul>
			<li>Group/Title (&lt;Group&gt;.&lt;Title&gt;)</li>
			<li>Username</li>
			<li>Password</li>
			<li>URL</li>
			<li>AutoType</li>
			<li>Created Time</li>
			<li>Password Modified Time</li>
			<li>Last Access Time</li>
			<li>Password Expiry Date</li>
			<li>Record Modified Time</li>
			<li>History</li>
			<li>Notes</li>
		</ul>

		<hr>
		<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

		<form method="POST" enctype="multipart/form-data">
			<table class="inputtable">
				<tr>
					<td colspan=2><input type="file" name="importfile"></td>
				</tr>
				<tr>
					<td><label><input type="checkbox" name="preview" value="1" checked>&nbsp;<?php echo translate('Preview only'); ?></label></td>
					<td><input type="submit" value="<?php __('Import'); ?>"></td>
				</tr>
			</table>
		</form>

		<?php if(isset($csv)) {
			if($is_preview) echo "<h1>".translate('Import Preview')."</h1>";
			else echo "<h1>".translate('Imported Records')."</h1>";

			$counter = 0;
			echo "<table border=1>";
			foreach($csv->data as $row) {
				if(isset($row['Group/Title']) && trim($row['Group/Title']) != "") {
					$counter ++;

					// get values from csv parser
					$group = "";
					$title = $row['Group/Title'];
					if(strpos($row['Group/Title'], '.') !== false) { // group is separated from title with a .
						$split = str_getcsv($row['Group/Title'], ".", '"');
						$title = array_pop($split);
						$group = implode(".", $split);
					}
					$username = ""; if(isset($row['Username'])) $username = $row['Username'];
					$password = ""; if(isset($row['Password'])) $password = $row['Password'];
					$url = ""; if(isset($row['URL'])) $url = $row['URL'];
					$notes = ""; if(isset($row['Notes'])) $notes = $row['Notes'];
					$createdtime = ""; if(isset($row['Created Time'])) $createdtime = $row['Created Time'];
					$passwordmodifiedtime = ""; if(isset($row['Password Modified Time'])) $passwordmodifiedtime = $row['Password Modified Time'];

					// echo preview
					echo "<tr>";
					echo "<td>".$group."</td>";
					echo "<td>".$title."</td>";
					echo "<td>".$url."</td>";
					echo "<td>".$createdtime."</td>";
					echo "<td>".$passwordmodifiedtime."</td>";
					echo "<td>".$username."</td>";
					echo "<td>".$password."</td>";
					echo "</tr>";
					if($notes != "") {
						echo "<tr>";
						echo "<td colspan=100 style='color:gray'><pre>".$notes."</pre></td>";
						echo "</tr>";
					}

					// insert into vault
					if(!$is_preview) {
						// check if group exists
						$sql = "SELECT * FROM passwordgroup WHERE title LIKE ?;";
						$statement = $mysqli->prepare($sql);
						$statement->bind_param('s', $group);
						if (!$statement->execute())
							die("Execute failed: (" . $statement->errno . ") " . $statement->error);
						$result = $statement->get_result();
						$group_id = -1;
						while($row = $result->fetch_object()) {
							$group_id = $row->id;
						}

						// create new group if necessary
						if($group_id == -1 && $group != "") {
							$sql = "INSERT INTO passwordgroup (title) VALUES (?);";
							$statement = $mysqli->prepare($sql);
							$statement->bind_param('s', $group);
							if (!$statement->execute())
								die("Execute failed: (" . $statement->errno . ") " . $statement->error);
							$group_id = $statement->insert_id;
						}

						// insert new entry
						$iv = generateIV();
						$encrypted = openssl_encrypt($password, $method, $_SESSION['sessionpassword'], 0, $iv);
						if($group_id == -1) $group_id = NULL;
						$sql = "INSERT INTO password "
							 . "(vault_id, group_id, title, username, password, iv, description, url) "
							 . "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
						$statement = $mysqli->prepare($sql);
						$statement->bind_param('iissssss',
											   $_SESSION['vault'],
											   $group_id,
											   $title,
											   $username,
											   $encrypted,
											   $iv,
											   $notes,
											   $url
						);
						if (!$statement->execute()) {
							die("Execute failed: (" . $statement->errno . ") " . $statement->error);
						} else {
							$info = translate("Added new entries") . " (" . $counter . ")";
							$infotype = "green";
						}
					}
				}
			}
			echo "</table>";

			if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php }
		}
		?>

		<?php if(isset($csv)) { ?>
		<div id="details">
			<button id="btndisplaydetails" onclick="obj('detailscontent').style.display='block';obj('btndisplaydetails').style.display='none';"><?php __('Show Details'); ?></button>
			<pre id="detailscontent" style="display:none;">
				<?php var_dump($csv); ?>
			</pre>
		</div>
		<?php } ?>
	</div>

</body>
</html>
