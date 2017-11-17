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

<div id="contentcontainer" class="passwordentries">
	<h1><?php echo htmlspecialchars($_SESSION['vaultname']); ?></h1>
	<div id="searchresults" style="display:none">
		<span id="searchresultstext"><span id="searchresultcount"></span>&nbsp;<?php __('result(s)'); ?>&nbsp;<button onclick="clearSearch()"><?php __('Close Search'); ?></button></span>
	</div>

	<br>
	<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

	<table class="resulttable" id="passwordentriestable">
		<tr>
			<th><?php __('Title'); ?></th>
			<th class="description"><?php __('Description'); ?></th>
			<th><?php __('URL to service'); ?></th>
			<th><?php __('Username'); ?></th>
			<th><?php __('Password'); ?></th>
		</tr>

		<?php
		$sql = "SELECT p.id AS 'id', pg.id AS 'group_id', pg.title AS 'group', pg.description AS 'group_desc', p.title AS 'title', p.username AS 'username', p.password AS 'password', p.iv AS 'iv', p.description AS 'description', p.url AS 'url' "
		     . "FROM password p LEFT JOIN passwordgroup pg ON p.group_id = pg.id "
		     . "WHERE vault_id = ? ORDER BY pg.title ASC";
			$statement = $mysqli->prepare($sql);
			$statement->bind_param('i', $_SESSION['vault']);
			$statement->execute();
			$result = $statement->get_result();
			$counter = 0;
			$groupview = "collapsed";
			if(isset($_GET['groupview'])) $groupview = $_GET['groupview'];
			$last_group = NULL;
			$entry_style = "";
			$group_collapsebtn_style = "display:none";
			$group_expandbtn_style = "";
			$entry_class = "entry_without_group";
			while($row = $result->fetch_object()) {
				$counter ++;
				// display group header, if we reached next group
				if($last_group != $row->group_id) {
					if($groupview != "expanded") { $entry_style = "display:none"; $group_collapsebtn_style = "display:none"; }
					if($groupview == "expanded") { $group_expandbtn_style = "display:none"; $group_collapsebtn_style = ""; }
					echo "<tr>";
					echo "<th colspan='100' class='groupheader' group='".$row->group_id."'>";
					echo "<button onclick='showRows(".$row->group_id.")' class='btnplusminus btnplus' id='btnplus".$row->group_id."' title='".translate('expand group')."' style='$group_expandbtn_style'>&#10133;</button>";
					echo "<button onclick='hideRows(".$row->group_id.")' class='btnplusminus btnminus' id='btnminus".$row->group_id."' title='".translate('collapse group')."' style='$group_collapsebtn_style'>&#10134;</button>";
					echo "<div class='grouptext'>";
					echo "<div class='grouptitle'>" . htmlspecialchars($row->group) . "</div>";
					echo "<div class='groupdescription'>" . htmlspecialchars($row->group_desc) . "</div>";
					echo "</div>";
					echo "</th>";
					echo "</tr>\n";
					$last_group = $row->group_id;
					$entry_class = "";
				}

				// display entry
				$decrypted = openssl_decrypt($row->password, $method, $_SESSION['sessionpassword'], 0, $row->iv);
				$url = $row->url; if(!(startsWith($row->url, "http://") || startsWith($row->url, "https://") || startsWith($row->url, "ftp://"))) $url = "http://".$url;
				echo "<tr class='entry $entry_class' group='".$row->group_id."' style='$entry_style'>\n";
				echo "<td class='title' title='" . htmlspecialchars($row->title, ENT_QUOTES) . "'>" . htmlspecialchars(shortText($row->title), ENT_QUOTES) . "</td>\n";
				echo "<td class='description' title='" . htmlspecialchars($row->description, ENT_QUOTES) . "'>" . htmlspecialchars(shortText($row->description), ENT_QUOTES) . "</td>\n";
				echo "<td>"
				   . "<a class='url' target='_blank' href='" . $url . "'>" . htmlspecialchars(shortText($row->url), ENT_QUOTES) . "</a>"
				   . "</td>\n";
				echo "<td>"
				   . "<input class='username' type='text' value='" . htmlspecialchars($row->username, ENT_QUOTES) . "' id='userbox".$row->id."' readonly>"
				   . "<button title='".translate("copy username to clipboard")."' onclick='toClipboard(\"userbox".$row->id."\");'>&#9997;</button>"
				   . "</td>\n";
				echo "<td>"
				   . "<input class='password' type='password' value='" . htmlspecialchars($decrypted, ENT_QUOTES) . "' id='pwbox".$row->id."' readonly>"
				   . "<div class='inlineblock'>"
				   . "<button title='".translate("show or hide password")."' onclick='toggleView(\"pwbox".$row->id."\");'>&#9678;</button>"
				   . "<button title='".translate("copy password to clipboard")."' onclick='toClipboard(\"pwbox".$row->id."\");'>&#9997;</button>"
				   . "</div>"
				   . "</td>\n";
				echo "<td>"
				   . "<form method='POST' action='new.php'><input type='hidden' name='edit' value='".$row->id."'><button title='".translate("edit this password entry")."' type='submit'>&#9998;</button></form>"
				   . "<form method='POST' onsubmit='return confirm(\"".translate('Remove this entry?')."\");'><input type='hidden' name='remove' value='".$row->id."'><button title='".translate("remove this password entry")."' type='submit' class='remove'>&#10006;</button></form>"
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
