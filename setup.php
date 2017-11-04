<?php

require_once('database.php');
require_once('global.php');


$showsetupbtn = false;
if(IsAlreadyEstablished($mysqli)) {
	$info = "Your WebPW database is already ready to <a href='login.php' class='styled_link'>use</a>.";
} else {
	$showsetupbtn = true;
	$info = "<b>Database setup ahead</b><br><div>Click the button below to <br>create the required tables.</div><br>";

	if(isset($_POST['action']) && $_POST['action'] == "setup") {
		#if (!$mysqli->multi_query(file_get_contents("sql/clean.sql")))
		#	echo("<b>ERROR DROPPING TABLES:</b><br>" . $mysqli->error . "<br>");
		#clearStoredResults($mysqli);
		if (!$mysqli->multi_query(file_get_contents("sql/pwsafe.sql")))
			die("<b>ERROR CREATING TABLES:</b><br>" . $mysqli->error . "<br>");
		clearStoredResults($mysqli);

		$sql = "INSERT INTO setting (title, value) VALUES (\"managementpassword\", ?)";
		$passwordhash = password_hash($_POST['managementpassword'], PASSWORD_DEFAULT);
		$statement = $mysqli->prepare($sql);
		$statement->bind_param('s', $passwordhash);
		if (!$statement->execute()) {
			die("Execute failed: (" . $statement->errno . ") " . $statement->error);
		}

		$showsetupbtn = false;
		$info = "<b>Setup finished.</b><br>"
		      . "You can now create vaults using the <a href='login.php' class='styled_link'>vault management page</a>.";
	}
}

?>

<!DOCTYPE html>
<html>
<head>
	<title>WebPW - Setup</title>
	<?php require("head.php"); ?>
</head>
<body>

	<div id="contentcontainer">
		<img id="logo" src="img/buzzsaw.svg"></img>
		<form method="POST" action="setup.php">
			<h1>WebPW</h1>
			<h2>web based password safe</h2>
			<div><?php echo $info; ?></div>
			<?php if($showsetupbtn) { ?>
			<input type="hidden" name="action" value="setup">
			<label>Choose a management password:<br><input autofocus="true" type="text" name="managementpassword" value=""></label>
			<input type="submit" value="Set up database">
			<?php } ?>
		</form>
	</div>

</body>
</html>
