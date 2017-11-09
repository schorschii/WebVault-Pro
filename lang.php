<?php

$info = ""; $infotype = "";
// change language for this session, if requested
if(isset($_POST['setlang']) && file_exists("lang/".$_POST['setlang'].".php")) {
	session_start();
	$_SESSION['lang'] = $_POST['setlang'];
	$info = "Language was set to" . " '".$_SESSION['lang']."'";
	$infotype = "green";
}

require_once('lang/.init.php');

?>

<!DOCTYPE html>
<html>
<head>
	<title><?php __('WebPW'); ?> - <?php __('Language'); ?></title>
	<?php require("head.php"); ?>
</head>
<body>

	<?php $loginmenu = true; require_once("menu.php"); ?>

	<div id="contentcontainer">
		<h1><?php __('Change language'); ?></h1>

		<?php if($info != "") { ?><div class="infobox <?php echo $infotype; ?>"><?php echo $info; ?></div><?php } ?>

		<form method="POST">
			<select name="setlang">
				<?php
				foreach(scandir("lang") as $file) {
					if(substr($file,0,1) == ".") continue;
					$file = basename($file, ".php");
					echo "<option>$file</option>";
				}
				?>
			</select>
			<input type="submit" value="<?php __('Set Language'); ?>">
		</form>
	</div>

</body>
</html>
