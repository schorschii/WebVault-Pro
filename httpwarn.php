<?php
if(!isset($_SERVER['HTTPS'])) {
	echo "<div id='httpwarn' onclick='this.style.display=\"none\";' style='cursor:pointer;'>";
	echo translate("You are accessing this site via HTTP. This is very insecure. Please consider using HTTPS.");
	echo "</div>";
}
?>
