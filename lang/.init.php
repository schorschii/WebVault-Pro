<?php

require_once("global.php"); // for default language
$langfile = "lang/".$defaultlang.".php"; // default language file

// check if language preference is set in this session
if(!isset($_SESSION))
	session_start();
#echo "LANG:".$_SESSION['lang']; // debug
if(isset($_SESSION['lang']) && file_exists("lang/".$_SESSION['lang'].".php"))
	$langfile = "lang/".$_SESSION['lang'].".php";

// include translation file
require_once($langfile);


// function for translating and echoing strings
function __($translate) {
	global $LANG;

	if(isset($LANG[$translate]))
		echo $LANG[$translate];
	else
		echo $translate;
}

// function for translating and returning strings
function translate($translate) {
	global $LANG;

	if(isset($LANG[$translate]))
		return $LANG[$translate];
	else
		return $translate;
}

?>
