<?php

require_once '../vendor/autoload.php';
require_once '../config/general.php';
require_once '../config/database.php';

require_once "../src/controllers/RedirectController.php";
require_once "../src/controllers/LoginController.php";
require_once "../src/controllers/VaultController.php";
require_once "../src/controllers/LanguageController.php";

require_once "../src/twig-extensions/TranslateFilterExtension.php";
require_once "../src/twig-extensions/ShortFilterExtension.php";


require_once "../src/slim-init.php";
require_once "../src/routes.php";


/******************************/
/********* START MAGIC ********/
$app->run();
/******************************/
