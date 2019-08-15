<?php

const WEBPW_VERSION = '0.2';


// set max session length
$session_length_seconds = 60/*s*/ * 15/*m*/;
ini_set('session.gc_maxlifetime', $session_length_seconds); // server should keep session data
session_set_cookie_params($session_length_seconds); // each client should remember their session id
session_start();

$app = new \Slim\App([
	'settings' => $config,
	'controller.class_prefix' => '\\WebPW\\Controllers'
]);
$container = $app->getContainer();
$container['view'] = function ($container) {
	$view = new \Slim\Views\Twig('../src/views', [
		#'cache' => '../cache' // enable in productive environment
	]);
	$langCtrl = new \WebPW\Controllers\LanguageController($container);
	$lang = $langCtrl->getCurrentLanguage();
	$view->addExtension(new \WebPW\Twig_Extensions\TranslateFilterExtension($lang));
	$view->addExtension(new \WebPW\Twig_Extensions\ShortFilterExtension(21));
	return $view;
};


$container['RedirectController'] = function($container) {
	return new WebPW\Controllers\RedirectController($container);
};
$container['LoginController'] = function($container) {
	return new WebPW\Controllers\LoginController($container);
};
$container['VaultController'] = function($container) {
	return new WebPW\Controllers\VaultController($container);
};
