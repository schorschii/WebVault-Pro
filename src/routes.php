<?php
use Slim\Routing\RouteContext;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Request;
use Slim\Psr7\Response;

/*** Route Definitions ***/

// HTML pages
$app->get('/', WebVault\Controllers\VaultController::class.':mainPage')
	->setName('main');
$app->get('/about', WebVault\Controllers\VaultController::class.':aboutPage')
	->setName('about');
$app->get('/js/strings.js', WebVault\Controllers\VaultController::class.':jsStrings')
	->setName('strings');

// JSON API requests
$app->post('/user/login', WebVault\Controllers\UserController::class.':login')
	->setName('user-login');
$app->get('/user/session', WebVault\Controllers\UserController::class.':session')
	->setName('user-session');
$app->post('/user/logout', WebVault\Controllers\UserController::class.':logout')
	->setName('user-logout');
$app->post('/user/keys', WebVault\Controllers\UserController::class.':setUserKeys')
	->setName('user-keys');
$app->post('/user/group', WebVault\Controllers\UserController::class.':createGroup')
	->setName('user-group-create');
$app->post('/user/group/{id}', WebVault\Controllers\UserController::class.':editGroup')
	->setName('user-group-edit');
$app->delete('/user/group/{id}', WebVault\Controllers\UserController::class.':deleteGroup')
	->setName('user-group-delete');

$app->get('/vault/entries', WebVault\Controllers\VaultController::class.':getEntries')
	->setName('vault-entries');

$app->post('/vault/password', WebVault\Controllers\VaultController::class.':createPassword')
	->setName('vault-password-new');
$app->post('/vault/password/{id}', WebVault\Controllers\VaultController::class.':editPassword')
	->setName('vault-password-edit');
$app->delete('/vault/password/{id}', WebVault\Controllers\VaultController::class.':removePassword')
	->setName('vault-password-delete');

$app->post('/vault/group', WebVault\Controllers\VaultController::class.':createGroup')
	->setName('vault-group-new');
$app->post('/vault/group/{id}', WebVault\Controllers\VaultController::class.':editGroup')
	->setName('vault-group-edit');
$app->delete('/vault/group/{id}', WebVault\Controllers\VaultController::class.':removeGroup')
	->setName('vault-group-delete');

// redirect all other requests to homepage
$errorMiddleware = $app->addErrorMiddleware(true, true, true);
$errorMiddleware->setErrorHandler(
HttpNotFoundException::class,
function(Request $request, Throwable $exception, bool $displayErrorDetails) {
	$routeParser = RouteContext::fromRequest($request)->getRouteParser();
	$response = new Response();
	return $response
		->withHeader('Location', $routeParser->urlFor('main'))
		->withStatus(302);
});
