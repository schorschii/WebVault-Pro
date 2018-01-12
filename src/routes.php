<?php

// route definitions
$app->get('/', 'RedirectController:redirect')
	->setName('root');
$app->get('/about', 'RedirectController:aboutPage')
	->setName('about');
$app->get('/licenseText', 'RedirectController:licenseText')
	->setName('licensetext');

$app->post('/setlang', 'RedirectController:setLanguage')
	->setName('setlang');

$app->get('/ajax', 'VaultController:ajax')
	->setName('ajax');

$app->get('/setup', 'RedirectController:setup')
	->setName('setup');
$app->post('/setup', 'RedirectController:doSetup')
	->setName('setup');

$app->get('/manage', 'VaultController:manage')
	->setName('manage');
$app->post('/manage', 'VaultController:doManage')
	->setName('domanage');

$app->get('/managelogin', 'LoginController:managementLogin')
	->setName('managelogin');
$app->post('/managelogin', 'LoginController:doManageLogin')
	->setName('domanagelogin');
$app->get('/login', 'LoginController:login')
	->setName('login');
$app->post('/login', 'LoginController:doLogin')
	->setName('dologin');
$app->get('/logout', 'LoginController:logout')
	->setName('logout');

$app->get('/vault', 'VaultController:view')
	->setName('vault');
$app->get('/editentry', 'VaultController:editPassword')
	->setName('editentry');
$app->post('/editentry', 'VaultController:doEditPassword')
	->setName('doeditentry');
$app->get('/editgroup', 'VaultController:editGroup')
	->setName('editgroup');
$app->post('/editgroup', 'VaultController:doEditGroup')
	->setName('editgroup');
$app->get('/vaultimport', 'VaultController:import')
	->setName('vaultimport');
$app->post('/vaultimport', 'VaultController:doImport')
	->setName('dovaultimport');
$app->get('/vaultexport', 'VaultController:export')
	->setName('vaultexport');
$app->post('/vaultexport', 'VaultController:doExport')
	->setName('dovaultexport');


// for testing purposes only ============================
#use \Slim\Http\Request as Request;
#use \Slim\Http\Response as Response;
#$app->get('/hello/{name}', function (Request $request, Response $response) {
#	$name = $request->getAttribute('name');
#	return $this->view->render($response, 'test.html.twig', [
#		'name' => $name
#	]);
#	return $response->getBody()->write("Hello, $name");
#});
// =======================================================
