<?php
namespace WebPW\Controllers;

use Slim\Http\Request as Request;
use Slim\Http\Response as Response;
use Illuminate\Database\Capsule\Manager as Capsule;
use \WebPW\Models\Vault as Vault;
use \WebPW\Models\Setting as Setting;

class RedirectController {

	private $container = null;
	private $langctrl = null;
	private $capsule = null;

	public function __construct($container)
	{
		$this->container = $container;
		$this->langctrl = new LanguageController($container);
		$this->capsule = new Capsule;
		$this->capsule->addConnection($this->container->get('settings')['db']);
		$this->capsule->setAsGlobal();
		$this->capsule->bootEloquent();
	}

	private function isAlreadyEstablished() {
		try {
			$results = Capsule::select(
				"SHOW TABLES LIKE 'setting'", [ ]
			);
		} catch (\Exception $e) {
			die("Unable to check if 'setting' table exists: {$e->getMessage()}");
		}
		return isset($results[0]);
	}


	public function redirect(Request $request, Response $response, $args)
	{
		$targetPathName = "login";
		if(!$this->isAlreadyEstablished()) $targetPathName = "setup";
		elseif(isset($_SESSION['vault']) && $_SESSION['vault'] != "") $targetPathName = "vault";
		return $response->withRedirect($this->container->router->pathFor($targetPathName), 303);
	}

	public function aboutPage(Request $request, Response $response, $args)
	{
		return $this->container['view']->render($response, 'about.html.twig', [
			'menu' => 'loggedout',
			'pagetitle' => 'About',
			'pageheader' => 'About WebPW' . ' ' . 'v'.WEBPW_VERSION,
			'pagesubheader' => 'web based password safe',
			'languages' => $this->langctrl->getLanguages()
		]);
	}

	public function licenseText(Request $request, Response $response, $args)
	{
		$licenseFilePath = __DIR__.'/../../LICENSE.txt';

		$licenseText = "License text file missing.";
		if(file_exists($licenseFilePath))
			$licenseText = file_get_contents($licenseFilePath);

		return $response->withHeader('Content-Type', 'text/plain')->write($licenseText);
	}

	public function setLanguage(Request $request, Response $response, $args)
	{
		if(isset($_POST['lang'])) {
			$langFilePath = __DIR__."/../../lang/".$_POST['lang'].".php";
			if(file_exists($langFilePath)) {
				$_SESSION['lang'] = $_POST['lang'];
			} else {
				$loginCtrl = new LoginController($this->container);
				return $loginCtrl->login($request, $response, [ 'info' => 'Language file not found', 'infotype' => 'red' ]);
			}
		}

		return $response->withRedirect($this->container->router->pathFor("root"), 303);
	}

	public function setup(Request $request, Response $response, $args)
	{
		return $this->container['view']->render($response, 'setup.html.twig', [
			'menu' => 'none',
			'pagetitle' => 'Setup',
			'pageheader' => 'Setup',
			'pagesubheader' => 'web based password safe',
			'setupbutton' => (!$this->isAlreadyEstablished())
		]);
	}

	public function doSetup(Request $request, Response $response, $args)
	{
		if(!$this->isAlreadyEstablished()) {
			if(isset($_POST['action']) && $_POST['action'] == "setup") {
				try {
					Capsule::schema()->create(
						'vault',
						function ($table) {
							$table->increments('id');
							$table->text('title');
							$table->text('password');
							$table->timestamps();
						}
					);
					Capsule::schema()->create(
						'passwordgroup',
						function ($table) {
							$table->increments('id');
							$table->integer('vault_id')->unsigned();
							$table->foreign('vault_id')->references('id')->on('vault');
							$table->integer('superior_group_id')->nullable();
							$table->text('title');
							$table->text('description')->nullable();
							$table->timestamps();
						}
					);
					Capsule::schema()->create(
						'password',
						function ($table) {
							$table->increments('id');
							$table->integer('vault_id')->unsigned();
							$table->foreign('vault_id')->references('id')->on('vault');
							$table->integer('group_id')->unsigned()->nullable();
							$table->foreign('group_id')->references('id')->on('passwordgroup')->nullable();
							$table->text('title');
							$table->text('username');
							$table->text('password');
							$table->longtext('file')->nullable();
							$table->text('filename')->nullable();
							$table->text('description')->nullable();
							$table->text('url')->nullable();
							$table->binary('iv');
							$table->timestamps();
						}
					);
					Capsule::schema()->create(
						'setting',
						function ($table) {
							$table->increments('id');
							$table->text('title');
							$table->text('value');
							$table->timestamps();
						}
					);
					$mgmtPasswordSetting = new Setting();
					$mgmtPasswordSetting->title = "managementpassword";
					$mgmtPasswordSetting->value = password_hash($_POST['managementpassword'], PASSWORD_DEFAULT);
					$mgmtPasswordSetting->save();
				} catch (\Exception $e) {
					die("Unable to setup required tables: {$e->getMessage()}");
				}
			}
		}
		return $response->withRedirect($this->container->router->pathFor("root"), 303);
	}

}
