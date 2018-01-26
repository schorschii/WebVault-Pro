<?php
namespace WebPW\Controllers;

use Slim\Http\Request as Request;
use Slim\Http\Response as Response;
use Illuminate\Database\Capsule\Manager as Capsule;
use \WebPW\Models\Vault as Vault;
use \WebPW\Models\Setting as Setting;

class LoginController {

	private $container = null;
	private $langctrl = null;
	private $capsule = null;

	public function __construct($container)
	{
		$this->container = $container;
		$this->langctrl = new LanguageController;
		$this->capsule = new Capsule;
		$this->capsule->addConnection($this->container->get('settings')['db']);
		$this->capsule->setAsGlobal();
		$this->capsule->bootEloquent();
	}


	private function getVaults() {
		$allVaults = Vault::all();
		$arrayVaults = [];
		foreach($allVaults as $vault) {
			$arrayVaults[] = [ 'id' => $vault->id, 'title' => $vault->title ];
		}
		return $arrayVaults;
	}

	private function correctManagementPassword($password) {
		$mgmtPassword = Setting::where('title', 'managementpassword')->get()[0];
		if($mgmtPassword == null) return false;
		if(password_verify($password, $mgmtPassword->value)) {
			return true;
		}
		return false;
	}

	public function correctVaultPassword($vault_id, $password) {
		$openVault = Vault::find($vault_id);
		if($openVault == null) return false;
		if(password_verify($password, $openVault->password)) {
			$_SESSION['vaulttitle'] = $openVault->title;
			return true;
		}
		return false;
	}


	public function login(Request $request, Response $response, $args)
	{
		return $this->container['view']->render($response, 'login.html.twig', [
			'menu' => 'loggedout',
			'pagetitle' => 'Login',
			'pageheader' => 'WebPW',
			'pagesubheader' => 'web based password safe',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'languages' => $this->langctrl->getLanguages($this->container->get('settings')['defaultLanguage']),
			'vaults' => $this->getVaults(),
			'vault' => isset($args['vault']) ? $args['vault'] : null,
			'defaultvault' => isset($args['defaultvault']) ? $args['defaultvault'] : null,
			'info' => isset($args['info']) ? $args['info'] : null,
			'infotype' => isset($args['infotype']) ? $args['infotype'] : null
		]);
	}

	public function managementLogin(Request $request, Response $response, $args)
	{
		return $this->container['view']->render($response, 'managelogin.html.twig', [
			'menu' => 'loggedout',
			'pagetitle' => 'Login',
			'pageheader' => 'Manage Vaults',
			'pagesubheader' => '',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'languages' => $this->langctrl->getLanguages($this->container->get('settings')['defaultLanguage']),
			'info' => isset($args['info']) ? $args['info'] : null,
			'infotype' => isset($args['infotype']) ? $args['infotype'] : null
		]);
	}

	public function doLogin(Request $request, Response $response, $args)
	{
		if (isset($_POST['vault']) && isset($_POST['password'])) {
			$vault = $_POST['vault'];
			$password = $_POST['password'];
			if ($this->correctVaultPassword($vault, $password)) {
				$_SESSION['vault'] = $vault;
				$_SESSION['sessionpassword'] = $password;
				return $response->withRedirect($this->container->router->pathFor("vault"), 303);
			} else {
				sleep(1); // wait a second in order to exacerbate brute force attacks
				$info = "Invalid password";
				return $this->login($request, $response, [ 'info' => $info, 'infotype' => "red", "vault" => $_POST['vault'] ]);
			}
		}
		return $response->withRedirect($this->container->router->pathFor("login"), 303);
	}

	public function doManageLogin(Request $request, Response $response, $args)
	{
		if(isset($_POST['managementpassword'])) {
			if($this->correctManagementPassword($_POST['managementpassword'])) {
				$_SESSION['management'] = 1;
				return $response->withRedirect($this->container->router->pathFor("manage"), 303);
			} else {
				sleep(1); // wait a second in order to exacerbate brute force attacks
				$info = "Invalid password";
				return $this->managementLogin($request, $response, [ 'info' => $info, 'infotype' => "red" ]);
			}
		}
		return $response->withRedirect($this->container->router->pathFor("managelogin"), 303);
	}

	public function logout(Request $request, Response $response, $args)
	{
		session_destroy();
		$info = "Successfully logged out";
		return $this->login($request, $response, [ 'info' => $info, 'infotype' => "green" ]);
	}

}
