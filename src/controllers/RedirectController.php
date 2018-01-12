<?php
namespace WebPW\Controllers;

use Slim\Http\Request as Request;
use Slim\Http\Response as Response;

class RedirectController {

	private $container = null;
	private $langctrl = null;
	private $mysqli = null;

	public function __construct($container)
	{
		$this->container = $container;
		$this->langctrl = new LanguageController;
		$db = $this->container->get('settings')['db'];
		$this->mysqli = new \mysqli($db['host'], $db['user'], $db['password'], $db['dbname']);
		if ($this->mysqli->connect_errno)
			die("Failed to connect to database server: " . $this->mysqli->connect_error);
		$this->mysqli->set_charset("utf8");
	}

	private function isAlreadyEstablished() {
		$statement = $this->mysqli->prepare("SHOW TABLES LIKE 'setting'");
		$statement->execute();
		$statement->store_result();
		return $statement->num_rows > 0;
	}


	public function redirect(Request $request, Response $response, $args)
	{
		$targetPathName = "login";
		if(!$this->isAlreadyEstablished()) $targetPathName = "setup";
		if(isset($_SESSION['vault']) && $_SESSION['vault'] != "") $targetPathName = "vault";
		return $response->withRedirect($this->container->router->pathFor($targetPathName), 303);
	}

	public function aboutPage(Request $request, Response $response, $args)
	{
		return $this->container['view']->render($response, 'about.html.twig', [
			'menu' => 'loggedout',
			'pagetitle' => 'About',
			'pageheader' => 'About WebPW' . ' ' . 'v0.1.0',
			'pagesubheader' => 'web based password safe',
			'languages' => $this->langctrl->getLanguages($this->container->get('settings')['defaultLanguage'])
		]);
	}

	public function licenseText(Request $request, Response $response, $args)
	{
		$licenseFilePath = __DIR__.'/../../LICENSE.txt';

		$licenseText = "License text file missing.";
		if(file_exists($licenseFilePath))
			$licenseText = file_get_contents($licenseFilePath);

		return $response->withHeader('Content-Type', 'text/plain')->write();
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
				#if (!$this->mysqli->multi_query(file_get_contents("sql/clean.sql")))
				#	echo("<b>ERROR DROPPING TABLES:</b><br>" . $this->mysqli->error . "<br>");
				#$this->clearStoredResults();
				if (!$this->mysqli->multi_query(file_get_contents(__DIR__."/../sql/pwsafe.sql")))
				die("<b>ERROR CREATING TABLES:</b><br>" . $this->mysqli->error . "<br>");
				$this->clearStoredResults();
				$sql = "INSERT INTO setting (title, value) VALUES (\"managementpassword\", ?)";
				$passwordhash = password_hash($_POST['managementpassword'], PASSWORD_DEFAULT);
				$statement = $this->mysqli->prepare($sql);
				$statement->bind_param('s', $passwordhash);
				if (!$statement->execute())
					die("Execute failed: (" . $statement->errno . ") " . $statement->error);
			}
		}
		return $response->withRedirect($this->container->router->pathFor("root"), 303);
	}

	private function clearStoredResults(){
		do {
			if ($res = $this->mysqli->store_result()) {
				$res->free();
			}
		} while ($this->mysqli->more_results() && $this->mysqli->next_result());
	}

}
