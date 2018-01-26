<?php
namespace WebPW\Controllers;

use Slim\Http\Request as Request;
use Slim\Http\Response as Response;
use Illuminate\Database\Capsule\Manager as Capsule;
use \WebPW\Models\PasswordEntry as PasswordEntry;
use \WebPW\Models\PasswordGroup as PasswordGroup;
use \WebPW\Models\Vault as Vault;
use \WebPW\Models\Setting as Setting;

class VaultController {

	private $container = null;
	private $langctrl = null;
	private $capsule = null;
	private $method = "AES-256-CBC";

	public function __construct($container)
	{
		$this->container = $container;
		$this->langctrl = new LanguageController;
		$this->capsule = new Capsule;
		$this->capsule->addConnection($this->container->get('settings')['db']);
		$this->capsule->setAsGlobal();
		$this->capsule->bootEloquent();
	}


	/*** IV Generator ***/
	private function generateRandomString($length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') {
		$str = '';
		$max = mb_strlen($keyspace, '8bit') - 1;
		for ($i = 0; $i < $length; ++$i) {
			$str .= $keyspace[random_int(0, $max)];
		}
		return $str;
	}

	private function generateIV() {
		$wasItSecure = false;
		$iv = openssl_random_pseudo_bytes(16, $wasItSecure);
		if ($wasItSecure) {
			return $iv;
		} else {
			// fallback if "crypto_strong" bool is false
			return $this->generateRandomString(16);
		}
	}

	/*** Entry Functions ***/
	private function getEntry($id, $decrypt_password) {
		try {
			$results = Capsule::select(
				"SELECT p.*, pg.title AS 'group_title' FROM password p LEFT JOIN passwordgroup pg ON p.group_id = pg.id WHERE p.id = ?",
				[ $id ]
			);
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		foreach($results as $row) {
			return [
				'id' => $row->id,
				'group_id' => $row->group_id,
				'group' => $row->group_title,
				'vault_id' => $row->vault_id,
				'title' => $row->title,
				'username' => $row->username,
				'password' => openssl_decrypt($row->password, $this->method, $decrypt_password, 0, $row->iv),
				'iv' => $row->iv,
				'description' => $row->description,
				'url' => $row->url,
				'file' => ($row->file != null) ? openssl_decrypt($row->file, $this->method, $decrypt_password, 0, $row->iv) : "",
				'filename' => $row->filename
			];
		}
	}

	private function getEntries($vault_id, $group_id, $decrypt_password) {
		try {
			$allEntries = PasswordEntry::where('vault_id', $vault_id)
				->where('group_id', $group_id)
				->get();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		$entries = [];
		foreach($allEntries as $row) {
			$entries[] = [
				'id' => $row->id,
				'group_id' => $row->group_id,
				'vault_id' => $row->vault_id,
				'grouptitle' => $this->getGroupTitle($row->id),
				'title' => $row->title,
				'username' => $row->username,
				'password' => openssl_decrypt($row->password, $this->method, $decrypt_password, 0, $row->iv),
				'iv' => $row->iv,
				'description' => $row->description,
				'url' => $row->url
			];
		}
		return $entries;
	}

	private function checkEntryChanged($id, $title, $username, $password, $decrypt_password, $description, $url, $group_id) {
		if($group_id == "NULL") $group_id = NULL;
		try {
			$entry = PasswordEntry::find($id);
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		if($entry == null) return true;
		return (!($entry->title == $title
		&& $entry->username == $username
		&& openssl_decrypt($entry->password, $this->method, $decrypt_password, 0, $entry->iv) == $password
		&& $entry->description == $description
		&& $entry->url == $url
		&& $entry->group_id == $group_id));
	}

	private function createOrUpdateEntry($id, $title, $username, $password, $encrypt_password, $iv, $description, $url, $group, $file, $filename) {
		if($url != "" && substr($url, 0, 7) != "http://"
		&& substr($url, 0, 8) != "https://"
		&& substr($url, 0, 6) != "ftp://")
			$url = "http://".$url;

		if($group == "NULL") $group = NULL;

		$encrypted = openssl_encrypt($password, $this->method, $encrypt_password, 0, $iv);
		if($file == null) $encrypted_file = null;
		else $encrypted_file = openssl_encrypt($file, $this->method, $encrypt_password, 0, $iv);

		try {
			if($id == null) $entry = new PasswordEntry();
			else $entry = PasswordEntry::find($id);
			if($entry == null) $entry = new PasswordEntry();
			$entry->group_id = $group;
			$entry->vault_id = $_SESSION['vault'];
			$entry->title = $title;
			$entry->username = $username;
			$entry->password = $encrypted;
			$entry->iv = $iv;
			$entry->description = $description;
			$entry->url = $url;
			$entry->file = $encrypted_file;
			$entry->filename = $filename;
			$entry->save();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	private function getItems($vault_id, $group_id, $decrypt_password) {
		$node = array();
		$node['entries'] = $this->getEntries($vault_id, $group_id, $decrypt_password);
		$node['groups'] = $this->getGroups($vault_id, $group_id, $decrypt_password);
		return $node;
	}

	private function removeEntry($vault_id, $id) {
		// also check vault_id so that the user can't send an id from another vault via POST
		try {
			PasswordEntry::where('id', $id)->where('vault_id', $vault_id)->delete();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	/*** Group Functions ***/
	private function quoteGroupTitle($title) {
		if(strpos($title, '.') !== false)
			return '"' . str_replace('"', "'", $title) . '"';
		else
			return $title;
	}

	private function getGroupTitle($id) {
		// return entry title in format: [GroupTitle[.GroupTitle].]EntryTitle for export
		try {
			$strResult = "";
			$search_group = null;
			$finished = false;
			$entry = PasswordEntry::find($id);
			if($entry == null) return null;
			if($entry->group_id == null)
				return $this->quoteGroupTitle($entry->title);
			else {
				$strResult = $this->quoteGroupTitle($entry->title);
				$search_group = $entry->group_id;
			}
			while($finished == false) {
				$group = PasswordGroup::find($search_group);
				$strResult = $this->quoteGroupTitle($group->title) . "." . $strResult;
				if($group->superior_group_id == null) $finished = true;
				$search_group = $group->superior_group_id;
			}
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return $strResult;
	}

	private function getAllGroups($vault_id) {
		try {
			$allGroups = PasswordGroup::where('vault_id', $vault_id)->get();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		$groups = [];
		foreach($allGroups as $row) {
			$groups[] = [ 'id' => $row->id, 'title' => $row->title, 'description' => $row->description, 'superior_group_id' => $row->superior_group_id ];
		}
		return $groups;
	}

	private function getGroups($vault_id, $superior_group_id = null, $decrypt_password) {
		try {
			$allGroups = PasswordGroup::where('vault_id', $vault_id)
				->where('superior_group_id', $superior_group_id)
				->get();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		$groups = array();
		foreach($allGroups as $row) {
			$items = array();
			$items['entries'] = $this->getEntries($vault_id, $row->id, $decrypt_password);
			$items['groups'] = $this->getGroups($vault_id, $row->id, $decrypt_password);
			$groups[] = [ 'id' => $row->id, 'title' => $row->title, 'description' => $row->description, 'items' => $items ];
		}
		return $groups;
	}

	private function createOrUpdateGroup($id, $vault_id, $title, $description, $superior_group_id) {
		try {
			if($id == null) $group = new PasswordGroup();
			else $group = PasswordGroup::find($id);
			if($group == null) $group = new PasswordGroup();
			$group->vault_id = $vault_id;
			$group->title = $title;
			$group->description = $description;
			$group->superior_group_id = $superior_group_id;
			$group->save();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return $group->id;
	}

	private function createGroups($vault_id, $groupString) {
		// $groupString = string of groups, dot-separated
		$superior_group_id = null;
		foreach(explode(".", $groupString) as $group) {
			$group_id = $this->getGroupId($vault_id, $group, $superior_group_id);
			if($group_id == null) {
				$group_id = $this->createOrUpdateGroup(null, $_SESSION['vault'], $group, null, $superior_group_id);
			}
			$superior_group_id = $group_id;
		}
		return $superior_group_id;
	}

	private function getGroupId($vault_id, $group, $superior_group_id) {
		try {
			$groups = PasswordGroup::where('vault_id', $vault_id)
				->where('title', $group)
				->where('superior_group_id', $superior_group_id)
				->get();
			foreach($groups as $group) {
				return $group->id;
			}
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return null;
	}

	private function removeGroup($vault_id, $id) {
		try {
			PasswordGroup::where('id', $id)->where('vault_id', $vault_id)->delete();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	/*** Login Functions ***/
	private function checkLogin($response) {
		if(!(isset($_SESSION['vault']) && $_SESSION['vault'] != "")) {
			return $response->withRedirect($this->container->router->pathFor("login"), 303);
		} else {
			return true;
		}
	}

	private function checkManageLogin($response) {
		if(!(isset($_SESSION['management']) && $_SESSION['management'] == 1)) {
			return $response->withRedirect($this->container->router->pathFor("managelogin"), 303);
		} else {
			return true;
		}
	}

	private function escapeOnlyQuotes($string) {
		return str_replace('"', '\"', $string);
	}

	/*** Vault Functions ***/
	private function getVaults() {
		try {
			$allVaults = Vault::all();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		$vaults = [];
		foreach($allVaults as $vault) {
			$vaults[] = [ 'id' => $vault->id, 'title' => $vault->title ];
		}
		return $vaults;
	}

	private function createVault($title, $password) {
		$password_hash = password_hash($password, PASSWORD_BCRYPT);
		try {
			$newVault = new Vault();
			$newVault->title = $title;
			$newVault->password = $password_hash;
			$newVault->save();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	private function editVault($id, $title, $password, $oldpassword) {
		try {
			Capsule::beginTransaction();
			$updatePasswordEntries = PasswordEntry::where('vault_id', $id)->get();
			foreach($updatePasswordEntries as $entry) {
				$decrypted = openssl_decrypt($entry->password, $this->method, $oldpassword, 0, $entry->iv);
				$decrypted_file = openssl_decrypt($entry->file, $this->method, $oldpassword, 0, $entry->iv);
				$iv = $this->generateIV();
				$encrypted = openssl_encrypt($decrypted, $this->method, $password, 0, $iv);
				$encrypted_file = openssl_encrypt($decrypted_file, $this->method, $password, 0, $iv);
				$entry->password = $encrypted;
				$entry->file = $encrypted_file;
				$entry->iv = $iv;
				$entry->save();
			}
			$updateVault = Vault::find($id);
			$updateVault->title = $title;
			$updateVault->password = password_hash($password, PASSWORD_BCRYPT);
			$updateVault->save();
			Capsule::commit();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	private function removeVault($id) {
		try {
			Capsule::beginTransaction();
			PasswordEntry::where('vault_id', $id)->delete();
			PasswordGroup::where('vault_id', $id)->delete();
			Vault::find($id)->delete();
			Capsule::commit();
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}

	private function changeManagementPassword($newpassword) {
		try {
			Setting::where('title', 'managementpassword')
				->update(['value' => password_hash($newpassword, PASSWORD_BCRYPT)]);
		} catch (\Exception $e) {
			die("Database error: {$e->getMessage()}");
		}
		return true;
	}


	public function manage(Request $request, Response $response, $args)
	{
		if(isset($_SESSION['management']) && $_SESSION['management'] == 1) {
			return $this->container['view']->render($response, 'manage.html.twig', [
				'menu' => 'loggedout',
				'pagetitle' => 'Manage Vaults',
				'pageheader' => 'Manage Vaults',
				'pagesubheader' => '',
				'httpwarn' => (!isset($_SERVER['HTTPS'])),
				'languages' => $this->langctrl->getLanguages($this->container->get('settings')['defaultLanguage']),
				'vaults' => $this->getVaults(),
				'info' => isset($args['info']) ? $args['info'] : null,
				'infotype' => isset($args['infotype']) ? $args['infotype'] : null
			]);
		} else {
			return $response->withRedirect($this->container->router->pathFor("managelogin"), 303);
		}
	}

	public function doManage(Request $request, Response $response, $args)
	{
		$login = $this->checkManageLogin($response);
		if($login !== true) return $login;

		if(isset($_POST['newmanagementpassword'])) {

			$result = $this->changeManagementPassword($_POST['newmanagementpassword']);
			if($result === true)
				return $this->manage($request, $response, [ 'info' => 'Management password successfully changed', 'infotype' => 'green' ]);
			else
				return $this->manage($request, $response, [ 'info' => $result, 'infotype' => 'red' ]);

		} elseif(isset($_POST['remove']) && $_POST['remove'] != "") {

			$result = $this->removeVault($_POST['remove']);
			if($result === true)
				return $this->manage($request, $response, [ 'info' => 'Vault successfully deleted', 'infotype' => 'green' ]);
			else
				return $this->manage($request, $response, [ 'info' => $result, 'infotype' => 'red' ]);

		} elseif(isset($_POST['title']) && isset($_POST['password']) && isset($_POST['password2'])) {

			if($_POST['password'] != $_POST['password2'])
				return $this->manage($request, $response, [ 'info' => 'Passwords do not match', 'infotype' => 'red' ]);

			if($_POST['title'] == "")
				return $this->manage($request, $response, [ 'info' => 'Title should not be empty', 'infotype' => 'red' ]);

			if(!isset($_POST['changepassword'])) {
				// create new vault
				$result = $this->createVault($_POST['title'], $_POST['password']);
				if($result === true)
					return $this->manage($request, $response, [ 'info' => 'Vault successfully created', 'infotype' => 'green' ]);
				else
					return $this->manage($request, $response, [ 'info' => $result, 'infotype' => 'red' ]);

			} else {

				// change title and password(s)
				$loginCtrl = new LoginController($this->container);
				if(!$loginCtrl->correctVaultPassword($_POST['changepassword'], $_POST['oldpassword']))
					return $this->manage($request, $response, [ 'info' => "Invalid password", 'infotype' => 'red' ]);

				$result = $this->editVault($_POST['changepassword'], $_POST['title'], $_POST['password'], $_POST['oldpassword']);
				if($result === true)
					return $this->manage($request, $response, [ 'info' => 'Vault successfully edited', 'infotype' => 'green' ]);
				else
					return $this->manage($request, $response, [ 'info' => $result, 'infotype' => 'red' ]);

			}

		} else {
			return $response->withRedirect($this->container->router->pathFor("manage"), 303);
		}
	}

	public function view(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		return $this->container['view']->render($response, 'vault.html.twig', [
			'searchbar' => true,
			'menu' => isset($_GET['popup']) ? 'popup' : 'loggedin',
			'pagetitle' => 'Vault',
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => '',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'items' => $this->getItems($_SESSION['vault'], null, $_SESSION['sessionpassword'])
		]);
	}

	public function import(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		return $this->container['view']->render($response, 'import.html.twig', [
			'menu' => 'loggedin',
			'pagetitle' => 'Import',
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => 'Import',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
		]);
	}

	public function doImport(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		$is_preview = (isset($_POST['preview']) && $_POST['preview'] == "1");

		if(class_exists("parseCSV")) {
			if(isset($_FILES['importfile']) && $_FILES['importfile']['tmp_name'] != "") {

				$csv = new \parseCSV();
				$csv->encoding('ISO-8859-1', 'UTF-8');
				$csv->delimiter = "\t";
				$csv->parse($_FILES['importfile']['tmp_name']);

				$counter = 0;
				$entries = array();
				foreach($csv->data as $row) {
					if(isset($row['Group/Title']) && trim($row['Group/Title']) != "") {
						$counter ++;
						// get values from csv parser
						$group = "";
						$title = $row['Group/Title'];
						if(strpos($row['Group/Title'], '.') !== false) { // group is separated from title with a .
							$split = str_getcsv($row['Group/Title'], ".", '"');
							$title = array_pop($split);
							$group = implode(".", $split);
						}
						$username = (isset($row['Username'])) ? $row['Username'] : "";
						$password = (isset($row['Password'])) ? $row['Password'] : "";
						$url = (isset($row['URL'])) ? $row['URL'] : "";
						$notes = (isset($row['Notes'])) ? $row['Notes'] : "";
						$createdtime = (isset($row['Created Time'])) ? $row['Created Time'] : "";
						$passwordmodifiedtime = (isset($row['Password Modified Time'])) ? $row['Password Modified Time'] : "";
						$entries[] = [
							"group" => $group,
							"title" => $title,
							"username" => $username,
							"password" => $password,
							"url" => $url,
							"created" => $createdtime,
							"modified" => $passwordmodifiedtime,
							"notes" => $notes
						];
					}
				}

				$infotype = "green";
				$info = 'Import preview generated';

			} else {
				$infotype = "red";
				$info = 'Import file not found';
			}

		} else {
			$infotype = "red";
			$info = 'ParseCSV-Library not found. Run composer update.';
		}

		// do the import
		if($is_preview == false && $infotype != "red") {
			$counter = 0;
			foreach($entries as $entry) {
				$counter ++;
				$group_id = null;
				if($entry['group'] != "") $group_id = $this->createGroups($_SESSION['vault'], $entry['group']);
				$iv = $this->generateIV();
				$this->createOrUpdateEntry(null, $entry['title'], $entry['username'], $entry['password'], $_SESSION['sessionpassword'], $iv, $entry['notes'], $entry['url'], $group_id, null, null);
			}
			$infotype = "green";
			$info = "Imported $counter entries";
			$entries = null;
		}

		return $this->container['view']->render($response, 'import.html.twig', [
			'menu' => 'loggedin',
			'pagetitle' => 'Import',
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => 'Import',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'infotype' => $infotype,
			'info' => $info,
			'importrows' => $entries
		]);
	}

	public function export(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		return $this->container['view']->render($response, 'export.html.twig', [
			'menu' => 'loggedin',
			'pagetitle' => 'Export',
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => 'Export',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'info' => isset($args['info']) ? $args['info'] : null,
			'infotype' => isset($args['infotype']) ? $args['infotype'] : null
		]);
	}

	public function doExport(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		if(isset($_POST['vaultpassword']) && isset($_POST['format'])) {

			$loginCtrl = new LoginController($this->container);
			if(!$loginCtrl->correctVaultPassword($_SESSION['vault'], $_POST['vaultpassword']))
				return $this->export($request, $response, [ 'info' => "Invalid password", 'infotype' => 'red' ]);

			if($_POST['format'] == "csv") {
				$this->container['view']->render($response, 'export-csv.html.twig', [
					'searchbar' => false,
					'menu' => 'none',
					'pagetitle' => 'Vault Export',
					'pageheader' => $_SESSION['vaulttitle'],
					'items' => $this->getItems($_SESSION['vault'], null, $_SESSION['sessionpassword'])
				]);
				return $response->withHeader('Content-Type', 'text/comma-separated-values; charset=utf-8')
					->withHeader('Content-Disposition', 'attachment; filename="pwexport.csv"');
			} elseif($_POST['format'] == "tab") {
				$this->container['view']->render($response, 'export-tab.html.twig', [
					'searchbar' => false,
					'menu' => 'none',
					'pagetitle' => 'Vault Export',
					'pageheader' => $_SESSION['vaulttitle'],
					'items' => $this->getItems($_SESSION['vault'], null, $_SESSION['sessionpassword'])
				]);
				return $response->withHeader('Content-Type', 'text/tab-separated-values; charset=utf-8')
					->withHeader('Content-Disposition', 'attachment; filename="pwexport.tsv"');
			} elseif($_POST['format'] == "html") {
				$this->container['view']->render($response, 'export-html.html.twig', [
					'searchbar' => false,
					'menu' => 'none',
					'pagetitle' => 'Vault Export',
					'pageheader' => $_SESSION['vaulttitle'],
					'items' => $this->getItems($_SESSION['vault'], null, $_SESSION['sessionpassword'])
				]);
				return $response->withHeader('Content-Type', 'text/html; charset=utf-8')
					->withHeader('Content-Disposition', 'attachment; filename="pwexport.html"');
			}

		} else {
			return $this->export($request, $response, [ 'info' => "Vault password or export format missing", 'infotype' => 'red' ]);
		}
	}

	public function ajax(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $response->withHeader('Content-Type', 'text/plain');

		if(isset($_GET['id']) && isset($_GET['param']) && $_GET['id'] != "") {
			$entry = $this->getEntry($_GET['id'], $_SESSION['sessionpassword']);
			switch($_GET['param']) {
				case "id":
				echo $entry['id'];
				break;
				case "title":
				echo $entry['title'];
				break;
				case "url":
				echo $entry['url'];
				break;
				case "group":
				echo $entry['group'];
				break;
				case "username":
				echo $entry['username'];
				break;
				case "password":
				echo $entry['password'];
				break;
				case "description":
				echo $entry['description'];
				break;
				case "download":
				if($entry['file'] == null) echo "";
				else echo 'download?id='.$entry['id'];
				break;
				case "filename":
				if($entry['filename'] == null) echo "";
				else echo $entry['filename'];
				break;
			}
			return $response->withHeader('Content-Type', 'text/plain');
		}
	}

	public function download(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $response->withHeader('Content-Type', 'text/plain');

		if(isset($_GET['id']) && $_GET['id'] != "") {
			$entry = $this->getEntry($_GET['id'], $_SESSION['sessionpassword']);
			$filename = $entry['filename'];
			if($filename == null || $filename == "")
				$filename = "download.txt";
			echo $entry['file'];
			return $response->withHeader('Content-Disposition', 'attachment; filename="'.$filename.'"');
		}
	}

	public function editPassword(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		$title = "New Entry";
		$entry = null;
		if(isset($args['id']) && $args['id'] != "") {
			$title = "Edit Entry";
			$entry = $this->getEntry($args['id'], $_SESSION['sessionpassword']);
		}
		if(isset($_GET['id']) && $_GET['id'] != "") {
			$title = "Edit Entry";
			$entry = $this->getEntry($_GET['id'], $_SESSION['sessionpassword']);
		}
		return $this->container['view']->render($response, 'editentry.html.twig', [
			'menu' => isset($_GET['popup']) ? 'popup' : 'loggedin',
			'pagetitle' => $title,
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => $title,
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'groups' => $this->getAllGroups($_SESSION['vault']),
			'entry' => $entry,
			'info' => isset($args['info']) ? $args['info'] : null,
			'infotype' => isset($args['infotype']) ? $args['infotype'] : null
		]);
	}

	public function doEditPassword(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		if(isset($_POST['remove'])) {
			$this->removeEntry($_SESSION['vault'], $_POST['remove']);
			return $response->withRedirect($this->container->router->pathFor("vault"), 303);
		}

		if(isset($_POST['title']) && isset($_POST['description'])) {

			if(trim($_POST['title']) == "")
				return $this->editPassword($request, $response, [ 'info' => "Title should not be empty", 'infotype' => "red" ]);

				$id = null;
				if(isset($_POST['id']) && $_POST['id'] != "") {
					$id = $_POST['id'];
					if($this->checkEntryChanged($id,
						$_POST['old_title'],
						$_POST['old_username'],
						$_POST['old_password'],
						$_SESSION['sessionpassword'],
						$_POST['old_description'],
						$_POST['old_url'],
						$_POST['old_group']
					))
					return $this->editPassword($request, $response, [ 'id' => $id, 'info' => "Entry was changed by another user", 'infotype' => "yellow" ]);
				}

				$filecontent = null;
				$filename = null;
				if(isset($_POST['keepfile']) && $_POST['keepfile'] == "true") {
					$entry = $this->getEntry($id, $_SESSION['sessionpassword']);
					$filecontent = $entry['file'];
					$filename = $entry['filename'];
				} elseif(isset($_FILES['file']['tmp_name']) && file_exists($_FILES['file']['tmp_name'])) {
					$filename = urldecode($_FILES['file']['name']);
					$handle = fopen($_FILES['file']['tmp_name'], "r");
					$filecontent = fread($handle, filesize($_FILES['file']['tmp_name']));
					fclose($handle);
				}

				$this->createOrUpdateEntry($id,
					$_POST['title'],
					$_POST['username'],
					$_POST['password'],
					$_SESSION['sessionpassword'],
					$this->generateIV(),
					$_POST['description'],
					$_POST['url'],
					$_POST['group'],
					$filecontent,
					$filename
				);

				return $response->withRedirect($this->container->router->pathFor("vault"), 303);

		}

		return $response->withRedirect($this->container->router->pathFor("vault"), 303);
	}

	public function editGroup(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;
		return $this->container['view']->render($response, 'editgroup.html.twig', [
			'menu' => 'loggedin',
			'pagetitle' => 'Groups',
			'pageheader' => $_SESSION['vaulttitle'],
			'pagesubheader' => '',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
			'groups' => $this->getAllGroups($_SESSION['vault']),
			'info' => isset($args['info']) ? $args['info'] : null,
			'infotype' => isset($args['infotype']) ? $args['infotype'] : null
		]);
	}

	public function doEditGroup(Request $request, Response $response, $args)
	{
		$login = $this->checkLogin($response);
		if($login !== true) return $login;

		if(isset($_POST['remove'])) {
			$this->removeGroup($_SESSION['vault'], $_POST['remove']);
			return $this->editGroup($request, $response, [ 'info' => "Successfully removed group", 'infotype' => "green" ]);
		}

		// add/edit group
		if(isset($_POST['title'])
		&& isset($_POST['description'])
		&& isset($_POST['superior_group_id'])
		) {
			$id = null;
			$superior_group_id = null;

			if(trim($_POST['title']) == "")
				return $this->editGroup($request, $response, [ 'info' => "Title should not be empty", 'infotype' => "red" ]);

			if(isset($_POST['group_id']) && $_POST['group_id'] == $_POST['superior_group_id'])
				return $this->editGroup($request, $response, [ 'info' => "Please choose another superior group", 'infotype' => "red" ]);

			if(isset($_POST['group_id']) && $_POST['group_id'] != "")
				$id = $_POST['group_id'];

			if($_POST['superior_group_id'] != "NULL")
				$superior_group_id = $_POST['superior_group_id'];

			$result = $this->createOrUpdateGroup($id, $_SESSION['vault'], $_POST['title'], $_POST['description'], $superior_group_id);
			if($result !== false) {
				return $this->editGroup($request, $response, [ 'info' => "Successfully created/edited group", 'infotype' => "green" ]);
			} else {
				return $this->editGroup($request, $response, [ 'info' => "Error while creating/editing group", 'infotype' => "red" ]);
			}
		}

		return $response->withRedirect($this->container->router->pathFor("editgroup"), 303);
	}

}
