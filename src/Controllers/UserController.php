<?php
namespace XVault\Controllers;

use \PDO as PDO;
use \Exception as Exception;
use Slim\Psr7\Request as Request;
use Slim\Psr7\Response as Response;

class UserController {

	private $container;

	private $db;
	private $ldapSync;

	public function __construct($container) {
		$this->container = $container;

		$dbsettings = $this->container->get('settings')['db'];
		$this->db = new DatabaseController($dbsettings);

		$ldapsettings = $this->container->get('settings')['ldapSync'];
		$this->ldapSync = new LdapSyncController($ldapsettings, $this->db);
	}


	/*** JSON API Request Handling ***/
	public function login(Request $request, Response $response, $args) {
		try {
			$json = JsonRpc::parseJsonRequest($request);
			$user = $this->db->selectUserByUsername($json['username']??'');
			if(!$user || !$this->checkPassword($user, $json['password']??''))
				throw new Exception('Invalid credentials');

			$_SESSION['user_id'] = $user->id;

			$groups = [];
			foreach($this->db->selectAllUserGroupForShare($_SESSION['user_id']) as $group) {
				$groups[] = [
					'id' => $group->id, 'title' => $group->title,
					'members' => $this->db->selectAllUserIdByUserGroup($group->id)
				];
			}
			$response->getBody()->write(json_encode([
				'id' => $user->id,
				'private_key' => $user->private_key,
				'salt' => $user->salt,
				'iv' => $user->iv,
				'users' => $this->db->selectAllUserForShare(),
				'groups' => $groups,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			sleep(1); // wait a second in order to exacerbate brute force attacks
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function session(Request $request, Response $response, $args) {
		try {
			self::checkLogin();
			$response->getBody()->write(json_encode([
				'success' => true
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function logout(Request $request, Response $response, $args) {
		session_destroy();
		$response->getBody()->write(json_encode([
			'success' => true
		]));
		return $response->withHeader('Content-Type', 'application/json');
	}

	public function setUserKeys(Request $request, Response $response, $args) {
		try {
			$json = JsonRpc::parseJsonRequest($request);
			$pub_key = $json['public_key'];
			$user = $this->db->selectUser($_SESSION['user_id']);
			if($user->public_key) {
				// once a keypair was generated, it is not allowed to change it
				// since the server can't re-encrypt the secrets to a new key
				// it is only allowed to update the own private key with a new passphrase
				$pub_key = $user->pubKey;
			}
			$this->db->updateUserKeys($_SESSION['user_id'],
				$pub_key, $json['private_key'], $json['salt'], $json['iv']
			);
			$response->getBody()->write(json_encode([
				'success' => true
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function createGroup(Request $request, Response $response, $args) {
		try {
			$json = JsonRpc::parseJsonRequest($request);
			if(empty($json['title'])) {
				throw new Exception('Title cannot be empty');
			}

			// update data
			$this->db->beginTransaction();
			$id = $this->db->insertUserGroup($json['title']);
			$this->db->insertUserGroupMember($_SESSION['user_id'], $id);
			$this->db->commitTransaction();

			// send response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $id,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function editGroup(Request $request, Response $response, $args) {
		try {
			$json = JsonRpc::parseJsonRequest($request);
			$id = $request->getAttribute('id');
			if(empty($json['title'])) {
				throw new Exception('Title cannot be empty');
			}
			if(empty($json['members']) || !is_array($json['members'])) {
				throw new Exception('Members cannot be empty');
			}
			if(!in_array($_SESSION['user_id'], $json['members'])) {
				throw new Exception('Self not in members');
			}

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserIdByUserGroup($id))) {
				throw new Exception('Permission denied');
			}

			// update data
			$this->db->beginTransaction();
			$this->db->deleteUserGroupMemberByUserGroup($id);
			foreach($json['members'] as $user_id) {
				$this->db->insertUserGroupMember($user_id, $id);
			}
			$this->db->commitTransaction();

			// send response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $id,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function deleteGroup(Request $request, Response $response, $args) {
		try {
			$id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserIdByUserGroup($id))) {
				throw new Exception('Permission denied');
			}

			// update data
			$this->db->deleteUserGroup($id);

			// send response
			$response->getBody()->write(json_encode([
				'success' => true
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	/*** Login Functions ***/
	static function checkLogin() {
		if(empty($_SESSION['user_id'])) {
			// todo: specific exception, return 401
			throw new Exception('Not logged in');
		}
	}

	private function checkPassword($user, $checkPassword) {
		$result = false;
		if($user->ldap) {
			$result = $this->ldapSync->checkPassword($user, $checkPassword);
		} else {
			$result = password_verify($checkPassword, $user->password);
		}
		if(!$result) {
			// log for fail2ban
			error_log('user '.$user->username.': authentication failure');
		}
		return $result;
	}

}
