<?php
namespace XVault\Controllers;

use \PDO as PDO;
use \Exception as Exception;
use Slim\Psr7\Request as Request;
use Slim\Psr7\Response as Response;

class UserController {

	private $container;
	private $db;
	private $vc;

	private $ldapSync;

	public function __construct($container, $db, $vaultController) {
		$this->container = $container;
		$this->db = $db;
		$this->vc = $vaultController;

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
			if($user->locked)
				throw new Exception('User is locked');

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
			$this->vc->checkLogin();
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

			// input checks
			if(empty($json['private_key']) || empty($json['salt']) || empty($json['iv'])) {
				throw new Exception('Missing data');
			}
			$user = $this->db->selectUser($_SESSION['user_id']);
			if($user->public_key && !empty($json['public_key'])) {
				// once a keypair was generated, it is not allowed to change it
				// since the server can't re-encrypt the secrets to a new key
				// it is only allowed to update the own private key with a new passphrase
				throw new Exception('You cannot change your public key');
			} elseif(!$user->public_key && empty($json['public_key'])) {
				throw new Exception('Missing data');
			}

			// update data
			$this->db->updateUserKeys($_SESSION['user_id'],
				$user->public_key ?? $json['public_key'], $json['private_key'], $json['salt'], $json['iv']
			);

			// return response
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
			if(empty($json['members']) || !is_array($json['members'])) {
				throw new Exception('Members cannot be empty');
			}
			if(!in_array($_SESSION['user_id'], $json['members'])) {
				throw new Exception('Self not in members');
			}

			// update data
			$this->db->beginTransaction();
			$id = $this->db->insertUserGroup($json['title']);
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
			if(!empty($json['passwords']) && is_array($json['passwords'])) {
				foreach($json['passwords'] as $password_id => $passwordUserData) {
					$lastRevision = $this->db->selectMaxPasswordRevision($password_id);
					if(!isset($passwordUserData['revision']) || $passwordUserData['revision'] != $lastRevision->revision) {
						throw new Exception('Record was changed by another user. Please reload your vault and try again.');
					}
					if(empty($passwordUserData['password_user']) || !is_array($passwordUserData['password_user'])) {
						throw new Exception('No password user data');
					}
					$this->db->updatePassword($password_id, $lastRevision->password_group_id, $passwordUserData['secret'], $passwordUserData['aes_iv'], $lastRevision->revision+1);
					$this->vc->updatePasswordUser($password_id, $passwordUserData['password_user']);
				}
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
