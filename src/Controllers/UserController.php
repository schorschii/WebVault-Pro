<?php
namespace WebVault\Controllers;

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

			if($user->totp_secret) {
				// second factor required, the login is completed in loginTotp()
				$_SESSION['totp_user_id'] = $user->id;
				$response->getBody()->write(json_encode([
					'totp_required' => true
				]));
				return $response->withHeader('Content-Type', 'application/json');
			}
			return $this->loginResponse($user, $response);

		} catch(Exception $e) {
			sleep(1); // wait a second in order to exacerbate brute force attacks
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function loginTotp(Request $request, Response $response, $args) {
		try {
			$json = JsonRpc::parseJsonRequest($request);
			$user = empty($_SESSION['totp_user_id']) ? null : $this->db->selectUser($_SESSION['totp_user_id']);
			if(!$user || !$user->totp_secret || $user->locked)
				throw new Exception('Invalid session');
			if(!$this->checkTotp($user, $json['code'] ?? ''))
				throw new Exception($this->vc->translate('invalid_code'));

			unset($_SESSION['totp_user_id']);
			return $this->loginResponse($user, $response);

		} catch(Exception $e) {
			sleep(1); // wait a second in order to exacerbate brute force attacks
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	private function loginResponse($user, Response $response) {
		session_regenerate_id(true);
		$_SESSION['user_id'] = $user->id;
		$_SESSION['last_activity'] = time();

		$groups = [];
		foreach($this->db->selectAllUserGroup() as $group) {
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
			'totp' => !empty($user->totp_secret),
		]));
		return $response->withHeader('Content-Type', 'application/json');
	}

	public function session(Request $request, Response $response, $args) {
		try {
			$this->vc->checkLogin(false); // periodic session check must not extend the session
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
			$this->vc->checkLogin();
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

	public function totpSetup(Request $request, Response $response, $args) {
		try {
			$this->vc->checkLogin();
			$user = $this->db->selectUser($_SESSION['user_id']);
			if($user->totp_secret) {
				throw new Exception('Already enabled');
			}

			// the secret is only stored after the user proved that the authenticator app works
			$secret = Totp::generateSecret();
			$_SESSION['totp_pending_secret'] = $secret;

			// return response
			$response->getBody()->write(json_encode([
				'secret' => $secret,
				'uri' => Totp::getUri($secret, $user->username, $this->container->get('settings')['subtitle'] ?: 'WebVault Pro'),
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function totpEnable(Request $request, Response $response, $args) {
		try {
			$this->vc->checkLogin();
			$json = JsonRpc::parseJsonRequest($request);
			$secret = $_SESSION['totp_pending_secret'] ?? null;
			if(!$secret) {
				throw new Exception('No pending setup');
			}
			if(Totp::verify($secret, $json['code'] ?? '') === false) {
				throw new Exception($this->vc->translate('invalid_code'));
			}

			// generate recovery codes, only the hashes are stored
			$recoveryCodes = [];
			$recoveryHashes = [];
			for($i=0; $i<8; $i++) {
				$code = strtoupper(bin2hex(random_bytes(5)));
				$recoveryCodes[] = $code;
				$recoveryHashes[] = password_hash($code, PASSWORD_DEFAULT);
			}

			// update data
			$this->db->updateUserTotp($_SESSION['user_id'], $secret, json_encode($recoveryHashes));
			unset($_SESSION['totp_pending_secret']);

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'recovery_codes' => $recoveryCodes,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function totpDisable(Request $request, Response $response, $args) {
		try {
			$this->vc->checkLogin();
			$json = JsonRpc::parseJsonRequest($request);
			$user = $this->db->selectUser($_SESSION['user_id']);
			if(!$user->totp_secret) {
				throw new Exception('Not enabled');
			}
			if(!$this->checkTotp($user, $json['code'] ?? '')) {
				throw new Exception($this->vc->translate('invalid_code'));
			}

			// update data
			$this->db->updateUserTotp($_SESSION['user_id'], null, null);

			// return response
			$response->getBody()->write(json_encode([
				'success' => true
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			sleep(1); // wait a second in order to exacerbate brute force attacks
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function createGroup(Request $request, Response $response, $args) {
		try {
			$this->vc->checkLogin();
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
			$this->vc->checkLogin();
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
			$this->vc->checkLogin();
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
	private function checkTotp($user, $code) {
		// accept a current one-time code (only once) or one of the recovery codes (removed after use)
		$step = Totp::verify($user->totp_secret, $code, $user->totp_last_step);
		if($step !== false) {
			$this->db->updateUserTotpLastStep($user->id, $step);
			return true;
		}
		$recoveryHashes = json_decode($user->totp_recovery ?? '', true) ?: [];
		foreach($recoveryHashes as $index => $hash) {
			if(password_verify($code, $hash)) {
				unset($recoveryHashes[$index]);
				$this->db->updateUserTotp($user->id, $user->totp_secret, json_encode(array_values($recoveryHashes)));
				return true;
			}
		}
		error_log('user '.$user->username.': second factor failure');
		return false;
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
