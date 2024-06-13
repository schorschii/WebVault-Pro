<?php
namespace WebVault\Controllers;

use \PDO as PDO;
use \Exception as Exception;
use Slim\Psr7\Request as Request;
use Slim\Psr7\Response as Response;

class VaultController {

	private $container;
	private $db;

	private $langCtrl;

	public function __construct($container, $db) {
		$this->container = $container;
		$this->db = $db;

		$this->langCtrl = new LanguageController();
	}


	/*** HTML Page Rendering ***/
	public function mainPage(Request $request, Response $response, $args) {
		return $this->container->get('view')->render($response, 'main.html.twig', [
			'version' => 'v'.APP_VERSION,
			'customcss' => $this->container->get('settings')['customStylesheet'] ?? '',
			'subtitle' => $this->container->get('settings')['subtitle'] ?? '',
			'httpwarn' => (!isset($_SERVER['HTTPS'])),
		]);
	}
	public function aboutPage(Request $request, Response $response, $args) {
		return $this->container->get('view')->render($response, 'about.html.twig', [
			'version' => 'v'.APP_VERSION,
			'customcss' => $this->container->get('settings')['customStylesheet'] ?? '',
		]);
	}
	public function jsStrings(Request $request, Response $response, $args) {
		return $this->container->get('view')->render($response, 'strings.js.twig', [
			'strings' => $this->langCtrl->getTranslations(),
		])->withHeader('Content-Type', 'text/javascript');
	}


	/*** JSON API Request Handling ***/
	public function getEntries(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();

			$passwords = [];
			foreach($this->db->selectAllPasswordByUser($_SESSION['user_id']) as $password) {
				$passwords[] = [
					'id' => $password->id,
					'password_group_id' => $password->password_group_id,
					'revision' => $password->revision,
					'secret' => $password->secret,
					'aes_key' => $password->aes_key,
					'aes_iv' => $password->aes_iv,
					'rsa_iv' => $password->rsa_iv,
					'share_users' => $this->db->selectAllSharedUserIdByPassword($password->id),
					'share_groups' => $this->db->selectAllSharedUserGroupIdByPassword($password->id),
				];
			}
			$groups = [];
			foreach($this->db->selectAllPasswordGroupByUser($_SESSION['user_id']) as $group) {
				$groups[] = [
					'id' => $group->id,
					'parent_password_group_id' => $group->parent_password_group_id,
					'title' => $group->title,
					'share_users' => $this->db->selectAllSharedUserIdByPasswordGroup($group->id),
					'share_groups' => $this->db->selectAllSharedUserGroupIdByPasswordGroup($group->id),
				];
			}

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'passwords' => $passwords,
				'groups'  => $groups,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function createPassword(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$json = JsonRpc::parseJsonRequest($request);

			// input checks
			if(empty($json['secret']) || empty($json['secret'])) {
				throw new Exception('Invalid secret provided');
			}

			// insert data
			$revision = 1;
			$this->db->beginTransaction();
			$password_id = $this->db->insertPassword($json['password_group_id'], $json['secret'], $json['aes_iv'], $revision);
			$this->updatePasswordUser($password_id, $json['password_user'], $json['share_users'], $json['share_groups'], true);
			$this->db->commitTransaction();

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $password_id,
				'revision' => $revision,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function editPassword(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$password_id = $request->getAttribute('id');
			$json = JsonRpc::parseJsonRequest($request);

			// input checks
			if(empty($json['secret']) || empty($json['secret'])) {
				throw new Exception('Invalid secret provided');
			}
			$revision = $this->db->selectMaxPasswordRevision($password_id)->revision;
			if(!isset($json['revision']) || $json['revision'] != $revision) {
				throw new Exception($this->langCtrl->translate('record_changed_by_another_user'));
			}
			$revision += 1;

			// update data
			$this->db->beginTransaction();
			$this->db->updatePassword($password_id, $json['password_group_id'], $json['secret'], $json['aes_iv'], $revision);
			$this->updatePasswordUser($password_id, $json['password_user'], $json['share_users'], $json['share_groups']);
			$this->db->commitTransaction();

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $password_id,
				'revision' => $revision,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function updatePasswordUser($password_id, Array $password_user, Array|null $share_users=null, Array|null $share_groups=null, Bool $isNewPassword=false) {
		// input checks
		if(empty($password_user)) {
			throw new Exception('Not encrypted to any user');
		}
		if(!array_key_exists($_SESSION['user_id'], $password_user)) {
			throw new Exception('Not encrypted to yourself');
		}

		// use existing share info if null
		if($share_users == null) {
			$share_users = $this->db->selectAllSharedUserIdByPassword($password_id);
		}
		if($share_groups == null) {
			$share_groups = $this->db->selectAllSharedUserGroupIdByPassword($password_id);
		}
		if(!$isNewPassword) {
			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($password_id))) {
				throw new Exception('Permission denied');
			}
			// check group permission
			foreach($share_groups as $group_id) {
				if(!in_array($_SESSION['user_id'], $this->db->selectAllUserIdByUserGroup($group_id))) {
					throw new Exception('You are not member of this group');
				}
			}
		}

		// check if given password_user data matches shares
		$givenDataUserIds = array_keys($password_user);
		$absoluteShareUserIds = $share_users;
		foreach($share_groups as $group_id) {
			$absoluteShareUserIds = array_merge($absoluteShareUserIds, $this->db->selectAllUserIdByUserGroup($group_id));
		}
		$absoluteShareUserIds = array_unique($absoluteShareUserIds);
		if(asort($givenDataUserIds) !== asort($absoluteShareUserIds)) {
			throw new Exception('Encrypted secrets do not match shares. Try to reload your vault for updated group memberships.');
		}

		// update data
		$this->db->deletePasswordUserByPassword($password_id);
		foreach($password_user as $user_id => $data) {
			if(empty($data['aes_key']) || empty($data['rsa_iv'])) {
				throw new Exception('Invalid data');
			}
			$this->db->insertPasswordUser(
				$password_id, $user_id,
				$data['aes_key'], $data['rsa_iv']
			);
		}
		$this->db->deletePasswordUserShareByPassword($password_id);
		foreach($share_users as $user_id) {
			$this->db->insertPasswordUserShare($password_id, $user_id);
		}
		$this->db->deletePasswordUserGroupShareByPassword($password_id);
		foreach($share_groups as $group_id) {
			$this->db->insertPasswordUserGroupShare($password_id, $group_id);
		}
	}

	public function removePassword(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($id))) {
				throw new Exception('Permission denied');
			}

			// delete data
			$this->db->deletePassword($id);

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function createGroup(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$json = JsonRpc::parseJsonRequest($request);

			// input checks
			if(empty($json['title']) || empty(trim($json['title']))) {
				throw new Exception($this->langCtrl->translate('title_cannot_be_empty'));
			}
			if(!isset($json['share_users']) || !isset($json['share_groups'])
			|| !is_array($json['share_users']) || !is_array($json['share_groups'])) {
				throw new Exception('Not shared to any user');
			}
			if(!array_key_exists('parent_password_group_id', $json)) {
				throw new Exception($this->langCtrl->translate('choose_another_parent_folder'));
			}
			$absoluteShareUserIds = $json['share_users'];
			foreach($json['share_groups'] as $group_id) {
				$absoluteShareUserIds = array_merge($absoluteShareUserIds, $this->db->selectAllUserIdByUserGroup($group_id));
			}
			if(!in_array($_SESSION['user_id'], $absoluteShareUserIds)) {
				throw new Exception('Not shared to yourself');
			}

			// permission check
			if(!empty($json['parent_password_group_id']) && !in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($json['parent_password_group_id']))) {
				throw new Exception('Permission denied');
			}

			// insert data
			$this->db->beginTransaction();
			$id = $this->db->insertPasswordGroup($json['parent_password_group_id']??null, $json['title']);
			$this->db->deletePasswordGroupUserShareByPasswordGroup($id);
			foreach($json['share_users'] as $user_id) {
				$this->db->insertPasswordGroupUserShare($id, $user_id);
			}
			$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($id);
			foreach($json['share_groups'] as $group_id) {
				$this->db->insertPasswordGroupUserGroupShare($id, $group_id);
			}
			$this->db->commitTransaction();

			// return response
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
			$this->checkLogin();
			$id = $request->getAttribute('id');
			$json = JsonRpc::parseJsonRequest($request);

			// input checks
			if(empty($json['title']) || empty(trim($json['title']))) {
				throw new Exception($this->langCtrl->translate('title_cannot_be_empty'));
			}
			if(!isset($json['share_users']) || !isset($json['share_groups'])
			|| !is_array($json['share_users']) || !is_array($json['share_groups'])) {
				throw new Exception('Not shared to any user');
			}
			if(!array_key_exists('parent_password_group_id', $json)
			|| $json['parent_password_group_id'] == $id) {
				throw new Exception($this->langCtrl->translate('choose_another_parent_folder'));
			}
			$absoluteShareUserIds = $json['share_users'];
			foreach($json['share_groups'] as $group_id) {
				$absoluteShareUserIds = array_merge($absoluteShareUserIds, $this->db->selectAllUserIdByUserGroup($group_id));
			}
			if(!in_array($_SESSION['user_id'], $absoluteShareUserIds)) {
				throw new Exception('Not shared to yourself');
			}

			// permission check
			$group = $this->db->selectPasswordGroup($id);
			if(empty($group)) throw new Exception('Not found');
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($id))
			|| (
				!empty($json['parent_password_group_id'])
				&& !in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($json['parent_password_group_id']))
				&& $json['parent_password_group_id'] != $group->parent_password_group_id
			)) {
				throw new Exception('Permission denied');
			}

			// update data
			$this->db->beginTransaction();
			$this->db->updatePasswordGroup($id, $json['parent_password_group_id'], $json['title']);
			$this->db->deletePasswordGroupUserShareByPasswordGroup($id);
			foreach($json['share_users'] as $user_id) {
				$this->db->insertPasswordGroupUserShare($id, $user_id);
			}
			$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($id);
			foreach($json['share_groups'] as $group_id) {
				$this->db->insertPasswordGroupUserGroupShare($id, $group_id);
			}
			// update subgroups and passwords
			if(!empty($json['passwords']) && is_array($json['passwords'])) {
				foreach($json['passwords'] as $password_id => $passwordData) {
					$lastRevision = $this->db->selectMaxPasswordRevision($password_id);
					if(!isset($passwordData['revision']) || $passwordData['revision'] != $lastRevision->revision) {
						throw new Exception('Record was changed by another user. Please reload your vault and try again.');
					}
					if(empty($passwordData['password_user']) || !is_array($passwordData['password_user'])) {
						throw new Exception('No password user data');
					}
					$this->db->updatePassword($password_id, $lastRevision->password_group_id, $passwordData['secret'], $passwordData['aes_iv'], $lastRevision->revision+1);
					$this->updatePasswordUser($password_id, $passwordData['password_user'], $json['share_users'], $json['share_groups']);
				}
			}
			if(!empty($json['groups']) && is_array($json['groups'])) {
				foreach($json['groups'] as $sub_group_id => $groupData) {
					// permission check
					if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($sub_group_id))) {
						throw new Exception('Permission to subgroup denied');
					}
					// update subgroup
					$this->db->deletePasswordGroupUserShareByPasswordGroup($sub_group_id);
					foreach($json['share_users'] as $user_id) {
						$this->db->insertPasswordGroupUserShare($sub_group_id, $user_id);
					}
					$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($sub_group_id);
					foreach($json['share_groups'] as $group_id) {
						$this->db->insertPasswordGroupUserGroupShare($sub_group_id, $group_id);
					}
				}
			}
			$this->db->commitTransaction();

			// return response
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

	public function removeGroup(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($id))) {
				throw new Exception('Permission denied');
			}

			// delete data
			$this->db->deletePasswordGroup($id);

			// return response
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

	public function checkLogin() {
		if(empty($_SESSION['user_id'])) {
			throw new Exception('Not logged in');
		}
		$user = $this->db->selectUser($_SESSION['user_id']);
		if(empty($user) || $user->locked) {
			throw new Exception('Invalid user');
		}
	}

}
