<?php
namespace WebVault\Controllers;

use \PDO as PDO;
use \Exception as Exception;
use \DateTime as DateTime;
use \DateTimeZone as DateTimeZone;
use Slim\Psr7\Request as Request;
use Slim\Psr7\Response as Response;

class VaultController {

	private $container;
	private $db;

	private $langCtrl;

	// share permission bits are restrictions, so that 0 (existing shares) means full access
	const PERMISSION_READ_ONLY = 1;
	const PERMISSION_NO_RESHARE = 2;

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
			'icons' => $this->getIconNames(),
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
				list($share_users, $share_user_permissions, $share_user_expires) = self::compileShares($this->db->selectAllSharedUserByPassword($password->id), 'user_id');
				list($share_groups, $share_group_permissions, $share_group_expires) = self::compileShares($this->db->selectAllSharedUserGroupByPassword($password->id), 'user_group_id');
				$passwords[] = [
					'id' => $password->id,
					'password_group_id' => $password->password_group_id,
					'revision' => $password->revision,
					'secret' => $password->secret,
					'aes_key' => $password->aes_key,
					'aes_iv' => $password->aes_iv,
					'rsa_iv' => $password->rsa_iv,
					'permission' => $this->db->selectPasswordPermission($password->id, $_SESSION['user_id']),
					'share_users' => $share_users,
					'share_groups' => $share_groups,
					'share_user_permissions' => $share_user_permissions,
					'share_group_permissions' => $share_group_permissions,
					'share_user_expires' => $share_user_expires,
					'share_group_expires' => $share_group_expires,
				];
			}
			$groups = [];
			foreach($this->db->selectAllPasswordGroupByUser($_SESSION['user_id']) as $group) {
				list($share_users, $share_user_permissions, $share_user_expires) = self::compileShares($this->db->selectAllSharedUserByPasswordGroup($group->id), 'user_id');
				list($share_groups, $share_group_permissions, $share_group_expires) = self::compileShares($this->db->selectAllSharedUserGroupByPasswordGroup($group->id), 'user_group_id');
				$groups[] = [
					'id' => $group->id,
					'parent_password_group_id' => $group->parent_password_group_id,
					'title' => $group->title,
					'icon' => $group->icon,
					'permission' => $this->db->selectPasswordGroupPermission($group->id, $_SESSION['user_id']),
					'share_users' => $share_users,
					'share_groups' => $share_groups,
					'share_user_permissions' => $share_user_permissions,
					'share_group_permissions' => $share_group_permissions,
					'share_user_expires' => $share_user_expires,
					'share_group_expires' => $share_group_expires,
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

			// permission check
			if(!empty($json['password_group_id'])
			&& $this->db->selectPasswordGroupPermission($json['password_group_id'], $_SESSION['user_id']) & self::PERMISSION_READ_ONLY) {
				throw new Exception('Permission denied');
			}

			// insert data
			$revision = 1;
			$this->db->beginTransaction();
			$password_id = $this->db->insertPassword($json['password_group_id'], $json['secret'], $json['aes_iv'], $revision);
			$this->updatePasswordUser($password_id, $json['password_user'], $json['share_users'], $json['share_groups'], true,
				$json['share_user_permissions'] ?? [], $json['share_group_permissions'] ?? [], $json['share_user_expires'] ?? [], $json['share_group_expires'] ?? []);
			$this->db->commitTransaction();

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $password_id,
				'revision' => $revision,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$this->db->rollbackTransaction();
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
			$lastRevision = $this->db->selectMaxPasswordRevision($password_id);
			$revision = $lastRevision->revision;
			if(!isset($json['revision']) || $json['revision'] != $revision) {
				throw new Exception($this->langCtrl->translate('record_changed_by_another_user'));
			}
			$revision += 1;

			// permission check for the target folder if the entry is moved
			if(!empty($json['password_group_id']) && $json['password_group_id'] != $lastRevision->password_group_id
			&& $this->db->selectPasswordGroupPermission($json['password_group_id'], $_SESSION['user_id']) & self::PERMISSION_READ_ONLY) {
				throw new Exception('Permission denied');
			}

			// update data
			$this->db->beginTransaction();
			$this->db->updatePassword($password_id, $json['password_group_id'], $json['secret'], $json['aes_iv'], $revision);
			$this->updatePasswordUser($password_id, $json['password_user'], $json['share_users'], $json['share_groups'], false,
				$json['share_user_permissions'] ?? [], $json['share_group_permissions'] ?? [], $json['share_user_expires'] ?? [], $json['share_group_expires'] ?? []);
			// remove files which are not referenced by the entry anymore (deleted or never saved after upload)
			foreach($this->db->selectAllPasswordFileIdByPassword($password_id) as $file_id) {
				if(!in_array($file_id, $json['file_ids'] ?? [])) {
					$this->db->deletePasswordFile($file_id);
				}
			}
			$this->db->commitTransaction();

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $password_id,
				'revision' => $revision,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$this->db->rollbackTransaction();
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function updatePasswordUser($password_id, Array $password_user, Array|null $share_users=null, Array|null $share_groups=null, Bool $isNewPassword=false, Array $share_user_permissions=[], Array $share_group_permissions=[], Array $share_user_expires=[], Array $share_group_expires=[]) {
		// input checks
		if(empty($password_user)) {
			throw new Exception('Not encrypted to any user');
		}
		if(!array_key_exists($_SESSION['user_id'], $password_user)) {
			throw new Exception('Not encrypted to yourself');
		}

		// use existing share info if null
		if($share_users === null) {
			list($share_users, $share_user_permissions, $share_user_expires) = self::compileShares($this->db->selectAllSharedUserByPassword($password_id), 'user_id');
		}
		if($share_groups === null) {
			list($share_groups, $share_group_permissions, $share_group_expires) = self::compileShares($this->db->selectAllSharedUserGroupByPassword($password_id), 'user_group_id');
		}
		if(!$isNewPassword) {
			// permission check
			$permission = $this->db->selectPasswordPermission($password_id, $_SESSION['user_id']);
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($password_id))
			|| $permission & self::PERMISSION_READ_ONLY) {
				throw new Exception('Permission denied');
			}
			$this->checkShareChangeAllowed($permission,
				$this->db->selectAllSharedUserByPassword($password_id), $this->db->selectAllSharedUserGroupByPassword($password_id),
				$share_users, $share_groups, $share_user_permissions, $share_group_permissions, $share_user_expires, $share_group_expires
			);
			// without resharing permission the secret must not be encrypted to new users, e.g. after adding a user to a shared user group
			if($permission & self::PERMISSION_NO_RESHARE
			&& array_diff(array_keys($password_user), $this->db->selectAllUserIdByPasswordUser($password_id))) {
				throw new Exception('Permission denied');
			}
		}
		// check group permission: only members can add a group share, existing group shares can be kept
		foreach($share_groups as $group_id) {
			if(in_array($_SESSION['user_id'], $this->db->selectAllUserIdByUserGroup($group_id))) continue;
			if($isNewPassword || !in_array($group_id, array_column($this->db->selectAllSharedUserGroupByPassword($password_id), 'user_group_id'))) {
				throw new Exception('You are not member of this group');
			}
		}

		// check if given password_user data matches shares
		$givenDataUserIds = array_map('intval', array_keys($password_user));
		sort($givenDataUserIds);
		$absoluteShareUserIds = $share_users;
		foreach($share_groups as $group_id) {
			$absoluteShareUserIds = array_merge($absoluteShareUserIds, $this->db->selectAllUserIdByUserGroup($group_id));
		}
		$absoluteShareUserIds = array_unique(array_map('intval', $absoluteShareUserIds));
		sort($absoluteShareUserIds);
		if($givenDataUserIds !== $absoluteShareUserIds) {
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
			$this->db->insertPasswordUserShare($password_id, $user_id, intval($share_user_permissions[$user_id] ?? 0), self::parseExpires($share_user_expires[$user_id] ?? null));
		}
		$this->db->deletePasswordUserGroupShareByPassword($password_id);
		foreach($share_groups as $group_id) {
			$this->db->insertPasswordUserGroupShare($password_id, $group_id, intval($share_group_permissions[$group_id] ?? 0), self::parseExpires($share_group_expires[$group_id] ?? null));
		}
	}

	public function uploadFile(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$password_id = $request->getAttribute('id');
			$json = JsonRpc::parseJsonRequest($request);

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($password_id))
			|| $this->db->selectPasswordPermission($password_id, $_SESSION['user_id']) & self::PERMISSION_READ_ONLY) {
				throw new Exception('Permission denied');
			}

			// input checks - the server only stores the ciphertext, the file key is part of the encrypted secret
			$data = base64_decode($json['data'] ?? '', true);
			if(empty($data)) {
				throw new Exception('Invalid data');
			}
			if(strlen($data) > ($this->container->get('settings')['maxFileSize'] ?? 10*1024*1024)) {
				throw new Exception($this->langCtrl->translate('file_too_large'));
			}

			// insert data
			$id = $this->db->insertPasswordFile($password_id, $data);

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

	public function downloadFile(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$password_id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($password_id))) {
				throw new Exception('Permission denied');
			}
			$file = $this->db->selectPasswordFile($request->getAttribute('fid'), $password_id);
			if(empty($file)) {
				throw new Exception('Not found');
			}

			// return ciphertext
			$response->getBody()->write($file->data);
			return $response->withHeader('Content-Type', 'application/octet-stream')
				->withHeader('Content-Disposition', 'attachment');

		} catch(Exception $e) {
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function removePassword(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordShare($id))
			|| $this->db->selectPasswordPermission($id, $_SESSION['user_id']) & self::PERMISSION_READ_ONLY) {
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
			$icon = $this->checkIcon($json['icon'] ?? null);
			$absoluteShareUserIds = $json['share_users'];
			foreach($json['share_groups'] as $group_id) {
				$absoluteShareUserIds = array_merge($absoluteShareUserIds, $this->db->selectAllUserIdByUserGroup($group_id));
			}
			if(!in_array($_SESSION['user_id'], $absoluteShareUserIds)) {
				throw new Exception('Not shared to yourself');
			}

			// permission check
			if(!empty($json['parent_password_group_id']) && (
				!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($json['parent_password_group_id']))
				|| $this->db->selectPasswordGroupPermission($json['parent_password_group_id'], $_SESSION['user_id']) & self::PERMISSION_READ_ONLY
			)) {
				throw new Exception('Permission denied');
			}

			// insert data
			$this->db->beginTransaction();
			$id = $this->db->insertPasswordGroup($json['parent_password_group_id']??null, $json['title'], $icon);
			$this->db->deletePasswordGroupUserShareByPasswordGroup($id);
			foreach($json['share_users'] as $user_id) {
				$this->db->insertPasswordGroupUserShare($id, $user_id, intval($json['share_user_permissions'][$user_id] ?? 0), self::parseExpires($json['share_user_expires'][$user_id] ?? null));
			}
			$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($id);
			foreach($json['share_groups'] as $group_id) {
				$this->db->insertPasswordGroupUserGroupShare($id, $group_id, intval($json['share_group_permissions'][$group_id] ?? 0), self::parseExpires($json['share_group_expires'][$group_id] ?? null));
			}
			$this->db->commitTransaction();

			// return response
			$response->getBody()->write(json_encode([
				'success' => true,
				'id' => $id,
			]));
			return $response->withHeader('Content-Type', 'application/json');

		} catch(Exception $e) {
			$this->db->rollbackTransaction();
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
			$icon = $this->checkIcon($json['icon'] ?? null);
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
			$permission = $this->db->selectPasswordGroupPermission($id, $_SESSION['user_id']);
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($id))
			|| $permission & self::PERMISSION_READ_ONLY
			|| (
				!empty($json['parent_password_group_id'])
				&& !in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($json['parent_password_group_id']))
				&& $json['parent_password_group_id'] != $group->parent_password_group_id
			)) {
				throw new Exception('Permission denied');
			}
			$this->checkShareChangeAllowed($permission,
				$this->db->selectAllSharedUserByPasswordGroup($id), $this->db->selectAllSharedUserGroupByPasswordGroup($id),
				$json['share_users'], $json['share_groups'], $json['share_user_permissions'] ?? [], $json['share_group_permissions'] ?? [],
				$json['share_user_expires'] ?? [], $json['share_group_expires'] ?? []
			);

			// update data
			$this->db->beginTransaction();
			$this->db->updatePasswordGroup($id, $json['parent_password_group_id'], $json['title'], $icon);
			$this->db->deletePasswordGroupUserShareByPasswordGroup($id);
			foreach($json['share_users'] as $user_id) {
				$this->db->insertPasswordGroupUserShare($id, $user_id, intval($json['share_user_permissions'][$user_id] ?? 0), self::parseExpires($json['share_user_expires'][$user_id] ?? null));
			}
			$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($id);
			foreach($json['share_groups'] as $group_id) {
				$this->db->insertPasswordGroupUserGroupShare($id, $group_id, intval($json['share_group_permissions'][$group_id] ?? 0), self::parseExpires($json['share_group_expires'][$group_id] ?? null));
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
					$this->updatePasswordUser($password_id, $passwordData['password_user'], $json['share_users'], $json['share_groups'], false,
						$json['share_user_permissions'] ?? [], $json['share_group_permissions'] ?? [], $json['share_user_expires'] ?? [], $json['share_group_expires'] ?? []);
				}
			}
			if(!empty($json['groups']) && is_array($json['groups'])) {
				foreach($json['groups'] as $sub_group_id => $groupData) {
					// permission check
					$subPermission = $this->db->selectPasswordGroupPermission($sub_group_id, $_SESSION['user_id']);
					if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($sub_group_id))
					|| $subPermission & self::PERMISSION_READ_ONLY) {
						throw new Exception('Permission to subgroup denied');
					}
					$this->checkShareChangeAllowed($subPermission,
						$this->db->selectAllSharedUserByPasswordGroup($sub_group_id), $this->db->selectAllSharedUserGroupByPasswordGroup($sub_group_id),
						$json['share_users'], $json['share_groups'], $json['share_user_permissions'] ?? [], $json['share_group_permissions'] ?? [],
						$json['share_user_expires'] ?? [], $json['share_group_expires'] ?? []
					);
					// update subgroup
					$this->db->deletePasswordGroupUserShareByPasswordGroup($sub_group_id);
					foreach($json['share_users'] as $user_id) {
						$this->db->insertPasswordGroupUserShare($sub_group_id, $user_id, intval($json['share_user_permissions'][$user_id] ?? 0), self::parseExpires($json['share_user_expires'][$user_id] ?? null));
					}
					$this->db->deletePasswordGroupUserGroupShareByPasswordGroup($sub_group_id);
					foreach($json['share_groups'] as $group_id) {
						$this->db->insertPasswordGroupUserGroupShare($sub_group_id, $group_id, intval($json['share_group_permissions'][$group_id] ?? 0), self::parseExpires($json['share_group_expires'][$group_id] ?? null));
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
			$this->db->rollbackTransaction();
			$response->getBody()->write($e->getMessage());
			return $response->withStatus(400);
		}
	}

	public function removeGroup(Request $request, Response $response, $args) {
		try {
			$this->checkLogin();
			$id = $request->getAttribute('id');

			// permission check
			if(!in_array($_SESSION['user_id'], $this->db->selectAllUserByPasswordGroupShare($id))
			|| $this->db->selectPasswordGroupPermission($id, $_SESSION['user_id']) & self::PERMISSION_READ_ONLY) {
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

	private static function compileShares($shares, $idColumn) {
		// split share rows into an id list, a permission map and an expiry map
		$ids = [];
		$permissions = [];
		$expires = [];
		foreach($shares as $share) {
			$ids[] = $share->$idColumn;
			$permissions[$share->$idColumn] = $share->permission;
			$expires[$share->$idColumn] = $share->expires;
		}
		return [$ids, $permissions, $expires];
	}
	private static function parseExpires($expires) {
		// expiry dates are transferred as UTC 'Y-m-d H:i:s' strings
		if(empty($expires)) return null;
		$date = DateTime::createFromFormat('Y-m-d H:i:s', $expires, new DateTimeZone('UTC'));
		if(!$date || $date->format('Y-m-d H:i:s') !== $expires) {
			throw new Exception('Invalid expiry date');
		}
		return $expires;
	}

	private static function shareMap($ids, $permissions, $expires) {
		$map = [];
		foreach($ids as $id) {
			$map[intval($id)] = [intval($permissions[$id] ?? 0), self::parseExpires($expires[$id] ?? null)];
		}
		ksort($map);
		return $map;
	}
	private function checkShareChangeAllowed($permission, $existingUserShares, $existingGroupShares, $share_users, $share_groups, $share_user_permissions, $share_group_permissions, $share_user_expires, $share_group_expires) {
		// users without resharing permission must leave the shares as they are
		if(!($permission & self::PERMISSION_NO_RESHARE)) return;
		list($existingUsers, $existingUserPermissions, $existingUserExpires) = self::compileShares($existingUserShares, 'user_id');
		list($existingGroups, $existingGroupPermissions, $existingGroupExpires) = self::compileShares($existingGroupShares, 'user_group_id');
		if(self::shareMap($share_users, $share_user_permissions, $share_user_expires) != self::shareMap($existingUsers, $existingUserPermissions, $existingUserExpires)
		|| self::shareMap($share_groups, $share_group_permissions, $share_group_expires) != self::shareMap($existingGroups, $existingGroupPermissions, $existingGroupExpires)) {
			throw new Exception('Permission denied');
		}
	}

	private function checkIcon($icon) {
		// an icon file name or a small PNG image uploaded by the user (re-encoded by the client)
		if(empty($icon)) return null;
		if(in_array($icon, $this->getIconNames())) return $icon;
		if(strlen($icon) <= 20000 && preg_match('/^data:image\/png;base64,([A-Za-z0-9+\/]+=*)$/', $icon, $matches)
		&& str_starts_with(base64_decode($matches[1], true) ?: '', "\x89PNG\r\n\x1a\n")) return $icon;
		throw new Exception('Invalid icon');
	}

	private function getIconNames() {
		$names = [];
		foreach(glob(__DIR__.'/../../public/img/icon/*.svg') as $file) {
			$names[] = basename($file, '.svg');
		}
		return $names;
	}

	public function translate($string) {
		return $this->langCtrl->translate($string);
	}

	public function checkLogin($touch=true) {
		if(empty($_SESSION['user_id'])) {
			throw new Exception('Not logged in');
		}
		// PHP's session gc does not reliably enforce the timeout, so check it here
		$timeout = $this->container->get('settings')['sessionTimeout'] ?? 0;
		if($timeout && isset($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > $timeout) {
			$_SESSION = [];
			throw new Exception('Session expired');
		}
		if($touch) $_SESSION['last_activity'] = time();
		$user = $this->db->selectUser($_SESSION['user_id']);
		if(empty($user) || $user->locked) {
			throw new Exception('Invalid user');
		}
	}

}
