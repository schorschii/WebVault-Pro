<?php
namespace WebVault\Controllers;

use \PDO as PDO;
use \Exception as Exception;

class DatabaseController {

	/* Function naming
	   "select..." - returns single item
	   "selectAll..." - returns array
	   "insert...", "update...", "delete..." */

	private $dbh;

	function __construct($dbsettings) {
		try {
			$this->dbh = new PDO(
				$dbsettings['driver'].':host='.$dbsettings['host'].';dbname='.$dbsettings['database'].';',
				$dbsettings['username'], $dbsettings['password'],
				array(PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8mb4')
			);
			$this->dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		} catch(Exception $e) {
			error_log($e->getMessage());
			throw new Exception('Failed to establish database connection to ›'.$dbsettings['host'].'‹. Gentle panic.');
		}
	}

	public function getDbHandle() {
		return $this->dbh;
	}
	public function getLastStatement() {
		return $this->stmt;
	}

	public function beginTransaction() {
		$this->dbh->beginTransaction();
	}
	public function commitTransaction() {
		$this->dbh->commit();
	}
	public function rollbackTransaction() {
		$this->dbh->rollBack();
	}

	public function selectAllUser() {
		$this->stmt = $this->dbh->prepare(
			'SELECT * FROM user'
		);
		$this->stmt->execute();
		return $this->stmt->fetchAll(PDO::FETCH_CLASS);
	}
	public function selectAllUserForShare() {
		$this->stmt = $this->dbh->prepare(
			'SELECT id, display_name, public_key FROM user ORDER BY display_name'
		);
		$this->stmt->execute();
		return $this->stmt->fetchAll(PDO::FETCH_CLASS);
	}
	public function selectUser($id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT * FROM user WHERE id = :id'
		);
		$this->stmt->execute([':id' => $id]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function selectUserByUsername($username) {
		$this->stmt = $this->dbh->prepare(
			'SELECT * FROM user WHERE username = :username'
		);
		$this->stmt->execute([':username' => $username]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function selectUserByUid($uid) {
		$this->stmt = $this->dbh->prepare(
			'SELECT * FROM user WHERE uid = :uid'
		);
		$this->stmt->execute([':uid' => $uid]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function insertUser($uid, $username, $display_name, $password, $ldap, $email, $description, $locked) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO user (uid, username, display_name, password, ldap, email, description, locked)
			VALUES (:uid, :username, :display_name, :password, :ldap, :email, :description, :locked)'
		);
		$this->stmt->execute([
			':uid' => $uid,
			':username' => $username,
			':display_name' => $display_name,
			':password' => $password,
			':ldap' => $ldap,
			':email' => $email,
			':description' => $description,
			':locked' => $locked,
		]);
		return $this->dbh->lastInsertId();
	}
	public function updateUser($id, $uid, $username, $display_name, $password, $ldap, $email, $description, $locked) {
		$this->stmt = $this->dbh->prepare(
			'UPDATE user SET uid = :uid, username = :username, display_name = :display_name, password = :password, ldap = :ldap, email = :email, description = :description, locked = :locked WHERE id = :id'
		);
		return $this->stmt->execute([
			':id' => $id,
			':uid' => $uid,
			':username' => $username,
			':display_name' => $display_name,
			':password' => $password,
			':ldap' => $ldap,
			':email' => $email,
			':description' => $description,
			':locked' => $locked,
		]);
	}
	public function updateUserKeys($id, $public_key, $private_key, $salt, $iv) {
		$this->stmt = $this->dbh->prepare(
			'UPDATE user SET public_key = :public_key, private_key = :private_key, salt = :salt, iv = :iv WHERE id = :id'
		);
		$this->stmt->execute([
			':id' => $id,
			':public_key' => $public_key,
			':private_key' => $private_key,
			':salt' => $salt,
			':iv' => $iv,
		]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function deleteUser($id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM user WHERE id = :id'
		);
		$this->stmt->execute([':id' => $id]);
		return $this->stmt->rowCount();
	}

	public function insertUserGroup($title) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO user_group (title) VALUES (:title)'
		);
		$this->stmt->execute([':title' => $title]);
		return $this->dbh->lastInsertId();
	}
	public function insertUserGroupMember($user_id, $user_group_id) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO user_group_member (user_id, user_group_id) VALUES (:user_id, :user_group_id)'
		);
		$this->stmt->execute([':user_id' => $user_id, ':user_group_id' => $user_group_id]);
		return $this->dbh->lastInsertId();
	}
	public function deleteUserGroupMemberByUserGroup($user_group_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM user_group_member WHERE user_group_id = :user_group_id'
		);
		return $this->stmt->execute([':user_group_id' => $user_group_id]);
	}
	public function deleteUserGroup($id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM user_group WHERE id = :id'
		);
		return $this->stmt->execute([':id' => $id]);
	}

	public function selectAllUserGroupForShare($user_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT ug.id, ug.title FROM user_group ug
			WHERE ug.id IN (SELECT ugm.user_group_id FROM user_group_member ugm WHERE ugm.user_id = :user_id)
			ORDER BY ug.title'
		);
		$this->stmt->execute([':user_id' => $user_id]);
		return $this->stmt->fetchAll(PDO::FETCH_CLASS);
	}
	public function selectAllUserIdByUserGroup($user_group_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT user_id FROM user_group_member WHERE user_group_id = :user_group_id'
		);
		$this->stmt->execute([':user_group_id' => $user_group_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->user_id;
		}
		return $array;
	}

	public function selectAllPasswordByUser($user_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT p.id, p.password_group_id, p.revision, p.secret, p.aes_iv, pu.aes_key, pu.rsa_iv
			FROM password_user pu JOIN password p ON pu.password_id = p.id
			WHERE pu.user_id = :user_id
			AND p.id IN (
				SELECT spu.password_id FROM share_password_user spu
				WHERE spu.user_id = :user_id
				UNION SELECT spug.password_id FROM share_password_user_group spug
				WHERE spug.user_group_id IN (
					SELECT ugm.user_group_id FROM user_group_member ugm WHERE ugm.user_id = :user_id
				)
			)'
		);
		$this->stmt->execute([':user_id' => $user_id]);
		return $this->stmt->fetchAll(PDO::FETCH_CLASS);
	}
	public function selectAllPasswordGroupByUser($user_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT pg.id, pg.parent_password_group_id, pg.title
			FROM password_group pg
			WHERE pg.id IN (
				SELECT spgu.password_group_id FROM share_password_group_user spgu
				WHERE spgu.user_id = :user_id
				UNION SELECT spgug.password_group_id FROM share_password_group_user_group spgug
				WHERE spgug.user_group_id IN (
					SELECT ugm.user_group_id FROM user_group_member ugm WHERE ugm.user_id = :user_id
				)
			)'
		);
		$this->stmt->execute([':user_id' => $user_id]);
		return $this->stmt->fetchAll(PDO::FETCH_CLASS);
	}
	public function selectMaxPasswordRevision($id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT MAX(revision) AS revision, password_group_id FROM password WHERE id = :id'
		);
		$this->stmt->execute([':id' => $id]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function insertPassword($password_group_id, $secret, $aes_iv, $revision) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO password (password_group_id, secret, aes_iv, revision)
			VALUES (:password_group_id, :secret, :aes_iv, :revision)'
		);
		$this->stmt->execute([
			':password_group_id' => $password_group_id,
			':secret' => $secret,
			':aes_iv' => $aes_iv,
			':revision' => $revision,
		]);
		return $this->dbh->lastInsertId();
	}
	public function insertPasswordUser($password_id, $user_id, $aes_key, $rsa_iv) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO password_user (password_id, user_id, aes_key, rsa_iv)
			VALUES (:password_id, :user_id, :aes_key, :rsa_iv)'
		);
		$this->stmt->execute([
			':password_id' => $password_id,
			':user_id' => $user_id,
			':aes_key' => $aes_key,
			':rsa_iv' => $rsa_iv,
		]);
		return $this->dbh->lastInsertId();
	}
	public function updatePassword($id, $password_group_id, $secret, $aes_iv, $revision) {
		$this->stmt = $this->dbh->prepare(
			'UPDATE password SET password_group_id = :password_group_id, secret = :secret, aes_iv = :aes_iv, revision = :revision
			WHERE id = :id'
		);
		$this->stmt->execute([
			':id' => $id,
			':password_group_id' => $password_group_id,
			':secret' => $secret,
			':aes_iv' => $aes_iv,
			':revision' => $revision,
		]);
		return $this->dbh->lastInsertId();
	}
	public function deletePassword($id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM password WHERE id = :id'
		);
		return $this->stmt->execute([':id' => $id]);
	}
	public function deletePasswordUserByPassword($password_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM password_user WHERE password_id = :password_id'
		);
		return $this->stmt->execute([':password_id' => $password_id]);
	}

	public function selectAllSharedUserIdByPassword($password_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT user_id, permission FROM share_password_user WHERE password_id = :password_id'
		);
		$this->stmt->execute([':password_id' => $password_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->user_id;
		}
		return $array;
	}
	public function selectAllSharedUserGroupIdByPassword($password_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT user_group_id, permission FROM share_password_user_group WHERE password_id = :password_id'
		);
		$this->stmt->execute([':password_id' => $password_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->user_group_id;
		}
		return $array;
	}
	public function selectAllSharedUserIdByPasswordGroup($password_group_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT user_id, permission FROM share_password_group_user WHERE password_group_id = :password_group_id'
		);
		$this->stmt->execute([':password_group_id' => $password_group_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->user_id;
		}
		return $array;
	}
	public function selectAllSharedUserGroupIdByPasswordGroup($password_group_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT user_group_id, permission FROM share_password_group_user_group WHERE password_group_id = :password_group_id'
		);
		$this->stmt->execute([':password_group_id' => $password_group_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->user_group_id;
		}
		return $array;
	}
	public function selectAllUserByPasswordShare($password_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT u.id FROM user u
			JOIN share_password_user spu ON spu.user_id = u.id
			WHERE spu.password_id = :password_id
			UNION SELECT u.id FROM user u
			WHERE u.id IN (
				SELECT ugm.user_id FROM user_group_member ugm
				JOIN share_password_user_group spug ON spug.user_group_id = ugm.user_group_id
				WHERE spug.password_id = :password_id
			)'
		);
		$this->stmt->execute([':password_id' => $password_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->id;
		}
		return $array;
	}
	public function selectAllUserByPasswordGroupShare($password_group_id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT u.id FROM user u
			JOIN share_password_group_user spgu ON spgu.user_id = u.id
			WHERE spgu.password_group_id = :password_group_id
			UNION SELECT u.id FROM user u
			WHERE u.id IN (
				SELECT ugm.user_id FROM user_group_member ugm
				JOIN share_password_group_user_group spgug ON spgug.user_group_id = ugm.user_group_id
				WHERE spgug.password_group_id = :password_group_id
			)'
		);
		$this->stmt->execute([':password_group_id' => $password_group_id]);
		$array = [];
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			$array[] = $row->id;
		}
		return $array;
	}
	public function insertPasswordUserShare($password_id, $user_id) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO share_password_user (password_id, user_id) VALUES (:password_id, :user_id)'
		);
		$this->stmt->execute([
			':password_id' => $password_id,
			':user_id' => $user_id,
		]);
		return $this->dbh->lastInsertId();
	}
	public function insertPasswordUserGroupShare($password_id, $user_group_id) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO share_password_user_group (password_id, user_group_id) VALUES (:password_id, :user_group_id)'
		);
		$this->stmt->execute([
			':password_id' => $password_id,
			':user_group_id' => $user_group_id,
		]);
		return $this->dbh->lastInsertId();
	}
	public function insertPasswordGroupUserShare($password_group_id, $user_id) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO share_password_group_user (password_group_id, user_id) VALUES (:password_group_id, :user_id)'
		);
		$this->stmt->execute([
			':password_group_id' => $password_group_id,
			':user_id' => $user_id,
		]);
		return $this->dbh->lastInsertId();
	}
	public function insertPasswordGroupUserGroupShare($password_group_id, $user_group_id) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO share_password_group_user_group (password_group_id, user_group_id) VALUES (:password_group_id, :user_group_id)'
		);
		$this->stmt->execute([
			':password_group_id' => $password_group_id,
			':user_group_id' => $user_group_id,
		]);
		return $this->dbh->lastInsertId();
	}
	public function deletePasswordUserShareByPassword($password_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM share_password_user WHERE password_id = :password_id'
		);
		return $this->stmt->execute([':password_id' => $password_id]);
	}
	public function deletePasswordUserGroupShareByPassword($password_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM share_password_user_group WHERE password_id = :password_id'
		);
		return $this->stmt->execute([':password_id' => $password_id]);
	}
	public function deletePasswordGroupUserShareByPasswordGroup($password_group_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM share_password_group_user WHERE password_group_id = :password_group_id'
		);
		return $this->stmt->execute([':password_group_id' => $password_group_id]);
	}
	public function deletePasswordGroupUserGroupShareByPasswordGroup($password_group_id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM share_password_group_user_group WHERE password_group_id = :password_group_id'
		);
		return $this->stmt->execute([':password_group_id' => $password_group_id]);
	}

	public function selectPasswordGroup($id) {
		$this->stmt = $this->dbh->prepare(
			'SELECT * FROM password_group WHERE id = :id'
		);
		$this->stmt->execute([':id' => $id]);
		foreach($this->stmt->fetchAll(PDO::FETCH_CLASS) as $row) {
			return $row;
		}
	}
	public function insertPasswordGroup($parent_password_group_id, $title) {
		$this->stmt = $this->dbh->prepare(
			'INSERT INTO password_group (parent_password_group_id, title)
			VALUES (:parent_password_group_id, :title)'
		);
		$this->stmt->execute([
			':parent_password_group_id' => $parent_password_group_id,
			':title' => $title,
		]);
		return $this->dbh->lastInsertId();
	}
	public function updatePasswordGroup($id, $parent_password_group_id, $title) {
		$this->stmt = $this->dbh->prepare(
			'UPDATE password_group SET parent_password_group_id = :parent_password_group_id, title = :title
			WHERE id = :id'
		);
		$this->stmt->execute([
			':id' => $id,
			':parent_password_group_id' => $parent_password_group_id,
			':title' => $title,
		]);
		return $this->dbh->lastInsertId();
	}
	public function deletePasswordGroup($id) {
		$this->stmt = $this->dbh->prepare(
			'DELETE FROM password_group WHERE id = :id'
		);
		$this->stmt->execute([':id' => $id]);
		return $this->dbh->lastInsertId();
	}

}
