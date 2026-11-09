<?php
namespace WebVault\Tests;

use PHPUnit\Framework\TestCase;
use WebVault\Controllers\VaultController;
use WebVault\Controllers\DatabaseController;

class VaultControllerTest extends TestCase {

	private $mockDb;
	private $mockContainer;
	private VaultController $controller;

	protected function setUp(): void {
		$_SESSION = [];
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en';

		$this->mockDb = $this->createMock(DatabaseController::class);
		$this->mockContainer = $this->createMock(\DI\Container::class);

		$this->controller = new VaultController($this->mockContainer, $this->mockDb);
	}

	// --- checkLogin ---

	public function testCheckLoginThrowsWhenNoSession(): void {
		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Not logged in');
		$this->controller->checkLogin();
	}

	public function testCheckLoginThrowsWhenUserNotFound(): void {
		$_SESSION['user_id'] = 99;
		$this->mockDb->method('selectUser')->with(99)->willReturn(null);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Invalid user');
		$this->controller->checkLogin();
	}

	public function testCheckLoginThrowsWhenUserLocked(): void {
		$_SESSION['user_id'] = 1;
		$user = new \stdClass();
		$user->locked = true;
		$this->mockDb->method('selectUser')->with(1)->willReturn($user);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Invalid user');
		$this->controller->checkLogin();
	}

	public function testCheckLoginThrowsWhenSessionExpired(): void {
		$_SESSION['user_id'] = 1;
		$_SESSION['last_activity'] = time() - 11;
		$this->mockContainer->method('get')->with('settings')->willReturn(['sessionTimeout' => 10]);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Session expired');
		$this->controller->checkLogin();
	}

	public function testCheckLoginSucceeds(): void {
		$_SESSION['user_id'] = 1;
		$user = new \stdClass();
		$user->locked = false;
		$this->mockDb->method('selectUser')->with(1)->willReturn($user);

		$this->controller->checkLogin();
		$this->assertTrue(true); // no exception thrown
	}

	// --- updatePasswordUser ---

	public function testUpdatePasswordUserThrowsWhenEmpty(): void {
		$_SESSION['user_id'] = 1;

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Not encrypted to any user');
		$this->controller->updatePasswordUser(1, [], [], [], true);
	}

	public function testUpdatePasswordUserThrowsWhenSelfExcluded(): void {
		$_SESSION['user_id'] = 1;

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Not encrypted to yourself');
		$this->controller->updatePasswordUser(
			1,
			[2 => ['aes_key' => 'k', 'rsa_iv' => 'i']],
			[2],
			[],
			true
		);
	}

	public function testUpdatePasswordUserThrowsOnShareMismatch(): void {
		$_SESSION['user_id'] = 1;
		$this->mockDb->method('selectAllUserIdByUserGroup')->willReturn([]);

		// password_user contains user 1 and 2, but share_users only has user 1
		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Encrypted secrets do not match shares');
		$this->controller->updatePasswordUser(
			1,
			[1 => ['aes_key' => 'k', 'rsa_iv' => 'i'], 2 => ['aes_key' => 'k2', 'rsa_iv' => 'i2']],
			[1],
			[],
			true
		);
	}

	public function testUpdatePasswordUserThrowsOnInvalidData(): void {
		$_SESSION['user_id'] = 1;
		$this->mockDb->method('selectAllUserIdByUserGroup')->willReturn([]);
		$this->mockDb->method('deletePasswordUserByPassword')->willReturn(true);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Invalid data');
		$this->controller->updatePasswordUser(
			1,
			[1 => ['aes_key' => '', 'rsa_iv' => 'i']], // empty aes_key
			[1],
			[],
			true
		);
	}

	public function testUpdatePasswordUserSucceedsForNewPassword(): void {
		$_SESSION['user_id'] = 1;
		$this->mockDb->method('selectAllUserIdByUserGroup')->willReturn([]);
		$this->mockDb->expects($this->once())->method('deletePasswordUserByPassword')->with(42);
		$this->mockDb->expects($this->once())->method('insertPasswordUser')->with(42, 1, 'key123', 'iv123');
		$this->mockDb->expects($this->once())->method('deletePasswordUserShareByPassword')->with(42);
		$this->mockDb->expects($this->once())->method('insertPasswordUserShare')->with(42, 1);
		$this->mockDb->expects($this->once())->method('deletePasswordUserGroupShareByPassword')->with(42);

		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'key123', 'rsa_iv' => 'iv123']],
			[1],
			[],
			true
		);
	}

	public function testUpdatePasswordUserPermissionDeniedForExistingPassword(): void {
		$_SESSION['user_id'] = 1;
		// user 1 is NOT in the password share list
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([2, 3]);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Permission denied');
		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k', 'rsa_iv' => 'i']],
			[1],
			[],
			false
		);
	}

	public function testUpdatePasswordUserThrowsWhenNotInSharedGroup(): void {
		$_SESSION['user_id'] = 1;
		// user 1 is allowed on the password itself
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([1, 2]);
		// but user 1 is NOT a member of group 10 and the password was not shared with the group before
		$this->mockDb->method('selectAllUserIdByUserGroup')->with(10)->willReturn([2, 3]);
		$this->mockDb->method('selectAllSharedUserGroupIdByPassword')->with(42)->willReturn([]);

		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('You are not member of this group');
		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k', 'rsa_iv' => 'i']],
			[1],
			[10],
			false
		);
	}

	public function testUpdatePasswordUserKeepsExistingShareOfForeignGroup(): void {
		$_SESSION['user_id'] = 1;
		// user 1 is NOT a member of group 10, but the password is already shared with the group
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([1, 2, 3]);
		$this->mockDb->method('selectAllUserIdByUserGroup')->with(10)->willReturn([2, 3]);
		$this->mockDb->method('selectAllSharedUserGroupIdByPassword')->with(42)->willReturn([10]);
		$this->mockDb->method('deletePasswordUserByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUser')->willReturn(true);
		$this->mockDb->method('deletePasswordUserShareByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUserShare')->willReturn(true);
		$this->mockDb->method('deletePasswordUserGroupShareByPassword')->willReturn(true);
		$this->mockDb->expects($this->once())->method('insertPasswordUserGroupShare')->with(42, 10);

		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k1', 'rsa_iv' => 'i1'], 2 => ['aes_key' => 'k2', 'rsa_iv' => 'i2'], 3 => ['aes_key' => 'k3', 'rsa_iv' => 'i3']],
			[1],
			[10],
			false
		);
	}

	public function testUpdatePasswordUserWithGroupShareSucceeds(): void {
		$_SESSION['user_id'] = 1;
		// group 10 has members user 1 and user 2
		$this->mockDb->method('selectAllUserIdByUserGroup')->with(10)->willReturn([1, 2]);
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([1, 2]);
		$this->mockDb->method('deletePasswordUserByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUser')->willReturn(true);
		$this->mockDb->method('deletePasswordUserShareByPassword')->willReturn(true);
		$this->mockDb->method('deletePasswordUserGroupShareByPassword')->willReturn(true);
		$this->mockDb->expects($this->once())->method('insertPasswordUserGroupShare')->with(42, 10);

		// both group members must be present in password_user
		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k1', 'rsa_iv' => 'i1'], 2 => ['aes_key' => 'k2', 'rsa_iv' => 'i2']],
			[],
			[10],
			false
		);
	}

	public function testUpdatePasswordUserSucceedsWhenSharedDirectlyAndViaGroup(): void {
		$_SESSION['user_id'] = 1;
		// user 1 is shared directly and is also member of group 10,
		// share_users is not sorted and the db returns the ids as strings
		$this->mockDb->method('selectAllUserIdByUserGroup')->with(10)->willReturn(['1', '2']);
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([1, 2]);
		$this->mockDb->method('deletePasswordUserByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUser')->willReturn(true);
		$this->mockDb->method('deletePasswordUserShareByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUserShare')->willReturn(true);
		$this->mockDb->method('deletePasswordUserGroupShareByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUserGroupShare')->willReturn(true);

		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k1', 'rsa_iv' => 'i1'], 2 => ['aes_key' => 'k2', 'rsa_iv' => 'i2']],
			[2, 1],
			[10],
			false
		);
		$this->assertTrue(true); // no exception = success
	}

	public function testUpdatePasswordUserFetchesSharesFromDbWhenNull(): void {
		$_SESSION['user_id'] = 1;
		$this->mockDb->method('selectAllSharedUserIdByPassword')->with(42)->willReturn([1]);
		$this->mockDb->method('selectAllSharedUserGroupIdByPassword')->with(42)->willReturn([]);
		$this->mockDb->method('selectAllUserByPasswordShare')->with(42)->willReturn([1]);
		$this->mockDb->method('selectAllUserIdByUserGroup')->willReturn([]);
		$this->mockDb->method('deletePasswordUserByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUser')->willReturn(true);
		$this->mockDb->method('deletePasswordUserShareByPassword')->willReturn(true);
		$this->mockDb->method('insertPasswordUserShare')->willReturn(true);
		$this->mockDb->method('deletePasswordUserGroupShareByPassword')->willReturn(true);

		// passing null for shares — controller should fetch from DB
		$this->controller->updatePasswordUser(
			42,
			[1 => ['aes_key' => 'k', 'rsa_iv' => 'i']],
			null,
			null,
			false
		);
		$this->assertTrue(true); // no exception = success
	}
}
