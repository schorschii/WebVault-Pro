<?php
namespace WebVault\Tests;

use PHPUnit\Framework\TestCase;
use WebVault\Controllers\UserController;
use WebVault\Controllers\VaultController;
use WebVault\Controllers\DatabaseController;
use WebVault\Controllers\Totp;

class UserControllerTest extends TestCase {

	const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	private $mockDb;
	private $checkTotp;
	private UserController $controller;

	protected function setUp(): void {
		$_SESSION = [];
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en';

		$this->mockDb = $this->createMock(DatabaseController::class);
		$mockContainer = $this->createMock(\DI\Container::class);
		$mockContainer->method('get')->willReturn(['ldapSync' => []]);

		$this->controller = new UserController($mockContainer, $this->mockDb, new VaultController($mockContainer, $this->mockDb));
		$this->checkTotp = new \ReflectionMethod(UserController::class, 'checkTotp');
	}

	private function createUser($failures, $failedAt) {
		$user = new \stdClass();
		$user->id = 1;
		$user->username = 'test';
		$user->totp_secret = self::SECRET;
		$user->totp_recovery = '[]';
		$user->totp_last_step = null;
		$user->totp_failures = $failures;
		$user->totp_failed_at = $failedAt;
		return $user;
	}

	// --- checkTotp ---

	public function testCheckTotpAcceptsCurrentCode(): void {
		$this->mockDb->expects($this->once())->method('updateUserTotpLastStep');
		$code = Totp::getCode(self::SECRET, intdiv(time(), Totp::PERIOD));
		$this->assertTrue($this->checkTotp->invoke($this->controller, $this->createUser(0, null), $code));
	}

	public function testCheckTotpLockedAfterTooManyFailures(): void {
		$this->mockDb->expects($this->never())->method('updateUserTotpLastStep');
		$code = Totp::getCode(self::SECRET, intdiv(time(), Totp::PERIOD));
		$this->assertFalse($this->checkTotp->invoke($this->controller, $this->createUser(5, time() - 10), $code));
	}

	public function testCheckTotpCountsRecentFailures(): void {
		$this->mockDb->expects($this->once())->method('updateUserTotpFailures')->with(1, 3, $this->anything());
		$this->assertFalse($this->checkTotp->invoke($this->controller, $this->createUser(2, time() - 10), 'wrong'));
	}

	public function testCheckTotpRestartsCountingAfterLockTime(): void {
		$this->mockDb->expects($this->once())->method('updateUserTotpFailures')->with(1, 1, $this->anything());
		$this->assertFalse($this->checkTotp->invoke($this->controller, $this->createUser(5, time() - 1000), 'wrong'));
	}
}
