<?php
namespace WebVault\Tests;

use PHPUnit\Framework\TestCase;
use WebVault\Controllers\Totp;

class TotpTest extends TestCase {

	// RFC 6238 test vectors (SHA1, secret "12345678901234567890"), truncated to 6 digits
	const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function testBase32RoundTrip(): void {
		$this->assertEquals('12345678901234567890', Totp::base32Decode(self::SECRET));
		$this->assertEquals(self::SECRET, Totp::base32Encode('12345678901234567890'));
	}

	public function testGetCodeMatchesRfcVectors(): void {
		$this->assertEquals('287082', Totp::getCode(self::SECRET, intdiv(59, 30)));
		$this->assertEquals('081804', Totp::getCode(self::SECRET, intdiv(1111111109, 30)));
		$this->assertEquals('005924', Totp::getCode(self::SECRET, intdiv(1234567890, 30)));
	}

	public function testVerifyAcceptsAdjacentStepsAndRejectsOthers(): void {
		$step = intdiv(1234567890, 30);
		$this->assertEquals($step, Totp::verify(self::SECRET, '005924', null, 1234567890));
		$this->assertEquals($step, Totp::verify(self::SECRET, '005924', null, 1234567890 + 30)); // previous step
		$this->assertEquals($step, Totp::verify(self::SECRET, '005924', null, 1234567890 - 30)); // next step
		$this->assertFalse(Totp::verify(self::SECRET, '005924', null, 1234567890 + 60));
		$this->assertFalse(Totp::verify(self::SECRET, '000000', null, 1234567890));
	}

	public function testVerifyRejectsReusedCode(): void {
		$step = intdiv(1234567890, 30);
		$this->assertFalse(Totp::verify(self::SECRET, '005924', $step, 1234567890));
	}

	public function testGeneratedSecretIsValid(): void {
		$secret = Totp::generateSecret();
		$this->assertEquals(32, strlen($secret));
		$this->assertEquals(20, strlen(Totp::base32Decode($secret)));
	}
}
