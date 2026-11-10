<?php
namespace WebVault\Tests;

use PHPUnit\Framework\TestCase;
use WebVault\Controllers\LanguageController;

class LanguageControllerTest extends TestCase {

	protected function setUp(): void {
		$_SESSION = [];
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en';
	}

	public function testTranslateKnownKey(): void {
		$lc = new LanguageController();
		$this->assertEquals('Close', $lc->translate('close'));
	}

	public function testTranslateFallsBackToKey(): void {
		$lc = new LanguageController();
		$this->assertEquals('nonexistent_key', $lc->translate('nonexistent_key'));
	}

	public function testGetTranslationsReturnsNonEmptyArray(): void {
		$lc = new LanguageController();
		$this->assertIsArray($lc->getTranslations());
		$this->assertNotEmpty($lc->getTranslations());
	}

	public function testGermanTranslationsFromBrowserHeader(): void {
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'de';
		$lc = new LanguageController();
		$this->assertEquals('Schließen', $lc->translate('close'));
		$this->assertEquals('Passwort', $lc->translate('password'));
	}

	public function testSessionLangOverridesBrowserLang(): void {
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'de';
		$_SESSION['lang'] = 'en';
		$lc = new LanguageController();
		$this->assertEquals('Close', $lc->translate('close'));
	}

	public function testUnknownBrowserLangFallsBackToEnglish(): void {
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'xy';
		$lc = new LanguageController();
		$this->assertEquals('Close', $lc->translate('close'));
	}

	public function testMissingBrowserLangFallsBackToEnglish(): void {
		unset($_SERVER['HTTP_ACCEPT_LANGUAGE']);
		$lc = new LanguageController();
		$this->assertEquals('Close', $lc->translate('close'));
	}

	public function testGermanTranslationsMergeWithEnglish(): void {
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'de';
		$lc = new LanguageController();
		$translations = $lc->getTranslations();
		// Keys only in English file should still be present
		$this->assertArrayHasKey('close', $translations);
		// German value should override English
		$this->assertEquals('Schließen', $translations['close']);
	}
}
