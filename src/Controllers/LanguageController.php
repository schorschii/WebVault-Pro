<?php
namespace WebVault\Controllers;

class LanguageController {

	const BASE_LANG = 'en';

	const LANG_DIR = __DIR__.'/../Lang';

	const LANG_MAP = [
		'en' => 'English',
		'de' => 'Deutsch'
	];

	private $langCode;
	private $translations;

	function __construct() {
		$this->langCode = $this->getCurrentLangCode();
		$this->translations = require(self::LANG_DIR.'/'.self::BASE_LANG.'.php');
		if($this->langCode && array_key_exists($this->langCode, self::LANG_MAP)) {
			$preferenceTranslations = require(self::LANG_DIR.'/'.$this->langCode.'.php');
			$this->translations = array_merge($this->translations, $preferenceTranslations);
		}
	}

	public function translate($string) {
		// return translation if exists
		if(isset($this->translations[$string]))
			return $this->translations[$string];
		else
			return $string;
	}

	public function getTranslations() {
		return $this->translations;
	}

	private function getCurrentLangCode() {
		$browserLanguage = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
		if(isset($_SESSION['lang']) && array_key_exists($_SESSION['lang'], self::LANG_MAP)) {
			// user preference
			return $_SESSION['lang'];
		} elseif(array_key_exists($browserLanguage, self::LANG_MAP)) {
			// browser language
			return $browserLanguage;
		} else {
			// default language
			return self::BASE_LANG;
		}
	}

}
