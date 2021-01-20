<?php
namespace WebPW\Controllers;

class LanguageController {

	private $container = null;

	public function __construct($container)
	{
		$this->container = $container;
	}


	private $languageMap = [
		'en' => 'English',
		'de' => 'Deutsch'
	];

	public function getLanguages($preselectLanguage = true)
	{
		if($preselectLanguage) $preselectLanguageName = $this->getCurrentLanguage();
		$languages = [];
		foreach(scandir(__DIR__.'/../../lang') as $file) {
			if(substr($file, 0, 1) == ".") continue;
			$isCurrentLanguage = ($preselectLanguage && basename($file, ".php") == $preselectLanguageName);
			$langTitle = basename($file, ".php");
			if(isset($this->languageMap[$langTitle])) $langTitle = $this->languageMap[$langTitle];
			$languages[] = [ 'title' => $langTitle, 'filename' => basename($file, ".php"), 'selected' => $isCurrentLanguage ];
		}
		return $languages;
	}

	private function existsLanguage($language, $validLanguages) {
		foreach($validLanguages as $validLanguage) {
			if($validLanguage['filename'] == $language)
				return true;
		}
		return false;
	}

	public function getCurrentLanguage() {
		$validLanguages = $this->getLanguages(false);
		$browserLanguage = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
		if(isset($_SESSION['lang']) && $this->existsLanguage($_SESSION['lang'], $validLanguages)) {
			// user preference
			return $_SESSION['lang'];
		} elseif($this->existsLanguage($browserLanguage, $validLanguages)) {
			// browser language
			return $browserLanguage;
		} else {
			// take default language from config file
			return $this->container->get('settings')['defaultLanguage'];
		}
	}

}
