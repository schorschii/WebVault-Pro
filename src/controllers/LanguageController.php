<?php
namespace WebPW\Controllers;

class LanguageController {

	public function getLanguages($defaultlanguage = "")
	{
		$currentlanguage = $this->getCurrentLanguage($defaultlanguage);
		$languages = [];
		foreach(scandir(__DIR__.'/../../lang') as $file) {
			$isCurrentLanguage = (basename($file, ".php") == $currentlanguage);
			if(substr($file, 0, 1) == ".") continue;
			$languages[] = [ 'title' => basename($file, ".php"), 'selected' => $isCurrentLanguage ];
		}
		return $languages;
	}

	private function getCurrentLanguage($defaultlanguage = "") {
		if(isset($_SESSION['lang']))
			return $_SESSION['lang'];
		else
			return $defaultlanguage;
	}

}
