<?php
namespace XVault\Twig_Extensions;

class TranslateFilterExtension extends \Twig\Extension\AbstractExtension {
	private $language;

	public function __construct($language) {
		$this->language = $language;
	}

	public function getFilters() {
		return array(
			new \Twig\TwigFilter('trans', array($this, 'translate')),
		);
	}

	public function translate($string) {
		// load translation file
		$langFilePath = \XVault\Controllers\LanguageController::LANG_DIR.'/'.$this->language.'.php';
		if(file_exists($langFilePath)) require($langFilePath);

		// return translation if exists
		if(isset($LANG[$string]))
			return $LANG[$string];
		else
			return $string;
	}
}
