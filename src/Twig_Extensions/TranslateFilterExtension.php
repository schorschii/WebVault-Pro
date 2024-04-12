<?php
namespace XVault\Twig_Extensions;

class TranslateFilterExtension extends \Twig\Extension\AbstractExtension {
	private $langCtrl;

	public function __construct($langCtrl) {
		$this->langCtrl = $langCtrl;
	}

	public function getFilters() {
		return array(
			new \Twig\TwigFilter('trans', array($this, 'translate')),
		);
	}

	public function translate($string) {
		return $this->langCtrl->translate($string);
	}
}
