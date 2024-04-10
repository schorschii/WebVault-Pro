<?php
namespace XVault\Twig_Extensions;

class ShortFilterExtension extends \Twig\Extension\AbstractExtension {
	private $maxlength = 21;

	public function __construct($maxlength) {
		$this->maxlength = $maxlength;
	}

	public function getFilters() {
		return array(
			new \Twig\TwigFilter('short', array($this, 'shortText')),
		);
	}

	public function shortText($string) {
		return strlen($string) > $this->maxlength ? substr($string, 0, $this->maxlength).'…' : $string;
	}
}
