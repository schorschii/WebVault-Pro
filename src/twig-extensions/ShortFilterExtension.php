<?php

class ShortFilterExtension extends \Twig_Extension
{
	private $maxlength = 21;

	public function __construct($maxlength) {
		$this->maxlength = $maxlength;
	}

	public function getFilters()
	{
		return array(
			new \Twig_SimpleFilter('short', array($this, 'shortText')),
		);
	}

	public function shortText($string)
	{
		return strlen($string) > $this->maxlength ? substr($string, 0, $this->maxlength)."..." : $string;
	}
}
