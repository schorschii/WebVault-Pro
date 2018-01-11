<?php

class TranslateFilterExtension extends \Twig_Extension
{
	private $language = "";

	public function __construct($language) {
		$this->language = $language;
	}

	public function getFilters()
	{
		return array(
			new \Twig_SimpleFilter('trans', array($this, 'translate')),
		);
	}

	public function translate($string)
	{
		$langFilePath = __DIR__."/../../lang/".$this->language.".php";
		if(file_exists($langFilePath))
			require($langFilePath);
		if(isset($LANG[$string]))
			return $LANG[$string];
		else
			return $string;
	}
}
