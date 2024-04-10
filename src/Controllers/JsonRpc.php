<?php
namespace XVault\Controllers;

use \Exception as Exception;
use Slim\Psr7\Request as Request;
use Slim\Psr7\Response as Response;

class JsonRpc {

	static function parseJsonRequest(Request $request) {
		if($request->getHeaderLine('Content-Type') !== 'application/json')
			throw new Exception('Invalid content type');
		$json = json_decode(file_get_contents('php://input'), true);
		if($json === null)
			throw new Exception('Invalid JSON payload');
		return $json;
	}

}
