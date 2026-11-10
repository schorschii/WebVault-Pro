<?php
namespace WebVault\Controllers;

// time-based one-time passwords (RFC 6238) using PHP's hash_hmac
class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const WINDOW = 1; // accept one time step before and after the current one

	public static function generateSecret() {
		return self::base32Encode(random_bytes(20));
	}

	public static function getUri($secret, $username, $issuer) {
		return 'otpauth://totp/'.rawurlencode($issuer).':'.rawurlencode($username)
			.'?secret='.$secret.'&issuer='.rawurlencode($issuer).'&algorithm=SHA1&digits='.self::DIGITS.'&period='.self::PERIOD;
	}

	public static function getCode($secret, $timeStep) {
		$hash = hash_hmac('sha1', pack('J', $timeStep), self::base32Decode($secret), true);
		$offset = ord($hash[19]) & 0x0f;
		$code = ((ord($hash[$offset]) & 0x7f) << 24) | (ord($hash[$offset+1]) << 16) | (ord($hash[$offset+2]) << 8) | ord($hash[$offset+3]);
		return str_pad(strval($code % pow(10, self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
	}

	// returns the matching time step or false; steps up to $lastStep are rejected to prevent code reuse
	public static function verify($secret, $code, $lastStep=null, $time=null) {
		$currentStep = intdiv($time ?? time(), self::PERIOD);
		for($step = $currentStep - self::WINDOW; $step <= $currentStep + self::WINDOW; $step++) {
			if($lastStep !== null && $step <= $lastStep) continue;
			if(hash_equals(self::getCode($secret, $step), strval($code))) return $step;
		}
		return false;
	}

	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function base32Encode($data) {
		$binary = '';
		foreach(str_split($data) as $char) {
			$binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
		}
		$encoded = '';
		foreach(str_split($binary, 5) as $chunk) {
			$encoded .= self::BASE32_ALPHABET[bindec(str_pad($chunk, 5, '0'))];
		}
		return $encoded;
	}

	public static function base32Decode($encoded) {
		$binary = '';
		foreach(str_split(strtoupper(rtrim($encoded, '='))) as $char) {
			$index = strpos(self::BASE32_ALPHABET, $char);
			if($index === false) continue;
			$binary .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
		}
		$data = '';
		foreach(str_split($binary, 8) as $chunk) {
			if(strlen($chunk) == 8) $data .= chr(bindec($chunk));
		}
		return $data;
	}

}
