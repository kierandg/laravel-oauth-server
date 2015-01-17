<?php

namespace Gponster\OAuth\Provider;

/**
 * Class Utils
 * Helper class to generate key
 */
class Utils {

	/**
	 * Generate key
	 *
	 * @param boolean $unique
	 *        	This is a description
	 * @return string This is the return value description
	 */
	public static function generateKey($unique = false) {
		if(function_exists('mcrypt_create_iv')) {
			return self::createKey($unique ? 24 : 12);
		}

		$key = md5(uniqid(rand(), true));
		if($unique) {
			list($usec, $sec) = explode(' ', microtime());
			$key .= dechex($usec) . dechex($sec);
		}

		return $key;
	}

	public static function createKey($length) {
		$key = '';
		$replace = array(
			'/', '+', '='
		);

		while(strlen($key) < $length) {
			$key .= str_replace($replace, NULL, base64_encode(mcrypt_create_iv($length, MCRYPT_RAND)));
		}

		return substr($key, 0, $length);
	}

	/**
	 * Check to see if a string is valid utf8
	 *
	 * @param string $s
	 * @return boolean
	 */
	public static function isUtf8($s) {
		return preg_match(
			'%(?:
               [\xC2-\xDF][\x80-\xBF]              # non-overlong 2-byte
               |\xE0[\xA0-\xBF][\x80-\xBF]         # excluding overlongs
               |[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}  # straight 3-byte
               |\xED[\x80-\x9F][\x80-\xBF]         # excluding surrogates
               |\xF0[\x90-\xBF][\x80-\xBF]{2}      # planes 1-3
               |[\xF1-\xF3][\x80-\xBF]{3}          # planes 4-15
               |\xF4[\x80-\x8F][\x80-\xBF]{2}      # plane 16
               )+%xs', $s);
	}
}