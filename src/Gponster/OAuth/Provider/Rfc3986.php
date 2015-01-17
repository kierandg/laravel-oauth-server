<?php

namespace Gponster\OAuth\Provider;

/**
 * Class Rfc3986
 * Helper class to encode, decode URL according to RFC 3986
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Rfc3986 {

	/**
	 * Encode a string according to the RFC 3986
	 *
	 * @param string $input
	 *        	This is a description
	 * @return string This is the return value description
	 */
	public static function urlEncode($input) {
		if($input === false) {
			return $input;
		} elseif(is_scalar($input)) {
			return str_replace('%7E', '~', rawurlencode($input));
		} else {
			return '';
		}
	}

	/**
	 * Decode a string according to RFC 3986.
	 * Also correctly decodes RFC 1738 URLs.
	 *
	 * @param string $input
	 * @return string
	 */
	public static function urlDecode($input) {
		if($input === false) {
			return $input;
		} elseif(is_scalar($input)) {
			return rawurldecode($input);
		} else {
			return '';
		}
	}

	/**
	 * Make sure that a value is encoded using RFC3986.
	 * We use a basic urlDecode() function so that any use of '+' as the
	 * encoding of the space character is correctly handled.
	 *
	 * @param
	 *        	string s
	 * @return string
	 */
	public static function urlTranscode($input) {
		if($input === false) {
			return $input;
		} elseif(is_scalar($input)) {
			return static::urlEncode(static::urlDecode($input));
		} else {
			return '';
		}
	}
}