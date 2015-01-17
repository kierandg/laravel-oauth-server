<?php

namespace Gponster\OAuth\Provider\Signature;

use Gponster\OAuth\Provider\Rfc3986;

/**
 * Class Md5Verifier
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 * Verify signature using MD5
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Md5Verifier implements VerifierInterface {

	/**
	 * This is method name
	 *
	 * @return string This is the return value description
	 */
	public function name() {
		return 'MD5';
	}

	/**
	 * Calculate the signature using MD5
	 * Binary md5 digest, as distinct from PHP's built-in hexdigest.
	 * This function is copyright Andy Smith, 2007.
	 *
	 * @param string $base
	 * @param string $consumerSecret
	 * @param string $tokenSecret
	 * @return string The encoded signature
	 */
	public function make($base, $consumerSecret, $tokenSecret) {
		$s .= '&' . Rfc3986::urlEncode($consumerSecret) . '&' . Rfc3986::urlEncode($tokenSecret);

		$md5 = md5($base);
		$bin = '';

		for($i = 0; $i < strlen($md5); $i += 2) {
			$bin .= chr(hexdec($md5{$i + 1}) + hexdec($md5{$i}) * 16);
		}

		// return encoded signature
		return Rfc3986::urlEncode(base64_encode($bin));
	}

	/**
	 * Check if the request signature corresponds to the one calculated for the request.
	 *
	 * @param string $base
	 *        	This is a description
	 * @param string $consumerSecret
	 * @param string $tokenSecret
	 * @param string $signature
	 *        	from the request, still URL encoded
	 * @return boolean True if signature is valid
	 */
	public function verify($signatureBase, $consumerSecret, $tokenSecret, $signature) {
		$a = Rfc3986::urlDecode($signature);
		$b = Rfc3986::urlDecode($this->make($signatureBase, $consumerSecret, $tokenSecret));

		// we have to compare the decoded values
		// $valA = base64_decode($a);
		// $valB = base64_decode($b);

		// Crude binary comparison
		// return (rawurlencode($a) === rawurlencode($b));
		return (rawurlencode($a) === rawurlencode($b));
	}
}