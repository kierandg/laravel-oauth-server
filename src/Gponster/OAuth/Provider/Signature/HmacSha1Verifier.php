<?php

namespace Gponster\OAuth\Provider\Signature;

use Gponster\OAuth\Provider\Rfc3986;

/**
 * Class HmacSha1Verifier
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 * Verify signature using HMAC-SHA1
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class HmacSha1Verifier implements VerifierInterface {

	/**
	 * This is method name
	 *
	 * @return string This is the return value description
	 */
	public function name() {
		return 'HMAC-SHA1';
	}

	/**
	 * Calculate the signature using HMAC-SHA1
	 * This function is copyright Andy Smith, 2007.
	 *
	 * @param string $signatureBase
	 * @param string $consumerSecret
	 * @param string $tokenSecret
	 * @return string The encoded signature
	 */
	public function make($signatureBase, $consumerSecret, $tokenSecret) {
		$key = Rfc3986::urlEncode($consumerSecret) . '&' . Rfc3986::urlEncode($tokenSecret);

		if(function_exists('hash_hmac')) {
			$signature = base64_encode(hash_hmac('sha1', $signatureBase, $key, true));
		} else {
			$blocksize = 64;
			$hashfunc = 'sha1';

			if(strlen($key) > $blocksize) {
				$key = pack('H*', $hashfunc($key));
			}

			$key = str_pad($key, $blocksize, chr(0x00));
			$ipad = str_repeat(chr(0x36), $blocksize);
			$opad = str_repeat(chr(0x5c), $blocksize);

			$hmac = pack('H*', $hashfunc(($key ^ $opad) . pack('H*', $hashfunc(($key ^ $ipad) . $signatureBase))));
			$signature = base64_encode($hmac);
		}

		// Return encoded signature
		return Rfc3986::urlEncode($signature);
	}

	/**
	 * Check if the request signature corresponds to the one calculated for the request.
	 *
	 * @param string $signatureBase
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

		// We have to compare the decoded values
		// $valA = base64_decode($a);
		// $valB = base64_decode($b);

		// Crude binary comparison
		// return (rawurlencode($a) === rawurlencode($b));
		return (rawurlencode($a) === rawurlencode($b));
	}
}