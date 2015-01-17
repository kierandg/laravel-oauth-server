<?php

namespace Gponster\OAuth\Provider\Storage;

/**
 * Interface for OAuth nonce store
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
interface NonceInterface {

	/**
	 * Check recentish timestamp
	 *
	 * @param int $timestamp
	 *        	The timestamp to be checked
	 * @return boolean
	 */
	function validateTimestamp($timestamp);

	/**
	 * Check an nonce/timestamp combination.
	 * Clears any nonce combinations that are older than the one received.
	 *
	 * @param string $consumerKey
	 *        	The consumer key
	 * @param string $token
	 *        	The token
	 * @param int $timestamp
	 *        	Timestamp
	 * @param string $nonce
	 *        	Nonce
	 * @return boolean
	 */
	function validateNonce($consumerKey, $token, $timestamp, $nonce);
}