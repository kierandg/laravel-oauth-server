<?php

namespace Gponster\OAuth\Provider\Signature;

/**
 * Interface for OAuth signature methods
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
interface VerifierInterface {

	/**
	 * Return the name of this signature
	 *
	 * @return string
	 */
	function name();

	/**
	 * Create the signature for the given request
	 *
	 * @param string $base
	 *        	This is a description
	 * @param string $consumerSecret
	 *        	This is a description
	 * @param string $tokenSecret
	 *        	This is a description
	 * @return string This is the return value description
	 */
	function make($base, $consumerSecret, $tokenSecret);

	/**
	 * Check if the request signature corresponds to the one calculated for the request.
	 *
	 * @param
	 *        	string base data to be signed, usually the base string, can be a request body
	 * @param
	 *        	string consumerSecret
	 * @param
	 *        	string tokenSecret
	 * @param
	 *        	string signature from the request, still urlencoded
	 * @return string
	 */
	function verify($base, $consumerSecret, $tokenSecret, $signature);
}