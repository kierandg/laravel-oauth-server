<?php

namespace Gponster\OAuth\Provider\Storage;

/**
 * Interface for OAuth request token store
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
interface RequestTokenInterface {

	/**
	 * Find stored credentials for the consumer key and token.
	 * Used by an OAuth server when verifying an OAuth request.
	 *
	 * @param string $token
	 *        	The request token
	 * @param string $consumerKey
	 *        	Consumer/API key
	 * @param array $options
	 *        	Search criteria [ 'authorized', 'expires_at' ]
	 *        	Default get only tokens not expired
	 * @return array The token information [ 'token', 'token_secret',
	 *         'consumer_key', 'username', 'authorized', 'callback_url', 'expires_at' ]
	 */
	function getRequestToken($token, $consumerKey = null, $options = []);

	/**
	 * Add request token
	 *
	 * @param string $consumerKey
	 *        	The consumer key
	 * @param array $options
	 *        	Optional ['token_ttl', 'callback_url', 'token_secret']
	 * @return array The information of token has been created
	 *         ['token', 'token_secret', 'callback_url', 'expires_at']
	 */
	function createRequestToken($consumerKey, $options);

	/**
	 * Delete request token
	 *
	 * @param string $token
	 */
	function deleteRequestToken($token);

	/**
	 * Upgrade a request token to be an authorized request token.
	 *
	 * @param string $token
	 *        	The unauthorized request token
	 * @param mixed $username
	 *        	User authorizing the token
	 * @param array $options
	 *        	Referer host used to set the referrer host for
	 *        	this token, for user feedback
	 * @return array [ 'username' , 'referer_url' , 'verifier' ]
	 */
	function authorizeRequestToken($token, $username, $options = []);
}