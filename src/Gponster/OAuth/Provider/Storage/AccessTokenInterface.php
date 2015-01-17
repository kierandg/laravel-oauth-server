<?php

namespace Gponster\OAuth\Provider\Storage;

/**
 * Interface for OAuth access token store
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
interface AccessTokenInterface {

	/**
	 * Find stored credentials for the consumer key and token.
	 * Used by an OAuth server when verifying an OAuth request.
	 *
	 * @param string $token
	 *        	The access token
	 * @param string $consumerKey
	 *        	Consumer/API key
	 * @param array $options
	 *        	Search criteria [ 'expires_at' ]
	 *        	Default get only tokens not expired
	 * @return array The token information [ 'token', 'token_secret',
	 *         'consumer_key', 'username', 'expires_at',
	 *         'callback_url', 'referer_url' ]
	 */
	function getAccessToken($token, $consumerKey = null, $options = []);

	/**
	 * Create an access token to exchange an authorized request token or
	 * for used after xAuth login
	 *
	 * @param string $consumerKey
	 *        	The consumer key
	 * @param string $username
	 *        	The authorizing user
	 * @param array $options
	 *        	Options for the token, ['token_ttl', 'callback_url', 'referer_url']
	 *        	Default callback URL is 'oob'
	 *        	Default referrer URL is 'client_auth'
	 * @return array
	 */
	function createAccessToken($consumerKey, $username, $options = []);

	/**
	 * Delete access token
	 *
	 * @param string $token
	 * @param string $username
	 */
	function deleteAccessToken($token, $username = null);

	/**
	 * Set the ttl of a consumer access token.
	 * This is done when the server receives a valid request with
	 * a xoauth_token_ttl parameter in it.
	 *
	 * @param string $token
	 * @param int $ttl
	 */
	function setAccessTokenTtl($token, $ttl);
}