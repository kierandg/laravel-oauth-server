<?php

namespace Gponster\OAuth\Provider\Storage;

use Gponster\OAuth\Provider\Consumer;
use Carbon\Carbon;
use Gponster\OAuth\Provider\Utils;
use Gponster\OAuth\Provider\RequestToken;
use Gponster\OAuth\Provider\AccessToken;
use Gponster\OAuth\Provider\OAuthException;
use Gponster\OAuth\Provider\Nonce;

/**
 * Class Pdo
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Pdo implements ConsumerInterface, RequestTokenInterface, AccessTokenInterface, NonceInterface {

	/**
	 * Maximum request token TTL
	 */
	protected $maximumRequestTokenTtl = 3600;

	/**
	 * Timestamp expired time
	 */
	protected $timestampThreshold = 36000;

	/**
	 * Maximum access token TTL if not specific expired time for access token
	 * 15 days = 15 * 24 * 60 * 60 in seconds
	 */
	protected $maximumAccessTokenTtl = 1296000;

	/**
	 * Get consumer details
	 *
	 * @param string $consumerKey
	 * @param string $type
	 * @param string $enabled
	 * @param array $options
	 *        	Search criteria [ 'name', 'publisher', 'type', 'category',
	 *        	'website_url', 'email', 'description', 'callback_url' ]
	 * @return array [ 'consumer_key', 'name', 'publisher', 'type', 'category',
	 *         'website_url', 'email', 'description', 'callback_url', 'enabled' ]
	 */
	public function getConsumer($consumerKey, $enabled = 1, $options = []) {
		$enabled = $enabled ? $enabled : 1;
		$options = array_merge([], $options);

		$builder = Consumer::where('consumer_key', $consumerKey)->where('enabled', $enabled);

		foreach([
			'name', 'publisher', 'type', 'category', 'website_url', 'email', 'description', 'callback_url'
		] as $field) {
			if(isset($options[$field])) {
				$builder->where($field, $options[$field]);
			}
		}

		$consumer = $builder->first();
		if($consumer) {
			$attributes = $consumer->getAttributes();
			if(isset($attributes['consumer_secret'])) {
				unset($attributes['consumer_secret']);
			}

			return $attributes;
		}

		return null;
	}

	/**
	 * Get consumer credentials (consumer_secret)
	 *
	 * @param string $consumerKey
	 * @param string $type
	 * @param string $enabled
	 * @param array $options
	 *        	Search criteria [ 'name', 'publisher', 'type', 'category',
	 *        	'website_url', 'email', 'description', 'callback_url' ]
	 * @return array [ 'consumer_key', 'consumer_secret' ]
	 */
	public function getConsumerCredentials($consumerKey, $enabled = 1, $options = []) {
		$enabled = $enabled ? $enabled : 1;
		$options = array_merge([], $options);

		$builder = Consumer::where('consumer_key', $consumerKey)->where('enabled', $enabled);

		foreach([
			'name', 'publisher', 'type', 'category', 'website_url', 'email', 'description', 'callback_url'
		] as $field) {
			if(isset($options[$field])) {
				$builder->where($field, $options[$field]);
			}
		}

		$consumer = $builder->first();
		if($consumer) {
			return $consumer->getAttributes();
		}

		return null;
	}

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
	 * @return array The token information [ 'token', 'token_secret',
	 *         'consumer_key', 'username', 'authorized', 'callback_url', 'expires_at' ]
	 */
	public function getRequestToken($token, $consumerKey = null, $options = []) {
		$options = array_merge([], $options);

		$builder = RequestToken::where('token', $token);
		if(! empty($consumerKey)) {
			$builder->where('consumer_key', $consumerKey);
		}

		if(! isset($options['expires_at'])) {
			$options['expires_at'] = new Carbon();
		}

		$builder->where('expires_at', '>=', $options['expires_at']);

		if(isset($options['authorized'])) {
			$builder->where('authorized', $options['authorized']);
		}

		$requestToken = $builder->first();
		if($requestToken) {
			return $requestToken->getAttributes();
		}

		return null;
	}

	/**
	 * Add request token
	 *
	 * @param string $consumerKey
	 *        	The consumer key
	 * @param array $options
	 *        	Optional ['token_ttl', 'callback_url', 'token_secret']
	 * @return array The token information [ 'token', 'token_secret',
	 *         'consumer_key', 'callback_url', 'expires_at' ]
	 */
	public function createRequestToken($consumerKey, $options) {
		$ttl = $this->maximumRequestTokenTtl;
		if(isset($options['token_ttl']) && is_numeric($options['token_ttl'])) {
			$ttl = intval($options['token_ttl']);
		}

		if(! isset($options['callback_url'])) {
			// 1.0a Compatibility : store callback url associated with request token
			$options['callback_url'] = 'oob';
		}

		$token = Utils::generateKey(true);
		$tokenSecret = ! isset($options['token_secret']) ? Utils::generateKey() : $options['token_secret'];

		$data = [
			'consumer_key' => $consumerKey, 'token' => $token, 'token_secret' => $tokenSecret,
			'callback_url' => $options['callback_url'], 'expires_at' => (new Carbon())->addSeconds($ttl)
		];

		$requestToken = new RequestToken();
		$requestToken->create($data);

		$data['expires_at'] = $data['expires_at']->timestamp;

		return $data;
	}

	/**
	 * Delete request token
	 *
	 * @param string $token
	 */
	public function deleteRequestToken($token) {
		return RequestToken::where('token', $token)->delete();
	}

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
	public function authorizeRequestToken($token, $username, $options = []) {
		// 1.0a Compatibility : create a token verifier
		$verifier = Utils::generateKey();
		$refererUrl = isset($options['referer_url']) ? $options['referer_url'] : null;

		$data = [
			'authorized' => 1, 'username' => $username, 'referer_url' => $refererUrl, 'verifier' => $verifier
		];

		$updated = RequestToken::where('token', $token)->update($data);
		if(! $updated) {
			return false;
		}

		return $data;
	}

	/**
	 * Find stored credentials for the consumer key and token.
	 * Used by an OAuth server when verifying an OAuth request.
	 *
	 * @param string $token
	 *        	The request token
	 * @param string $consumerKey
	 *        	Consumer/API key
	 * @param array $options
	 *        	Search criteria [ 'expires_at' ]
	 * @return array The token information [ 'token', 'token_secret',
	 *         'consumer_key', 'username', 'expires_at',
	 *         'callback_url', 'referer_url', 'info' ]
	 */
	public function getAccessToken($token, $consumerKey = null, $options = []) {
		$options = array_merge([], $options);

		$builder = AccessToken::where('token', $token);
		if(! empty($consumerKey)) {
			$builder->where('consumer_key', $consumerKey);
		}

		if(! isset($options['expires_at'])) {
			$options['expires_at'] = new Carbon();
		}

		$builder->where('expires_at', '>=', $options['expires_at']);

		$accessToken = $builder->first();
		if($accessToken) {
			return $accessToken->getAttributes();
		}

		return null;
	}

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
	public function createAccessToken($consumerKey, $username, $options = []) {
		$token = Utils::generateKey(true);
		$tokenSecret = Utils::generateKey();

		// Maximum time to live for this token?
		$ttl = $this->maximumAccessTokenTtl;
		if(isset($options['token_ttl']) && is_numeric($options['token_ttl'])) {
			$ttl = intval($options['token_ttl']);
		}

		$callbackUrl = isset($options['callback_url']) ? $options['callback_url'] : 'oob';
		$referrerUrl = isset($options['referer_url']) ? $options['referer_url'] : 'client_auth';

		$data = [
			'consumer_key' => $consumerKey, 'username' => $username, 'token' => $token, 'token_secret' => $tokenSecret,
			'referer_url' => $referrerUrl, 'callback_url' => $callbackUrl,
			'expires_at' => (new Carbon())->addSeconds($ttl)
		];

		$accessToken = new AccessToken($data);
		$saved = $accessToken->save();
		if(! $saved) {
			return false;
		}

		$data['expires_at'] = $data['expires_at']->timestamp;

		return $data;
	}

	/**
	 * Delete access token
	 *
	 * @param string $token
	 * @param string $username
	 */
	public function deleteAccessToken($token, $username = null) {
		$builder = AccessToken::where('token', $token);
		if(! empty($username)) {
			$builder->where('username', $username);
		}

		return $builder->delete();
	}

	/**
	 * Set the ttl of a consumer access token.
	 * This is done when the server receives a valid request with
	 * a xoauth_token_ttl parameter in it.
	 *
	 * @param string $token
	 * @param int $ttl
	 */
	public function setAccessTokenTtl($token, $ttl) {
		if($ttl <= 0) {
			// Immediate delete when the token is past its ttl
			$this->deleteAccessToken($token);
		} else {
			return AccessToken::where('token', $token)->update(
				[
					'expires_at' => (new Carbon())->addSeconds($ttl)
				]);
		}
	}

	/**
	 * Exchange an authorized request token for new access token.
	 *
	 * @param
	 *        	string token The authorized request token
	 * @param
	 *        	array options Options for the token, token_ttl
	 *        	@exception Exception when token could not be exchanged
	 * @return array (token, token_ttl)
	 */
	public function exchangeRequestForAccessToken($token, $options = array()) {
		$db = Zend_Db_Table::getDefaultAdapter(); // data adapter

		$accessToken = Utils::generateKey(true);
		$accessTokenSecret = Utils::generateKey();

		// Maximum time to live for this token
		if(isset($options['token_ttl']) && is_numeric($options['token_ttl'])) {
			$ttlExp = new Zend_Db_Expr('DATE_ADD(NOW(), INTERVAL ' . intval($options['token_ttl']) . ' SECOND)');
		} else {
			$ttlExp = new Zend_Db_Expr($db->quoteInto('DATE_ADD(?, INTERVAL 0 SECOND)', $this->maximumAccessTokenTtl));
		}

		// Update token data
		$data = array(
			'token' => $accessToken, 'token_secret' => $accessTokenSecret, 'token_type' => 'access',
			'token_ttl' => $ttlExp
		);

		$where = array();
		$where[] = $db->quoteInto('token = ?', $token);
		$where[] = $db->quoteInto('token_type = ?', 'request');
		$where[] = $db->quoteInto('authorized = ?', 1);
		$where[] = $db->quoteInto('token_ttl >= ?', new Zend_Db_Expr('NOW()'));

		if(isset($options['verifier'])) {
			$where[] = $db->quoteInto('verifier = ?', $options['verifier']);
		}

		// Exchange token
		$effected = $db->update('tokens', $data, $where);
		if($effected != 1) {
			throw new Exception(
				'Can\'t exchange request token "' . $token . '" for access token. No such token or not authorized');
		}

		// New access token
		$result = array(
			'token' => $accessToken, 'token_secret' => $accessTokenSecret
		);

		// Get TTL of new token
		$select = new Zend_Db_Select($db);
		$ttlExp = new Zend_Db_Expr(
			$db->quoteInto('IF(token_ttl >= ?, NULL, UNIX_TIMESTAMP(token_ttl) - UNIX_TIMESTAMP(NOW()))',
				$this->maximumAccessTokenTtl));
		$select->from('tokens', array(
			'token_ttl' => $ttlExp, 'user_id'
		))
			->where('token = ?', $accessToken);

		// Dump SQL query for test purpose
		// var_dump($select->toString());

		// Get TTL of access token
		$row = $db->fetchRow($select);
		if(is_numeric($row['token_ttl'])) {
			$result['token_ttl'] = intval($row['token_ttl']);
		} else {
			$result['token_ttl'] = $this->maximumAccessTokenTtl;
		}

		$result['user_id'] = $row['user_id'];

		// return result
		return $result;
	}

	/**
	 * Check recentish timestamp
	 *
	 * @param int $timestamp
	 *        	The timestamp to be checked
	 * @return boolean
	 */
	public function validateTimestamp($timestamp) {
		$now = new Carbon();

		return $now->diffInSeconds(Carbon::createFromTimestamp($timestamp)) < $this->timestampThreshold;
	}

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
	public function validateNonce($consumerKey, $token, $timestamp, $nonce) {
		$data = [
			'consumer_key' => $consumerKey, 'token' => $token, 'timestamp' => Carbon::createFromTimestamp($timestamp),
			'nonce' => $nonce
		];

		$model = new Nonce($data);
		try {
			$saved = $model->save();
		} catch(\Exception $e) {
			$saved = false;
		}

		if($saved) {
			Nonce::where('consumer_key', $consumerKey)->where('token', $token)
				->where('timestamp', '<', $data['timestamp']->subSeconds($this->timestampThreshold))
				->delete();

			return true;
		}

		return false;
	}
}