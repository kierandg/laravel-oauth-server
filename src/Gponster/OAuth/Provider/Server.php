<?php

namespace Gponster\OAuth\Provider;

use Carbon\Carbon;
use Session;
use Config;
use Auth;
use Illuminate\Support\Facades\Response;

/**
 * This is class OAuth Server
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Server extends RequestVerifier {

	/**
	 * Whether bypass nonce or not
	 *
	 * @var boolean
	 *
	 */
	protected $forceBypassNonce = true;

	/**
	 *
	 * @var string Prefix to use for session variables
	 */
	protected $sessionPrefix = 'gponster/oauth-server_';

	/**
	 *
	 * @var string State token for validation
	 */
	protected $state;

	/**
	 *
	 * @var boolean Toggle for PHP session status check
	 */
	protected $checkForSessionStatus = true;

	/**
	 * This is method requestToken
	 *
	 * @return void
	 *
	 */
	public function xAuth() {
		// Auth config
		$auth = \Config::get('gponster/laravel-oauth-server::auth');

		// ----------------------------------------------------------------------------
		// IF PASSWORD STORE IN DATABASE AS DIGEST FORMAT, CLIENT APPLICATION
		// MUST GENERATE PASSWORD DIGEST BEFORE BUILD SIGNATURE WITH SAME ALGORITHM
		// ----------------------------------------------------------------------------
		$credentials = [
			$auth['username'] => $this->getParam(self::X_AUTH_USERNAME, true),
			$auth['password'] => $this->getParam(self::X_AUTH_PASSWORD, true),
			$auth['status'] => 1
		];

		if(empty($credentials[$auth['username']])) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
				[
					'name' => self::X_AUTH_USERNAME
				]);
		}

		if(empty($credentials[$auth['password']])) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
				[
					'name' => self::X_AUTH_PASSWORD
				]);
		}

		$xAuthMode = $this->getParam(self::X_AUTH_MODE, true);
		$loggedIn = false;
		$user = null;

		if($xAuthMode == 'client_auth') {
			$loggedIn = \Auth::validate($credentials);
			if($loggedIn) {
				$user = Auth::getLastAttempted();
			}
		} else if(! empty($auth['social_login'])) {
			// Try social-login
			$provider = \App::make(
				'Gponster\\OAuth\\Provider\\SocialLoginProviderInterface');
			$user = $provider->login($xAuthMode, $credentials[$auth['username']],
				$credentials[$auth['password']], null);
		}

		if(! $user) {
			throw OAuthException::make(OAuthException::INVALID_CREDENTIALS,
				[
					'username' => $credentials[$auth['username']]
				]);
		}

		// Verify request if signature not valid
		$result = $this->verify(false, $this->forceBypassNonce);

		$options = [];
		$options['callback_url'] = isset($result['callback_url']) ? $result['callback_url'] : null;
		$options['referer_url'] = isset($result['referer_url']) ? $result['referer_url'] : null;

		// Should have a transaction here?
		$accessToken = $this->storages['access_token']->createAccessToken(
			$result['consumer_key'], $credentials[$auth['username']], $options);
		if(! $accessToken) {
			throw new \RuntimeException(
				'Cannot create new access token for ' . json_encode($result));
		}

		$data = [];
		$data[self::OAUTH_TOKEN] = Rfc3986::urlEncode($accessToken['token']);
		$data[self::OAUTH_TOKEN_SECRET] = Rfc3986::urlEncode($accessToken['token_secret']);
		$data[self::OAUTH_CALLBACK_CONFIRMED] = 1;

		$data['user'] = [
			$auth['username'] => $user->{$auth['username']}
		];

		// Get extra information
		if(! empty($auth['profile'])) {
			$provider = \App::make(
				'Gponster\\OAuth\\Provider\\UserProfileProviderInterface');
			$profile = $provider->profile($user->{$auth['username']}, [
				'login' => true
			]);

			if(is_array($profile)) {
				$data['user'] = array_merge($data['user'], $profile);
			}
		}

		if(! empty($accessToken['expires_at']) && is_numeric($accessToken['expires_at'])) {
			$expiresAt = Carbon::createFromTimestamp(intval($accessToken['expires_at']));

			$data[self::XOAUTH_TOKEN_TTL] = $expiresAt->diffInSeconds();
			$data['expires_at'] = $expiresAt->timestamp;
		}

		return $data;
	}

	/**
	 * This is method requestToken
	 *
	 * @return mixed This is the return value description
	 */
	public function requestToken() {
		$this->verify(false);

		// Optional TTL
		$options = array();
		$ttl = $this->getParam(self::XOAUTH_TOKEN_TTL, false);
		if($ttl) {
			$options['token_ttl'] = $ttl;
		}

		// 1.0a Compatibility : associate callback url to the request token
		$callbackUrl = $this->getParam(self::OAUTH_CALLBACK, true);
		if($callbackUrl) {
			$options['callback_url'] = $callbackUrl;
		}

		// Create a request token
		$consumerKey = $this->getParam(self::OAUTH_CONSUMER_KEY, true);

		if(! isset($this->storages['request_token'])) {
			throw new \RuntimeException(
				'You must supply a storage object implementing ' .
					 $this->storageMap['request_token']);
		}

		// MUST be included with an empty value to indicate this is a two-legged request.
		$is2Legged = $this->getParam(self::OAUTH_CALLBACK) === '';
		if($is2Legged) {
			// Create pre-authorized request token
		}

		$requestToken = $this->storages['request_token']->createRequestToken($consumerKey,
			$options);

		$data = [];
		$data[self::OAUTH_TOKEN] = Rfc3986::urlEncode($requestToken['token']);
		$data[self::OAUTH_TOKEN_SECRET] = Rfc3986::urlEncode(
			$requestToken['token_secret']);
		$data[self::OAUTH_CALLBACK_CONFIRMED] = '1';

		if(! empty($requestToken['expires_at']) && is_numeric($requestToken['expires_at'])) {
			$expiresAt = Carbon::createFromTimestamp(intval($requestToken['expires_at']));

			$data[self::XOAUTH_TOKEN_TTL] = $expiresAt->diffInSeconds();
		}

		return $data;
	}

	public function getRequestToken($token) {
		if(! isset($this->storages['request_token'])) {
			throw new \RuntimeException(
				'You must supply a storage object implementing ' .
					 $this->storageMap['request_token']);
		}

		$requestToken = $this->storages['request_token']->getRequestToken($token);
		if(! $requestToken) {
			throw OAuthException::make(OAuthException::TOKEN_REJECTED,
				[
					'value' => $token
				]);
		}

		return $requestToken;
	}

	/**
	 * Verify the authorization information
	 *
	 * @return array The state of authorization flow
	 */
	public function authorizeVerify() {
		// Authorization implementation goes here
		$token = $this->getParam(self::OAUTH_TOKEN, true);

		if(! isset($this->storages['request_token'])) {
			throw new \RuntimeException(
				'You must supply a storage object implementing ' .
					 $this->storageMap['request_token']);
		}

		$requestToken = $this->storages['request_token']->getRequestToken($token);
		if(! $requestToken) {
			throw OAuthException::make(OAuthException::TOKEN_REJECTED,
				[
					'value' => $token
				]);
		}

		$state = $this->loadState();

		// We need to remember the callback
		if(empty($state['token']) || strcmp($state['token'], $requestToken['token'])) {
			$state['token'] = $requestToken['token'];
			$state['consumer_key'] = $requestToken['consumer_key'];

			$cb = $this->getParam(self::OAUTH_CALLBACK, true);
			if($cb) {
				$state['callback_url'] = $cb;
			} else {
				$state['callback_url'] = $requestToken['callback_url'];
			}

			$this->storeState($state);
		}

		return $state;
	}

	/**
	 * Finish the authozization flow
	 *
	 * @param boolean $authorized
	 *        	Whether user authorized or not
	 * @param string $username
	 *        	The authorizing username
	 * @return string The verifier/PIN code
	 */
	public function authorizeFinish($authorized, $username) {
		$token = $this->getParam(self::OAUTH_TOKEN, true);
		$result = null;

		// Initialize session
		$state = $this->loadState();

		// Check session has verified
		if(isset($state['token']) && $state['token'] == $token) {
			// Fetch the referrer host from the oauth callback parameter
			$refererUrl = '';
			$callbackUrl = false;
			if(! empty($state['callback_url']) && $state['callback_url'] != 'oob') { // OUT OF BAND
				$callbackUrl = $state['callback_url'];
				$components = parse_url($callbackUrl);

				if(isset($components['host'])) {
					$refererUrl = $components['host'];
				}
			}

			if(! isset($this->storages['request_token'])) {
				throw new \RuntimeException(
					'You must supply a storage object implementing ' .
						 $this->storageMap['request_token']);
			}

			if($authorized) {
				// 1.0a Compatibility : create a verifier code
				$result = $this->storages['request_token']->authorizeRequestToken($token,
					$username, $refererUrl);
			} else {
				$this->storages['request_token']->deleteRequestToken($token);
			}

			if(! empty($callbackUrl)) {
				$params = [
					'oauth_token' => rawurlencode($token)
				];

				// 1.0a Compatibility : if verifier code has been generated, add it to the URL
				if($result) {
					$params['oauth_verifier'] = $result['verifier'];
				}

				$this->redirect($callbackUrl, $params);
			}
		}

		return $result;
	}

	/**
	 * Exchange a request token for an access token
	 *
	 * @param boolean $bypassNonce
	 *        	Whether bypass nonce check or not
	 * @return array The new access token
	 */
	public function accessToken($bypassNonce = false) {
		$result = $this->verify('request', $bypassNonce);

		// Optional TTL
		$options = array();
		$ttl = $this->getParam(self::XOAUTH_TOKEN_TTL, true);
		if($ttl) {
			$options['token_ttl'] = $ttl;
		}

		$verifier = $this->getParam(self::OAUTH_VERIFIER, true);
		if($verifier) {
			$options['verifier'] = $verifier;
		}

		$options['callback_url'] = isset($result['callback_url']) ? $result['callback_url'] : null;
		$options['referer_url'] = isset($result['referer_url']) ? $result['referer_url'] : null;

		// Exchange request token for an access token
		if(! isset($this->storages['request_token'])) {
			throw new \RuntimeException(
				'You must supply a storage object implementing ' .
					 $this->storageMap['request_token']);
		}

		if(! isset($this->storages['access_token'])) {
			throw new \RuntimeException(
				'You must supply a storage object implementing ' .
					 $this->storageMap['access_token']);
		}

		// Should have a transaction here?
		$accessToken = $this->storages['access_token']->createAccessToken(
			$result['consumer_key'], $result['username'], $options);
		if(! $accessToken) {
			throw new \RuntimeException(
				'Cannot create new access token for ' . json_encode($result));
		}

		// Delete request token here
		$this->storages['access_token']->deleteRequestToken($result['token']);

		$data = [];
		$data[self::OAUTH_TOKEN] = Rfc3986::urlEncode($accessToken['token']);
		$data[self::OAUTH_TOKEN_SECRET] = Rfc3986::urlEncode($accessToken['token_secret']);
		$data[self::OAUTH_CALLBACK_CONFIRMED] = 1;

		if(! empty($accessToken['expires_at']) && is_numeric($accessToken['expires_at'])) {
			$expiresAt = Carbon::createFromTimestamp(intval($accessToken['expires_at']));

			$data[self::XOAUTH_TOKEN_TTL] = $expiresAt->diffInSeconds();
		}

		return $data;
	}

	protected function storeState($state) {
		Session::put($this->sessionPrefix . 'state', $state);
	}

	protected function loadState() {
		$this->state = Session::get($this->sessionPrefix . 'state');
		return $this->state;
	}

	/**
	 * Disables the session_status() check when using $_SESSION
	 */
	public function disableSessionStatusCheck() {
		$this->checkForSessionStatus = false;
	}

	/**
	 * This is method fault
	 *
	 * @param mixed $exception
	 *        	This is a description
	 * @param mixed $format
	 *        	This is a description
	 * @param mixed $httpCode
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function fault($exception = null, $format = 'json', $httpCode = null) {
		$error = false;
		if($exception instanceof OAuthException) {
			$error = [
				'code' => $exception->getCode(), 'message' => $exception->getMessage()
			];
		} else if($exception instanceof \Exception) {
			$error = [
				'code' => $exception->getCode(), 'message' => $exception->getMessage()
			];
		} else {
			$error = [
				'code' => BAD_URL, 'message' => static::getError(BAD_URL)
			];
		}

		switch($format) {
			case 'xml':
				$errorXml = Response::error($error['code'], $error['message']);
				return $errorXml;

			case 'plain-text':
				return Response::plain($error);

			case 'json':
				$errorXml = Response::error($error['code'], $error['message'], false);
				return Zend_Json::fromXml($errorXml);
		}
	}
}