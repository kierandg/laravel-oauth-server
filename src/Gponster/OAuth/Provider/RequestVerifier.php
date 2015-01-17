<?php

namespace Gponster\OAuth\Provider;

use Gponster\OAuth\Provider\Storage\ConsumerInterface;

/**
 * Class RequestVerifier
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 * Using data store to verify the request
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class RequestVerifier extends Request {

	/**
	 * Storage interfaces name map
	 *
	 * @var array
	 */
	protected $storageMap = [
		'access_token' => 'Gponster\OAuth\Provider\Storage\AccessTokenInterface',
		'consumer' => 'Gponster\OAuth\Provider\Storage\ConsumerInterface',
		'nonce' => 'Gponster\OAuth\Provider\Storage\NonceInterface',
		'request_token' => 'Gponster\OAuth\Provider\Storage\RequestTokenInterface'
	];

	/**
	 * The data storages
	 *
	 * @var array
	 *
	 */
	protected $storages;

	/**
	 * Construct the request to be verified
	 *
	 * @param string $uri
	 * @param string $method
	 * @param
	 *        	array params The request parameters
	 */
	public function __construct($storages = [], array $config = [], $uri = null, $method = null, $params = null) {
		if($params) {
			$encodedParams = array();
			foreach($params as $k => $v) {
				if(preg_match('/^oauth_/', $k)) {
					continue;
				}

				$encodedParams[rawurlencode($k)] = rawurlencode($v);
			}

			$this->params = array_merge($this->params, $encodedParams);
		}

		parent::__construct($uri, $method);

		// Setup storages
		$storages = is_array($storages) ? $storages : [
			$storages
		];

		$this->storages = [];
		foreach($storages as $key => $service) {
			$this->addStorage($service, $key);
		}
	}

	/**
	 * Set a storage object for the server
	 *
	 * @param $storage An
	 *        	object implementing one of the Storage interfaces
	 * @param $key If
	 *        	null, the storage is set to the key of each storage interface it implements
	 * @see storageMap
	 */
	public function addStorage($storage, $key = null) {
		// if explicitly set to a valid key, do not "magically" set below
		if(isset($this->storageMap[$key])) {
			if(! is_null($storage) && ! $storage instanceof $this->storageMap[$key]) {
				throw new \InvalidArgumentException(
					sprintf('Storage of type "%s" must implement interface "%s"', $key, $this->storageMap[$key]));
			}

			$this->storages[$key] = $storage;
		} elseif(! is_null($key) && ! is_numeric($key)) {
			throw new \InvalidArgumentException(
				sprintf('Unknown storage key "%s", must be one of [%s]', $key,
					implode(', ', array_keys($this->storageMap))));
		} else {
			// Null key and storage is one of the interfaces
			$set = false;
			foreach($this->storageMap as $name => $interface) {
				if($storage instanceof $interface) {
					$this->storages[$name] = $storage;
					$set = true;
				}
			}

			if(! $set) {
				throw new \InvalidArgumentException(
					sprintf('Storage of class "%s" must implement one of [%s]', get_class($storage),
						implode(', ', $this->storageMap)));
			}
		}
	}

	public function getStorages() {
		return $this->storages;
	}

	public function getStorage($name) {
		return isset($this->storages[$name]) ? $this->storages[$name] : null;
	}

	/**
	 * See if the current request is signed
	 *
	 * @return boolean
	 */
	public function isSigned() {
		if(isset($_REQUEST[self::OAUTH_SIGNATURE])) {
			$signed = true;
		} else {
			// In headers
			$headers = $this->getAllHeaders();
			if(isset($headers['Authorization']) && strpos($headers['Authorization'], self::OAUTH_SIGNATURE) !== false) {
				$signed = true;
			} else {
				$signed = false;
			}
		}

		return $signed;
	}

	/**
	 * Verify the request if it seemed to be signed.
	 *
	 * @param
	 *        	string type the kind of token needed, defaults to 'access'
	 *        	@exception OAuthException thrown when the request did not verify
	 * @return boolean true when signed, false when not signed
	 */
	public function verifyIfSigned($tokenType = 'access') {
		if($this->getParam(self::OAUTH_CONSUMER_KEY)) {
			$this->verify($tokenType);
			$signed = true;
		} else {
			$signed = false;
		}

		return $signed;
	}

	/**
	 * Verify the request
	 *
	 * @param string $tokenType
	 *        	The kind of token needed, defaults to 'access' (false, 'access', 'request')
	 * @param boolean $bypassNonce
	 *        	Indicate to bypass check nonce
	 * @throws OAuthException thrown when the request did not verify
	 * @return array The username associated with token (false when no user associated)
	 */
	public function verify($tokenType = 'access', $bypassNonce = false) {
		$consumerKey = $this->getParam(self::OAUTH_CONSUMER_KEY, true);
		$token = $this->getParam(self::OAUTH_TOKEN, true);

		if(empty($consumerKey)) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
				[
					'name' => self::OAUTH_CONSUMER_KEY
				]);
		}

		if($tokenType !== false && empty($token)) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT, [
				'name' => self::OAUTH_TOKEN
			]);
		}

		if(! isset($this->storages['consumer'])) {
			throw new \RuntimeException('You must supply a storage object implementing ' . $this->storageMap['consumer']);
		}

		$consumerCredentials = $this->storages['consumer']->getConsumerCredentials($consumerKey);
		if(! $consumerCredentials) {
			throw OAuthException::make(OAuthException::CONSUMER_KEY_REJECTED, [
				'value' => $consumerKey
			]);
		}

		$tokenCredentials = null;
		try {
			if($tokenType == 'access') {
				if(! isset($this->storages['access_token'])) {
					throw new \RuntimeException(
						'You must supply a storage object implementing ' . $this->storageMap['access_token']);
				}

				$tokenCredentials = $this->storages['access_token']->getAccessToken($token, $consumerKey);
			} else if($tokenType == 'request') {
				if(! isset($this->storages['request_token'])) {

					throw new \RuntimeException(
						'You must supply a storage object implementing ' . $this->storageMap['request_token']);
				}

				$tokenCredentials = $this->storages['request_token']->getRequestToken($token, $consumerKey);
			}
		} catch(\Exception $e) {
			throw OAuthException::make(OAuthException::TOKEN_REJECTED, [
				'value' => $token
			]);
		}

		if($tokenType !== false && ! $tokenCredentials) {
			throw OAuthException::make(OAuthException::TOKEN_REJECTED, [
				'value' => $token
			]);
		}

		if($bypassNonce === false) {
			if(! isset($this->storages['nonce'])) {
				throw new \RuntimeException(
					'You must supply a storage object implementing ' . $this->storageMap['nonce']);
			}

			$timestamp = $this->getParam(self::OAUTH_TIMESTAMP, true);
			if(empty($timestamp)) {
				throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
					[
						'name' => self::OAUTH_TIMESTAMP
					]);
			}

			$valid = $this->storages['nonce']->validateTimestamp($timestamp);
			if(! $valid) {
				throw OAuthException::make(OAuthException::TIMESTAMP_REFUSED, [
					'value' => $timestamp
				]);
			}

			$nonce = $this->getParam(self::OAUTH_NONCE, true);
			if(empty($nonce)) {
				throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
					[
						'name' => self::OAUTH_NONCE
					]);
			}

			$valid = $this->storages['nonce']->validateNonce($consumerKey, $token, $timestamp, $nonce);
			if(! $valid) {
				throw OAuthException::make(OAuthException::NONCE_USED, [
					'value' => $nonce
				]);
			}
		}

		$this->verifySignature($consumerCredentials['consumer_secret'],
			isset($tokenCredentials['token_secret']) ? $tokenCredentials['token_secret'] : '', $tokenType);

		// Check the optional body signature
		if($this->getParam(self::XOAUTH_BODY_SIGNATURE)) {
			$signatureMethod = $this->getParam(self::XOAUTH_BODY_SIGNATURE_METHOD);
			if(empty($signatureMethod)) {
				$signatureMethod = $this->getParam(self::OAUTH_SIGNATURE_METHOD);
			}

			$this->verifyDataSignature($this->getBody(), $consumerCredentials['consumer_secret'],
				$tokenCredentials['token_secret'], $signatureMethod, $this->getParam(self::XOAUTH_BODY_SIGNATURE));
		}

		// Check if the consumer wants us to reset the ttl of this token
		$ttl = $this->getParam(self::XOAUTH_TOKEN_TTL, true);
		if(is_numeric($ttl)) {
			if(! isset($this->storages['access_token'])) {
				throw new \RuntimeException(
					'You must supply a storage object implementing ' . $this->storageMap['access_token']);
			}

			$this->storages['access_token']->setAccessTokenTtl($token, $ttl);
		}

		return [
			'username' => isset($tokenCredentials['username']) ? $tokenCredentials['username'] : null,
			'callback_url' => isset($tokenCredentials['callback_url']) ? $tokenCredentials['callback_url'] : null,
			'referer_url' => isset($tokenCredentials['referer_url']) ? $tokenCredentials['referer_url'] : null,
			'consumer_key' => $consumerKey, 'token' => $token
		];
	}

	/**
	 * Common function to calculate the signature of the request.
	 * The signature is
	 * returned encoded in the form as used in the URL. Verify the signature of the request,
	 * using the method in oauth_signature_method.
	 *
	 * @param string $consumerSecret
	 *        	application API key
	 * @param string $tokenSecret
	 *        	@exception OAuthException thrown when the signature method is unknown
	 *        	@exception OAuthException when not all parts available
	 *        	@exception OAuthException when signature does not match
	 * @return string
	 */
	protected function verifySignature($consumerSecret, $tokenSecret, $tokenType = 'access') {
		/*
         * 'oauth_consumer_key', 'oauth_signature_method', 'oauth_signature' 'oauth_timestamp', 'oauth_nonce',
         */
		$signature = $this->params[self::OAUTH_SIGNATURE];
		if(empty($signature)) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT, [
				'name' => self::OAUTH_SIGNATURE
			]);
		}

		$signatureMethod = $this->getParam(self::OAUTH_SIGNATURE_METHOD, true);
		if(empty($signatureMethod)) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT,
				[
					'name' => self::OAUTH_SIGNATURE_METHOD
				]);
		}

		// Version 1.0
		$this->verifyVersion();

		$signatureBase = $this->getSignatureBase();
		$this->verifyDataSignature($signatureBase, $consumerSecret, $tokenSecret, $signature, $signatureMethod);
	}

	/**
	 * Verify the signature of a string.
	 *
	 * @param
	 *        	string data
	 * @param
	 *        	string consumerSecret
	 * @param
	 *        	string tokenSecret
	 * @param
	 *        	string signature
	 * @param
	 *        	string signatureMethod
	 *        	@exception OAuthException thrown when the signature method is unknown
	 *        	@exception OAuthException when signature does not match
	 */
	public function verifyDataSignature($data, $consumerSecret, $tokenSecret, $signature, $signatureMethod = 'HMAC-SHA1') {
		if(is_null($data)) {
			$data = '';
		}

		$verifier = $this->getSignatureVerifierByMethod($signatureMethod);

		$valid = $verifier->verify($data, $consumerSecret, $tokenSecret, $signature);
		if(! $valid) {
			throw OAuthException::make(OAuthException::SIGNATURE_INVALID,
				[
					'value' => $signature, 'base' => $data
				]);
		}
	}

	/**
	 * Fetch the signature object used for calculating and checking the signature base string
	 *
	 * @param
	 *        	string method
	 * @return OAuthSignatureVerifier object
	 */
	protected function getSignatureVerifierByMethod($method) {
		$method = strtoupper($method);

		$className = null;
		if($method == 'MD5') {
			$className = 'Gponster\\OAuth\\Provider\\Signature\\Md5Verifier';
		} elseif($method == 'HMAC-SHA1' || $method == 'HMACSHA1') {
			$className = 'Gponster\\OAuth\\Provider\\Signature\\HmacSha1Verifier';
		}

		if(! empty($className)) {
			return $this->getSignatureVerifier($className);
		} else {
			throw OAuthException::make(OAuthException::SIGNATURE_METHOD_REJECTED, [
				'value' => $method
			]);
		}
	}

	function getSignatureVerifier($className) {
		if(class_exists($className)) {
			$reflClass = new \ReflectionClass($className);

			if($reflClass->implementsInterface('Gponster\\OAuth\\Provider\\Signature\\VerifierInterface')) {
				return new $className();
			}

			throw new \RuntimeException(
				sprintf(
					'Signature verifiver %s must implement Gponster\\OAuth\\Provider\\Signature\\VerifierInterface.',
					$className));
		}

		throw new \RuntimeException(sprintf('Class %s not found', $className));
	}

	/**
	 * Perform version check.
	 * @exception OAuthException thrown when sanity checks failed
	 */
	protected function verifyVersion() {
		$version = $this->getParam(self::OAUTH_VERSION, true);
		if(empty($version)) {
			throw OAuthException::make(OAuthException::PARAMETER_ABSENT, [
				'name' => self::OAUTH_VERSION
			]);
		}

		if($version != '1.0' && $version != '1.0a') {
			throw OAuthException::make(OAuthException::VERSION_REJECTED, [
				'value' => $version
			]);
		}
	}
}