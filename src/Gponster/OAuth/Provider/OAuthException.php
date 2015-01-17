<?php

namespace Gponster\OAuth\Provider;

/**
 * Class OAuthException
 * Helper class to keep track exception of OAuth request
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class OAuthException extends \Exception {

	/**
	 * This error occurs when the required OAuth parameter is absent.
	 */
	const PARAMETER_ABSENT = 90;

	/**
	 * This error occurs when t​he oauth_timestamp value has expired or is invalid.
	 */
	const TIMESTAMP_REFUSED = 91;

	/**
	 * This error occurs when t​he oauth_nonce value may have been used in a previous request.
	 */
	const NONCE_USED = 92;

	/**
	 * This error occurs when t​he oauth_signature_method value is invalid.
	 */
	const SIGNATURE_METHOD_REJECTED = 93;

	/**
	 * This error occurs when t​he oauth_signature value is invalid.
	 */
	const SIGNATURE_INVALID = 94;

	/**
	 * This error occurs when t​he oauth_consumer_key value is unknown.
	 */
	const CONSUMER_KEY_REJECTED = 95;

	/**
	 * This error occurs when t​he oauth_token value has expired.
	 */
	const TOKEN_EXPIRED = 96;

	/**
	 * This error occurs when t​he oauth_token value is rejected.
	 */
	const TOKEN_REJECTED = 97;

	/**
	 * This error occurs when t​he oauth_version value is invalid.
	 */
	const VERSION_REJECTED = 98;

	/**
	 * Not authorized
	 */
	const NOT_AUTHORIZED = 99;

	/**
	 * IP address rejected
	 */
	const IP_REJECTED = 100;

	/**
	 * Service not available
	 */
	const SERVICE_UNAVAILABLE = 101;

	/**
	 * Bad URL
	 */
	const BAD_URL = 102;

	/**
	 * Invalid credentials for xAuth
	 */
	const INVALID_CREDENTIALS = 103;

	/**
	 * OAuth problem name
	 *
	 * @var string
	 */
	protected $name;

	public function __construct($message, $code = 0, \Exception $previous = null) {
		parent::__construct($message, $code, $previous);
	}

	/**
	 * Override __toString
	 *
	 * @return string Description of exception
	 */
	public function __toString() {
		return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
	}

	public function getName() {
		return $this->name;
	}

	public function setName($name) {
		$this->name = $name;

		return $this;
	}

	public static function make($code, $params = [], \Exception $previous = null) {
		$results = static::initialize($code, $params);

		$e = new OAuthException($results['message'], $code, $previous);
		$e->setName($results['name']);

		return $e;
	}

	public static function challenge($problem, $advice, $realm = 'Users') {
		$challenge = 'OAuth realm="' . $realm . '"';
		if(! empty($problem)) {
			$challenge .= ', oauth_problem="' . Rfc3986::urlEncode($problem) . '"';
		}

		if(! empty($advice)) {
			$challenge .= ', oauth_problem_advice="' . Rfc3986::urlEncode($advice) . '"';
		}

		return $challenge;
	}

	/**
	 * Get message of specific error
	 *
	 * @param int $code
	 *        	The error code
	 * @return string The error message
	 */
	public static function initialize($code, $params = []) {
		$message = '';
		$name = '';

		switch($code) {

			case self::PARAMETER_ABSENT:
				{
					$name = 'oauth_problem="parameter_absent"';
					$message = trans('gponster/laravel-oauth-server::errors.parameter_absent', $params);
				}
				break;

			case self::TIMESTAMP_REFUSED:
				{
					$name = 'oauth_problem="timestamp_refused"';
					$message = trans('gponster/laravel-oauth-server::errors.timestamp_refused', $params);
				}
				break;

			case self::NONCE_USED:
				{
					$name = 'oauth_problem="nonce_used"';
					$message = trans('gponster/laravel-oauth-server::errors.nonce_used', $params);
				}
				break;

			case self::SIGNATURE_METHOD_REJECTED:
				{
					$name = 'oauth_problem="signature_method_rejected"';
					$message = trans('gponster/laravel-oauth-server::errors.signature_method_rejected', $params);
				}
				break;

			case self::SIGNATURE_INVALID:
				{
					$name = 'oauth_problem="signature_invalid"';
					$message = trans('gponster/laravel-oauth-server::errors.signature_invalid', $params);
				}
				break;

			case self::CONSUMER_KEY_REJECTED:
				{
					$name = 'oauth_problem="consumer_key_rejected"';
					$message = trans('gponster/laravel-oauth-server::errors.consumer_key_rejected', $params);
				}
				break;

			case self::TOKEN_EXPIRED:
				{
					$name = 'oauth_problem="token_expired"';
					$message = trans('gponster/laravel-oauth-server::errors.token_expired', $params);
				}
				break;

			case self::TOKEN_REJECTED:
				{
					$name = 'oauth_problem="token_rejected"';
					$message = trans('gponster/laravel-oauth-server::errors.token_rejected', $params);
				}
				break;

			case self::VERSION_REJECTED:
				{
					$name = 'oauth_problem="version_rejected"';
					$message = trans('gponster/laravel-oauth-server::errors.version_rejected', $params);
				}
				break;

			case self::NOT_AUTHORIZED:
				{
					$name = 'oauth_problem="not_authorized"';
					$message = trans('gponster/laravel-oauth-server::errors.not_authorized', $params);
				}
				break;

			case self::SERVICE_UNAVAILABLE:
				{
					$name = 'oauth_problem="service_unavailable"';
					$message = trans('gponster/laravel-oauth-server::errors.service_unavailable', $params);
				}
				break;

			case self::IP_REJECTED:
				{
					$name = 'oauth_problem="service_unavailable"';
					$message = trans('gponster/laravel-oauth-server::errors.service_unavailable', $params);
				}
				break;

			case self::BAD_URL:
				{
					$name = 'oauth_problem="bad_url"';
					$message = trans('gponster/laravel-oauth-server::errors.bad_url', $params);
				}
				break;

			case self::INVALID_CREDENTIALS:
				{
					$name = 'oauth_problem="invalid_credentials"';
					$message = trans('gponster/laravel-oauth-server::errors.invalid_credentials', $params);
				}
				break;

			default:
				$name = 'oauth_problem="unknown_error"';
				$message = trans('gponster/laravel-oauth-server::errors.unknown_error');
		}

		return [
			'message' => $message, 'name' => $name
		];
	}
}