<?php

namespace Gponster\OAuth\Provider;

/**
 * Class OAuth Request
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Request {

	/**
	 * OAuth parameter prefix
	 */
	const OAUTH_PARAM_PREFIX = 'oauth_';

	/**
	 * OAuth parameter prefix
	 */
	const XOAUTH_PARAM_PREFIX = 'xoauth_';

	/**
	 * XAuth parameter prefix
	 */
	const X_AUTH_PARAM_PREFIX = 'xauth_';

	/**
	 * XAuth parameter prefix
	 */
	const X_AUTH_MODE = 'x_auth_mode';

	/**
	 * XAuth password parameter
	 */
	const X_AUTH_PASSWORD = 'x_auth_password';

	/**
	 * XAuth username parameter
	 */
	const X_AUTH_USERNAME = 'x_auth_username';

	/**
	 * OAuth parameter prefix
	 */
	const XOAUTH_TOKEN_TTL = 'xoauth_token_ttl';

	/**
	 * OAuth parameter prefix
	 */
	const XOAUTH_BODY_SIGNATURE = 'xoauth_body_signature';

	/**
	 * OAuth parameter prefix
	 */
	const XOAUTH_BODY_SIGNATURE_METHOD = 'xoauth_body_signature_method';

	/**
	 * OAuth consumer key: oauth_consumer_key
	 */
	const OAUTH_CONSUMER_KEY = 'oauth_consumer_key';

	/**
	 * OAuth consumer secret: oauth_consumer_secret
	 */
	const OAUTH_CONSUMER_SECRET = 'oauth_consumer_secret';

	/**
	 * OAuth token key: oauth_token
	 */
	const OAUTH_TOKEN = 'oauth_token';

	/**
	 * OAuth token key: oauth_token_secret
	 */
	const OAUTH_TOKEN_SECRET = 'oauth_token_secret';

	/**
	 * OAuth signature method: oauth_signature_method
	 */
	const OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';

	/**
	 * OAuth signature: oauth_signature
	 */
	const OAUTH_SIGNATURE = 'oauth_signature';

	/**
	 * OAuth timestamp: oauth_timestamp
	 */
	const OAUTH_TIMESTAMP = 'oauth_timestamp';

	/**
	 * OAuth nonce: oauth_nonce
	 */
	const OAUTH_NONCE = 'oauth_nonce';

	/**
	 * OAuth callback: oauth_callback
	 */
	const OAUTH_CALLBACK = 'oauth_callback';

	const OAUTH_CALLBACK_CONFIRMED = 'oauth_callback_confirmed';

	/**
	 * OAuth verifier: oauth_verifier
	 */
	const OAUTH_VERIFIER = 'oauth_verifier';

	/**
	 * OAuth version: oauth_version
	 */
	const OAUTH_VERSION = 'oauth_version';

	/**
	 * The realm for this request
	 */
	protected $realm;

	/**
	 * All the parameters, RFC3986 encoded name/value pairs
	 */
	protected $params = array();

	/**
	 * The request raw URI
	 */
	protected $uri;

	/**
	 * The request URI components
	 */
	protected $uriComponents;

	/**
	 * The request headers
	 */
	protected $headers;

	/**
	 * The request HTTP method
	 */
	protected $method;

	/**
	 * The body of the OAuth request
	 */
	protected $body;

	/**
	 * Construct from the current request.
	 * Useful for checking the signature of a request.
	 * When not supplied with any parameters this will use the current request.
	 *
	 * @param string $uri
	 *        	URI
	 * @param string $method
	 *        	GET, PUT, POST etc.
	 * @param string $params
	 *        	additional post parameters as string
	 * @param array $headers
	 *        	headers for request
	 * @param string $body
	 *        	optional body of the request (POST or PUT)
	 */
	public function __construct($uri = null, $method = null, $params = '', $headers = array(), $body = null) {
		if(is_object($_SERVER)) {
			// Tainted arrays - the normal stuff in anyMeta
			if(! $method) {
				$method = $_SERVER->REQUEST_METHOD->getRawUnsafe();
			}

			if(empty($uri)) {
				$uri = $_SERVER->REQUEST_URI->getRawUnsafe();
				$proto = $this->getProto();

				if(strpos($uri, '://') === false) {
					$uri = sprintf('%s://%s%s', $proto, $_SERVER->HTTP_HOST->getRawUnsafe(), $uri);
				}
			}
		} else {
			// Non anyMeta systems
			if(! $method) {
				if(isset($_SERVER['REQUEST_METHOD'])) {
					$method = $_SERVER['REQUEST_METHOD'];
				} else {
					$method = 'GET';
				}
			}

			$proto = $this->getProto();

			if(empty($uri)) {
				if(strpos($_SERVER['REQUEST_URI'], '://') !== false) {
					$uri = $_SERVER['REQUEST_URI'];
				} else {
					$uri = sprintf('%s://%s%s', $proto, $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']);
				}
			}
		}

		$headers = static::getAllHeaders();
		$method = strtoupper($method);
		$this->method = $method;

		// If this is a post then also check the posted variables
		if(strcasecmp($method, 'POST') == 0) {
			// TODO: what to do with 'multipart/form-data'?
			if($this->getRequestContentType() == 'multipart/form-data') {
				// Get the posted body (when available)
				if(! isset($headers['X-OAuth-Test'])) {
					$params .= $this->getRequestBodyOfMultipart();
				}
			}

			if($this->getRequestContentType() == 'application/x-www-form-urlencoded') {
				// Get the posted body (when available)
				if(! isset($headers['X-OAuth-Test'])) {
					$params .= $this->getRequestBody();
				}
			} else {
				$body = $this->getRequestBody();
			}
		} else if(strcasecmp($method, 'PUT') == 0) {
			$body = $this->getRequestBody();
		}

		// Method and header
		$this->headers = $headers;

		// Store value, prepare for verify
		$this->uri = $uri;
		$this->body = $body;

		// Parse URI with optional parameters string
		$this->parseUri($params);
		$this->parseHeaders();

		// Re-encode RFC 3986 after get all params
		$this->transcodeParams();
	}

	public function getProto() {
		$proto = 'http';

		// Vu Dang <anhvudg@gmail.com> 2014/04/05 fixed https cannot be detected with HAProxy or Nginx
		// Proxy converts the received HTTPS traffic into HTTP and adds the x-forwarded-proto header and x-forwarded-for
		if(isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https') {
			$_SERVER['HTTPS'] = 'on';
		}

		if(isset($_SERVER['HTTPS'])) {
			$proto = ($_SERVER['HTTPS'] == 'on') ? 'https' : 'http';
		} else {
			$proto = (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) ? 'https' : 'http';
		}

		return $proto;
	}

	/**
	 * Helper to try to sort out headers for people who aren't running apache,
	 * or people who are running PHP as FastCGI.
	 *
	 * @return array of request headers as associative array.
	 */
	public static function getAllHeaders() {
		$ret = array();
		$headers = array();

		if(function_exists('apache_request_headers')) {
			$headers = apache_request_headers();
		} else {
			$headers = array_merge($_ENV, $_SERVER);

			foreach($headers as $key => $val) {
				// We need this header
				if(strpos(strtolower($key), 'content-type') !== FALSE) {
					continue;
				}

				if(strtoupper(substr($key, 0, 5)) != 'HTTP_') {
					unset($headers[$key]);
				}
			}
		}

		// Normalize this array to Cased-Like-This structure.
		foreach($headers as $key => $value) {
			$key = preg_replace('/^HTTP_/i', '', $key);
			$key = str_replace(' ', '-', ucwords(strtolower(str_replace(array(
				'-', '_'
			), ' ', $key))));

			$ret[$key] = $value;
		}

		ksort($ret);

		return $ret;
	}

	/**
	 * This is method getMethod
	 *
	 * @return string Return HTTP method of this request
	 */
	public function getMethod() {
		return $this->method;
	}

	/**
	 * Get the body of this request
	 *
	 * @return string The request's body
	 */
	public function getBody() {
		return $this->body;
	}

	/**
	 * Set the body for this request
	 *
	 * @param string $body
	 *        	Null if not available
	 */
	public function setBody($body) {
		$this->body = $body;
	}

	/**
	 * Return the normalized URL for signature checks
	 */
	public function getRequestUrl() {
		// URI components has been parsed in constructor
		$url = $this->uriComponents['scheme'] . '://' . $this->uriComponents['user'] .
			 (! empty($this->uriComponents['pass']) ? ':' : '') . $this->uriComponents['pass'] .
			 (! empty($this->uriComponents['user']) ? '@' : '') . $this->uriComponents['host'];

		if($this->uriComponents['port'] &&
			 $this->uriComponents['port'] != $this->getDefaultPort($this->uriComponents['scheme'])) {
			$url .= ':' . $this->uriComponents['port'];
		}

		if(! empty($this->uriComponents['path'])) {
			$url .= $this->uriComponents['path'];
		}

		return $url;
	}

	/**
	 * Get a parameter, value is default URL encoded
	 *
	 * @param string $name
	 *        	Parameter's name
	 * @param boolean $encode
	 *        	Set to true to decode the value upon return
	 * @return string False when not found
	 */
	public function getParam($name, $decode = false) {
		if(isset($this->params[$name])) {
			$value = $this->params[$name];
		} elseif(isset($this->params[Rfc3986::urlEncode($name)])) {
			$value = $this->params[Rfc3986::urlEncode($name)];
		} else {
			$value = false;
		}

		if(! empty($value) && $decode) {
			if(is_array($value)) {
				$value = array_map(array(
					'Rfc3986', 'urlDecode'
				), $value);
			} else {
				$value = Rfc3986::urlDecode($value);
			}
		}

		return $value;
	}

	/**
	 * Set a parameter
	 *
	 * @param string $name
	 *        	The parameter name
	 * @param string $value
	 *        	The value
	 * @param boolean $encoded
	 *        	Set encoded or not both name and value. Default is false.
	 */
	function setParam($name, $value, $encoded = false) {
		if(! $encoded) {
			$nameEncoded = Rfc3986::urlEncode($name);

			if(is_array($value)) {
				foreach($value as $v) {
					$this->params[$nameEncoded][] = Rfc3986::urlEncode($v);
				}
			} else {
				$this->params[$nameEncoded] = Rfc3986::urlEncode($value);
			}
		} else {
			$this->params[$name] = $value;
		}
	}

	/**
	 * Re-encode all parameters so that they are encoded using RFC 3986.
	 * Updates the $this->params attribute.
	 */
	protected function transcodeParams() {
		$params = $this->params;
		$transcode = array();

		foreach($params as $name => $value) {
			if(is_array($value)) {
				$transcode[Rfc3986::urlTranscode($name)] = array_map(array(
					'Rfc3986', 'urlTranscode'
				), $value);
			} else {
				$transcode[Rfc3986::urlTranscode($name)] = Rfc3986::urlTranscode($value);
			}
		}

		$this->params = $transcode;
	}

	/**
	 * Fetch the content type of the current request
	 *
	 * @return string The request content-type
	 */
	protected function getRequestContentType() {
		$type = 'application/octet-stream';
		if(! empty($_SERVER) && array_key_exists('CONTENT_TYPE', $_SERVER)) {
			list($type) = explode(';', $_SERVER['CONTENT_TYPE']);
		}

		return trim($type);
	}

	/**
	 * Get the body of a POST or PUT.
	 * Used for fetching the post parameters and to calculate the body signature.
	 *
	 * @return string Return null when no body present (or wrong content type for body)
	 */
	protected function getRequestBody() {
		$body = null;
		if($this->method == 'POST' || $this->method == 'PUT') {
			$body = '';
			$fh = @fopen('php://input', 'r');
			if($fh) {
				while(! feof($fh)) {
					$chunk = fread($fh, 1024);
					if(is_string($chunk)) {
						$body .= $chunk;
					}
				}

				fclose($fh);
			}
		}

		return $body;
	}

	/**
	 * Get the body of a POST with multipart/form-data by Edison tsai on 16:52 2010/09/16
	 * Used for fetching the post parameters and to calculate the body signature.
	 *
	 * @return string null when no body present (or wrong content type for body)
	 */
	protected function getRequestBodyOfMultipart() {
		$body = null;
		if($this->method == 'POST') {
			$body = '';
			if(is_array($_POST) && count($_POST) > 1) {
				foreach($_POST as $k => $v) {
					$body .= $k . '=' . Rfc3986::urlEncode($v) . '&';
				}

				if(substr($body, - 1) == '&') {
					$body = substr($body, 0, strlen($body) - 1);
				}
			}
		}

		return $body;
	}

	/**
	 * Simple function to perform a redirect (GET).
	 * Redirects the User-Agent, does not return.
	 *
	 * @param string $uri
	 *        	URI to redirect to
	 * @param array $params
	 *        	Parameters with URL encoded
	 *        	@exception Exception Throw exception when redirect URI is illegal
	 */
	public function redirect($uri, $params) {
		if(! empty($params)) {
			$list = array();
			foreach($params as $name => $value) {
				$list[] = $name . '=' . $value;
			}

			$query = implode('&', $list);

			if(strpos($uri, '?')) {
				$uri .= '&' . $query;
			} else {
				$uri .= '?' . $query;
			}
		}

		// Simple security - multiline location headers can inject all kinds of extras
		$uri = preg_replace('/\s/', '%20', $uri);
		if(strncasecmp($uri, 'http://', 7) && strncasecmp($uri, 'https://', 8)) {
			if(strpos($uri, '://')) {
				throw new OAuthException(
					trans('gponster/laravel-oauth-server::errors.illegal_protocol', [
						'uri' => $uri
					]));
			}

			$uri = 'http://' . $uri;
		}

		header('HTTP/1.1 302 Found');
		header('Location: ' . $uri);
		echo '';
		exit();
	}

	/**
	 * Parse the oauth parameters from the request headers
	 * Looks for something like:
	 * Authorization: OAuth realm="http://photos.example.net/authorize",
	 * oauth_consumer_key="dpf43f3p2l4k3l03",
	 * oauth_token="nnch734d00sl2jdk",
	 * oauth_signature_method="HMAC-SHA1",
	 * oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D",
	 * oauth_timestamp="1191242096",
	 * oauth_nonce="kllo9940pd9333jh",
	 * oauth_version="1.0"
	 */
	protected function parseHeaders() {
		/*
			$this->headers['Authorization'] = 'OAuth realm="http://photos.example.net/authorize",
			oauth_consumer_key="dpf43f3p2l4k3l03",
			oauth_token="nnch734d00sl2jdk",
			oauth_signature_method="HMAC-SHA1",
			oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D",
			oauth_timestamp="1191242096",
			oauth_nonce="kllo9940pd9333jh",
			oauth_version="1.0"';
		*/
		if(isset($this->headers['Authorization'])) {
			$auth = trim($this->headers['Authorization']);
			if(strncasecmp($auth, 'OAuth', 4) == 0) {
				$pairs = explode(',', substr($auth, 6));
				foreach($pairs as $pair) {
					if(strpos($pair, '=')) {
						$pair = trim($pair);
						@list($name, $value) = explode('=', $pair, 2);

						if(! empty($value) && $value{0} == '"' && substr($value, - 1) == '"') {
							$value = substr(substr($value, 1), 0, - 1);
						}

						if(strcasecmp($name, 'realm') == 0) {
							$this->realm = $value;
						} else {

							if(isset($this->params[$name])) {
								// WARNING HERE
								// we have already received parameter(s) with this name, so add to the list
								// of parameters with this name
								if(is_scalar($this->params[$name])) {
									// this is the first duplicate, so transform scalar (string) into an array
									// so we can add the duplicates
									$this->params[$name] = array(
										$this->params[$name]
									);
								}

								$this->params[$name][] = $value;
							} else {
								$this->params[$name] = $value;
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Parse the uri into its parts.
	 * Fill in the missing parts.
	 *
	 * @todo check for the use of HTTPS, right now we default to HTTP
	 * @todo support for multiple occurrences of parameters
	 * @param string $params
	 *        	Optional extra parameters (from e.g the HTTP POST)
	 */
	protected function parseUri($params) {
		$components = parse_url($this->uri);

		// get the current/requested method
		if(empty($components['scheme'])) {
			$components['scheme'] = 'http';
		} else {
			$components['scheme'] = strtolower($components['scheme']);
		}

		// get the current/requested host
		if(empty($components['host'])) {
			if(isset($_SERVER['HTTP_HOST'])) {
				$components['host'] = $_SERVER['HTTP_HOST'];
			} else {
				$components['host'] = '';
			}
		}

		// Phong Linh 2011/10/20 comment for dev pursposes
		// if (function_exists('mb_strtolower')) {
		// $components['host'] = mb_strtolower($components['host']);
		// } else {
		// $components['host'] = strtolower($components['host']);
		// }
		//
		// if (!preg_match('/^[a-z0-9\.\-]+$/', $components['host'])) {
		// throw new Exception('Unsupported characters in host name');
		// }

		// get the port we are talking on
		if(empty($components['port'])) {
			$components['port'] = $this->getDefaultPort($components['scheme']);
		}

		if(empty($components['user'])) {
			$components['user'] = '';
		}

		if(empty($components['pass'])) {
			$components['pass'] = '';
		}

		if(empty($components['path'])) {
			$components['path'] = '/';
		}

		if(empty($components['query'])) {
			$components['query'] = '';
		}

		if(empty($components['fragment'])) {
			$components['fragment'] = '';
		}

		if(! is_array($this->params)) {
			$this->params = array();
		}

		// Now all is complete - parse all parameters
		foreach(array(
			$components['query'], $params
		) as $input) {
			if(strlen($input) > 0) {
				$this->parseParameters($input);
			}
		}

		$this->uriComponents = $components;
	}

	/**
	 * Return the default port for a scheme
	 *
	 * @param string $scheme
	 *        	Scheme of request HTTP or HTTPS
	 * @return int The default port associate to scheme
	 */
	protected function getDefaultPort($scheme) {
		switch($scheme) {
			case 'http':
				return 80;

			case 'https':
				return 43;

			default:
				throw new OAuthException(
					trans('gponster/laravel-oauth-server::errors.unsupported_scheme',
						[
							'scheme' => $scheme
						]));
				break;
		}
	}

	/**
	 * This function takes a input like a=b&a=c&d=e and returns the parsed
	 * parameters like this array('a' => array('b', 'c'), 'd' => 'e')
	 *
	 * @param string $input
	 *        	This is a description
	 * @return mixed Return the parameters
	 */
	protected function parseParameters($input) {
		if(! isset($input) || ! $input) {
			return array();
		}

		if(strlen($input) > 0) {
			$pairs = explode('&', $input);
			foreach($pairs as $pair) {
				if(strpos($pair, '=')) {
					@list($name, $value) = explode('=', $pair, 2);

					// Check value exist
					$value = isset($value) ? $value : '';
					if(isset($this->params[$name])) {
						// We have already received parameter(s) with this name, so add to the list
						// of parameters with this name
						if(is_scalar($this->params[$name])) {
							// This is the first duplicate, so transform scalar (string) into an array
							// so we can add the duplicates
							$this->params[$name] = array(
								$this->params[$name]
							);
						}

						$this->params[$name][] = $value;
					} else {
						$this->params[$name] = $value;
					}
				}
			}
		}

		// Return parsed parameters
		return $this->params;
	}

	/**
	 * Return the complete parameter string for the signature check.
	 * All parameters are correctly URL encoded and sorted on name and value
	 *
	 * @return string
	 */
	protected function getNormalizedParams() {
		$params = $this->params;
		$normalized = array();

		ksort($params);
		foreach($params as $key => $value) {
			// All names and values are already URL encoded, exclude the signature
			if($key != self::OAUTH_SIGNATURE) {
				if(is_array($value)) {
					$vals = $value;
					sort($vals);
					foreach($vals as $v) {
						$normalized[] = $key . '=' . $v;
					}
				} else {
					$normalized[] = $key . '=' . $value;
				}
			}
		}

		return implode('&', $normalized);
	}

	/**
	 * Return the signature base string.
	 * Note that we can't use rawurlencode due to specified use of RFC3986.
	 *
	 * @todo Get the request URL
	 * @todo Get the normalized parameters
	 * @return string The signature base string
	 */
	protected function getSignatureBase() {
		$signature = [];
		$signature[] = $this->method;
		$signature[] = $this->getRequestUrl();
		$signature[] = $this->getNormalizedParams();

		return implode('&', array_map(array(
			'Gponster\\OAuth\\Provider\\Rfc3986', 'urlEncode'
		), $signature));
	}
}