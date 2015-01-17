<?php
/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
return [
	'parameter_absent' => 'The parameter ":name" is required.',
	'parameter_rejected' => 'Invalid/duplicated parameter ":name" = ":value".',
	'timestamp_refused' => 'The timestamp ":value" is one of the following: in the future, too old, or malformed.',
	'nonce_used' => 'Provided nonce ":value" has been seen before.',
	'signature_method_rejected' => 'Invalid signature method ":value", currently supports "HMAC-SHA1".',
	'signature_invalid' => 'Invalid signature ":value", provided signature base ":base".',
	'consumer_key_rejected' => 'Invalid consumer key or consumer key not found ":value".',
	'token_expired' => 'Expired user token ":value".', 'token_rejected' => 'Invalid user token ":value".',
	'version_rejected' => 'The version ":value" is not supported. You must specify 1.0 for the oauth_version parameter use "1.0" or "1.0a".',
	'not_authorized' => 'The consumer key/token passed was not valid or has expired.',
	'ip_rejected' => 'The IP address ":value" is not allowed.',
	'invalid_credentials' => 'The user credentials passed for username ":username" are not valid.',
	'authorize_fail' => 'An error occurs during authorization.',
	'already_authorize' => 'An error occurs during authorization.',
	'illegal_protocol' => 'Illegal protocol in redirect URI :uri',
	'unsupported_scheme' => 'Unsupported scheme type, expected http or https, got scheme=:scheme'
];