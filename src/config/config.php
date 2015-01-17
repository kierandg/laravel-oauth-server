<?php
/**
 * Configuration Facebook Connect.
 *
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
return array(
	'routes' => [
		// Access token endpoint
		'access_token' => 'oauth/access_token',

		// Request token endpoint
		'request_token' => 'oauth/request_token',

		// Authorize endpoint
		'authorize' => 'oauth/authorize',

		// xAuth endpoint
		'x_auth' => 'oauth/x_auth'
	], 'storages' => '\Gponster\\OAuth\\Provider\\Storage\\Pdo', 
	'database' => [],
	'layout' => 'layouts.mini',
	'auth' => [

		// Social login
		'social_login' => '\SocialLoginProvider',

		// Profile provider
		'profile' => '\UserProfileProvider',

		// User validator
		'validator' => '\UserValidator',

		'username' => 'username', 'password' => 'password', 'status' => 'status'
	]
);