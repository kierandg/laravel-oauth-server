<?php
/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
return [
	'login' => [
		'title' => 'Login', 'desc' => 'Enter your credentials', 'submit' => 'Login',
		'fail' => 'Invalid username/password combination.'
	],
	'authorize' => [
		'title' => 'Authorize', 'desc' => 'Please authorize to use services', 'confirm' => 'Confirm', 'deny' => 'Deny',
		'logged_in_as' => 'Logged in as :name (<a href=":link">Not you?</a>)',
		'connect' => 'An application  would like to connect to your account',
		'app_info' => 'The app :name by :publisher would like to access your information.',
		'granted_to' => 'You\'ve granted to :name, enter this PIN to complete the authorization process',
		'pin_usage' => 'You can write down this PIN and close this window and return application.',
		'warning' => 'Please contact the developer of the application that sent you here for assistance.'
	], 'error' => [
		'title' => 'Error', 'desc' => 'Error'
	]
];