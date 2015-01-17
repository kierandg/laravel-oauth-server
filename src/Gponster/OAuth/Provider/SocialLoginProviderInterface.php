<?php

/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
namespace Gponster\OAuth\Provider;

use Illuminate\Auth\UserInterface;

/**
 * Interface that declares the methods that must be
 * present in the UserValidator
 */
interface SocialLoginProviderInterface {

	/**
	 *
	 * @param string $provider
	 * @param string $uid
	 * @param string $accessToken
	 *
	 * @return UserInterface return user who linked to this social profile, return null
	 *         if not found or cannot verify against provider using provided information
	 */
	public function login($provider, $uid, $accessToken, $accessTokenSecret = null);
}