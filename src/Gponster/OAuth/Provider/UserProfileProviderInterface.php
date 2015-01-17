<?php

/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
namespace Gponster\OAuth\Provider;

/**
 * Interface that declares the methods that must be
 * present in the UserValidator
 */
interface UserProfileProviderInterface {

	/**
	 * Retrieve a user profile
	 *
	 * @param mixed $identifier
	 * @return array
	 */
	public function profile($identifier, $options = []);
}