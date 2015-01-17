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
interface UserValidatorInterface {

	/**
	 * Validates the given user.
	 * Should check if all the fields are correctly
	 * and may check other stuff too, like if the user is unique.
	 *
	 * @param UserInterface $user
	 *        	Instance to be tested.
	 * @return bool return true if the $user is valid.
	 */
	public function validate(array $data);

	/**
	 *
	 * @return array
	 */
	public function rules($name = null);

	/**
	 *
	 * @return array
	 */
	public function messages();
}