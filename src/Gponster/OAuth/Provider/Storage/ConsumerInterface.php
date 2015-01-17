<?php

namespace Gponster\OAuth\Provider\Storage;

/**
 * Interface for OAuth consumer store
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
interface ConsumerInterface {

	/**
	 * Get consumer details
	 *
	 * @param string $consumerKey
	 * @param string $type
	 * @param string $enabled
	 * @param array $options
	 *        	Search criteria [ 'name', 'publisher', 'type', 'category',
	 *        	'website_url', 'email', 'description', 'callback_url' ]
	 * @return array [ 'consumer_key', 'name', 'publisher', 'type', 'category',
	 *         'website_url', 'email', 'description', 'callback_url', 'enabled' ]
	 */
	function getConsumer($consumerKey, $enabled = 1, $options = []);

	/**
	 * Get consumer credentials (consumer_secret)
	 *
	 * @param string $consumerKey
	 * @param string $type
	 * @param string $enabled
	 * @param array $options
	 *        	Search criteria [ 'name', 'publisher', 'type', 'category',
	 *        	'website_url', 'email', 'description', 'callback_url' ]
	 * @return array [ 'consumer_key', 'consumer_secret' ]
	 */
	function getConsumerCredentials($consumerKey, $enabled = 1, $options = []);
}