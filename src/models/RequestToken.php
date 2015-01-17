<?php

namespace Gponster\OAuth\Provider;

use Illuminate\Database\Eloquent\Model;

/**
 * Class RequestToken
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class RequestToken extends Model {

	/**
	 * The database table used by the model.
	 *
	 * @var string
	 */
	protected $table = 'oauth_request_tokens';

	/**
	 *
	 * @var array
	 */
	protected $guarded = [];

	public function __construct($attributes = array()) {
		parent::__construct($attributes);

		$connectionName = \Config::get('gponster/laravel-oauth-server::database.default');
		if(! empty($connectionName)) {
			$this->connection = 'gponster/laravel-oauth-server::' . $connectionName;
		}
	}
}