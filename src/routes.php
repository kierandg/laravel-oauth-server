<?php
/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
/*
|--------------------------------------------------------------------------
| Route
|--------------------------------------------------------------------------
|
| Route Facebook URL to our controller action.
|
*/
if(! empty(Config::get('gponster/laravel-oauth-server::routes'))) {

	Route::get(Config::get('gponster/laravel-oauth-server::routes.access_token'),
		'\Gponster\OAuth\Provider\OAuthController@getAccessToken');

	Route::get(Config::get('gponster/laravel-oauth-server::routes.request_token'),
		'\Gponster\OAuth\Provider\OAuthController@getRequestToken');

	Route::get(Config::get('gponster/laravel-oauth-server::routes.authorize'),
		'\Gponster\OAuth\Provider\OAuthController@getAuthorize');

	Route::post(Config::get('gponster/laravel-oauth-server::routes.authorize'),
		'\Gponster\OAuth\Provider\OAuthController@postAuthorize');

	$xAuthEndpoint = Config::get('gponster/laravel-oauth-server::routes.x_auth');
	if(! empty($xAuthEndpoint)) {
		Route::post($xAuthEndpoint, '\Gponster\OAuth\Provider\OAuthController@postAuth');
	}
}