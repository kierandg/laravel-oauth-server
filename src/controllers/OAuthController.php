<?php

/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
namespace Gponster\OAuth\Provider;

use Controller;
use Config;
use Input;
use DB;
use Auth;
use Redirect;
use Carbon\Carbon;
use Gponster\OAuth\Provider\Facades\OAuthServer;

class OAuthController extends Controller {

	/**
	 * The layout that should be used for responses.
	 */
	protected $layout;
	protected $validator;

	/**
	 * Setup the layout used by the controller.
	 *
	 * @return void
	 */
	protected function setupLayout() {
		if(! is_null($this->layout)) {
			$this->layout = \View::make($this->layout);
		}
	}

	public function __construct(UserValidatorInterface $validator) {
		$this->validator = $validator;

		$layout = \Config::get('gponster/laravel-oauth-server::layout');

		if(! empty($layout)) {
			$this->layout = $layout;
		}

		$this->beforeFilter('csrf',
			[
				'on' => 'post', 'except' => [
					'postAuth'
				]
			]);
	}

	public function getRequestToken() {
		return $this->handle('requestToken');
	}

	public function getAccessToken() {
		return $this->handle('accessToken');
	}

	public function postAuth() {
		return $this->handle('xAuth');
	}

	/**
	 * Handle request token, access token and xAuth login
	 */
	protected function handle($action) {
		$response = [];
		//\Debugbar::disable();

		$now = new Carbon();

		try {
			$statusCode = 200;
			$response = [
				'result' => [
					'status' => 'success', 'code' => $statusCode,
					'server' => $_SERVER['SERVER_ADDR'], 'time' => $now->timestamp,
					'version' => 1
				]
			];

			switch($action) {
				case 'requestToken':
					$result = OAuthServer::requestToken();
					break;

				case 'accessToken':
					$result = OAuthServer::accessToken();
					break;

				case 'xAuth':
					$result = OAuthServer::xAuth();
					break;

				case 'logout':
					$result = OAuthServer::logout();
					break;

				default:
					throw OAuthException::make(OAuthException::SERVICE_UNAVAILABLE);
			}

			$response = array_merge($response, $result);
		} catch(OAuthException $e) {
			$statusCode = 400;

			$response = [
				'result' => [
					'status' => 'error', 'code' => $statusCode, 'message' => $e->getName(),
					'server' => $_SERVER['SERVER_ADDR'], 'time' => $now->timestamp,
					'version' => 1,
					'errors' => [
						[
							'message' => $e->getMessage(), 'code' => $e->getCode(),
							'method' => \Request::method(), 'url' => \Request::fullUrl()
						]
					]
				]
			];
		} catch(\Exception $e) {
			\Log::error($e,
				[
					'method' => \Request::method(), 'url' => \Request::fullUrl(),
					'error' => 'OAuth exception occured'
				]);

			$statusCode = 500;
			$response = [
				'status' => 'error', 'code' => $statusCode,
				'server' => $_SERVER['SERVER_ADDR'], 'time' => $now->timestamp,
				'version' => 1,
				'errors' => [
					[
						'message' => 'Error occured', 'code' => 500,
						'method' => \Request::method(), 'url' => \Request::fullUrl()
					]
				]
			];
		} finally{
			return \Response::json($response, $statusCode);
		}
	}

	protected function validateToken() {
		// Auth config
		$auth = \Config::get('gponster/laravel-oauth-server::auth');

		// Make sure we have oauth_token
		$token = Input::get(Request::OAUTH_TOKEN);
		if(empty($token)) {
			// Not have oauth_token just return to home
			$this->error(
				trans('gponster/laravel-oauth-server::errors.parameter_absent',
					[
						'name' => Request::OAUTH_TOKEN
					]));

			return null;
		}

		$message = trans('gponster/laravel-oauth-server::errors.token_rejected',
			[
				'value' => $token
			]);

		$requestToken = null;
		try {
			$requestToken = OAuthServer::getRequestToken($token);
		} catch(OAuthException $e) {
			$message = $e->getMessage();
		}

		if(! $requestToken) {
			// Not have oauth_token just return to home
			$this->error($message);
			return null;
		}

		// Already authorized?
		if($requestToken['authorized']) {
			$username = $requestToken['username'];

			if(Auth::check()) {
				// We already authorized this token
				if($username == Auth::user()->{$auth['username']}) {
					$app = Consumer::where('consumer_key', $requestToken['consumer_key'])->first();

					$callbackUrl = $this->getParam(self::OAUTH_CALLBACK, true);
					if(! $callbackUrl) {
						$callbackUrl = $requestToken['callback_url'];
					}

					if(! empty($callbackUrl) && $callbackUrl != 'oob') {
						$params = [
							'oauth_token' => rawurlencode($requestToken['token']),
							'oauth_verifier' => $requestToken['verifier']
						];

						// Redirect here
						OAuthServer::redirect($callbackUrl, $params);
					}

					// Display the result if callback URL is 'oob'
					$this->authorize(false, $app, true, $requestToken['verifier']);
					return null;
				} else {
					// Another user has authorized this token, report error here
					$this->error(
						trans('gponster/laravel-oauth-server::errors.already_authorize'));
					return null;
				}
			}
		}

		return $requestToken;
	}

	public function getAuthorize() {
		$requestToken = $this->validateToken();
		if(! $requestToken) {
			return;
		}

		$app = Consumer::where('consumer_key', $requestToken['consumer_key'])->first();
		if(Auth::check()) {
			$this->authorize(true, $app);
		} else {
			// Show login form
			$this->layout->title = trans(
				'gponster/laravel-oauth-server::pages.login.title');
			$this->layout->content = \View::make('gponster/laravel-oauth-server::login')->with(
				'token', $requestToken['token']);
		}
	}

	protected function error($error) {
		$this->layout->title = trans('gponster/laravel-oauth-server::pages.error.title');
		$this->layout->content = \View::make('gponster/laravel-oauth-server::error')->with(
			'error', $error);
	}

	protected function authorize($form, $app, $authorized = false, $verifier = null) {

		// Login OK show authorize form here
		$this->layout->title = trans(
			'gponster/laravel-oauth-server::pages.authorize.title');
		$this->layout->content = \View::make('gponster/laravel-oauth-server::authorize')->with(
			[
				'form' => $form, 'authorized' => $authorized,
				'token' => Input::get(Request::OAUTH_TOKEN), 'app' => $app,
				'verifier' => $verifier
			]);
	}

	protected function login() {
		// Auth config
		$auth = \Config::get('gponster/laravel-oauth-server::auth');

		$remember = (Input::has('remember_me')) ? true : false;
		$credentials = [
			$auth['username'] => Input::get('username'),
			$auth['password'] => Input::get('password'), 'status' => 1
		];

		// Validation rules
		$rules = $this->validator->rules('login');

		$v = \Validator::make(
			[
				$auth['username'] => Input::get('username'),
				$auth['password'] => Input::get('password')
			], $rules, $this->validator->messages());
		if(! $v->passes()) {
			return Redirect::back()->withErrors($v)
				->withInput(Input::except([
				'password'
			]));
		}

		$loggedIn = false;

		try {
			$loggedIn = Auth::attempt($credentials, $remember);
		} catch(\Exception $e) {
			Log::error($e, [
				'error' => 'Auth exception'
			]);
		}

		if(! $loggedIn) {
			return Redirect::back()->with('message',
				'error|' . trans('gponster/laravel-oauth-server::pages.login.fail'))
				->withInput(Input::except('password'))
				->with('token', Input::get(Request::OAUTH_TOKEN));
		}

		$requestToken = $this->validateToken();
		if(! $requestToken) {
			return;
		}

		$app = Consumer::where('consumer_key', $requestToken['consumer_key'])->first();
		$this->authorize(true, $app);
	}

	public function postAuthorize() {
		$isLogin = (Input::has('authorize_login')) ? true : false;
		if($isLogin) {
			$this->login();
		} else {
			// User confirm or deny
			$authorized = (Input::has('confirm')) ? true : false;

			$result = null;
			$state = null;
			if($authorized) {
				try {
					$state = OAuthServer::authorizeVerify();

					// If callback URL not 'oob' redirect will occur here
					$result = OAuthServer::authorizeFinish($authorized,
						Auth::user()->username);
				} catch(OAuthException $e) {
					return $this->error($e->getMessage());
				} catch(\Exception $e) {
					\Log::error($e);
					return $this->error(
						trans('gponster/laravel-oauth-server::errors.authorize_fail'));
				}
			}

			$app = Consumer::where('consumer_key', $state['consumer_key'])->first();
			// Display the result if callback URL is 'oob'
			$this->authorize(false, $app, $authorized, $result['verifier']);
		}
	}
}