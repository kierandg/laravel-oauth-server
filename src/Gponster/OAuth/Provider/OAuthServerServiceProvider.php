<?php

namespace Gponster\OAuth\Provider;

use Illuminate\Support\ServiceProvider;

class OAuthServerServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot() {
		// ---------------------------------------------------------------------
		// Notes
		// ---------------------------------------------------------------------
		// The register method is called immediately when the service provider is registered,
		// while the boot command is only called right before a request is routed.
		// So, if actions in your service provider rely on another service provider
		// already being registered, or you are overriding services bound by another provider,
		// you should use the boot method.

		// ---------------------------------------------------------------------
		// Access package configuration
		// ---------------------------------------------------------------------
		// If using namespace to get config must use syntax Config::get('vendor/package::file.option');
		// If not using namespace the syntax is Config::get('package::file.option');
		// public function package($package, $namespace = null, $path = null)
		$this->package('gponster/laravel-oauth-server', 'gponster/laravel-oauth-server',
			__DIR__ . '/../../..');

		include __DIR__ . '/../../../routes.php';

		$database = \Config::get('gponster/laravel-oauth-server::database');
		if(is_array($database)) {
			$connections = isset($database['connections']) ? $database['connections'] : [];

			$packageConnections = [];
			foreach($connections as $name => $conn) {
				$packageConnections['gponster/laravel-oauth-server::' . $name] = $conn;
			}

			$this->app['config']['database.connections'] = array_merge(
				$this->app['config']['database.connections'], $packageConnections);
		}

		// ---------------------------------------------------------------------
		// Bind the UserValidatorInterface
		// ---------------------------------------------------------------------
		$validatorName = \Config::get('gponster/laravel-oauth-server::auth.validator');
		if(empty($validatorName)) {
			throw new \RuntimeException('User vadidator class has not been configured.');
		}

		if(! class_exists($validatorName)) {
			throw new \RuntimeException(
				sprintf('User validator class \'%s\' does not exist.', $validatorName));
		}

		$reflClass = new \ReflectionClass($validatorName);
		if(! $reflClass->implementsInterface(
			'Gponster\\OAuth\\Provider\\UserValidatorInterface')) {
			throw new \RuntimeException(
				sprintf(
					'User validator class \'%s\' must implements interface Gponster\\OAuth\\Provider\\UserValidatorInterface.',
					$validatorName));
		}

		$this->app->bind('Gponster\\OAuth\\Provider\\UserValidatorInterface',
			$validatorName);

		// ---------------------------------------------------------------------
		// Bind the SocialLoginProvider
		// ---------------------------------------------------------------------
		$providerName = \Config::get('gponster/laravel-oauth-server::auth.social_login');

		// Have social-login configuration
		if(! empty($providerName)) {
			if(! class_exists($providerName)) {
				throw new \RuntimeException(
					sprintf('Social login provider class \'%s\' does not exist.',
						$providerName));
			}

			$reflClass = new \ReflectionClass($providerName);
			if(! $reflClass->implementsInterface(
				'Gponster\\OAuth\\Provider\\SocialLoginProviderInterface')) {
				throw new \RuntimeException(
					sprintf(
						'Social login provider \'%s\' must implements interface Gponster\\OAuth\\Provider\\SocialLoginProviderInterface.',
						$providerName));
			}

			$this->app->bind('Gponster\\OAuth\\Provider\\SocialLoginProviderInterface',
				$providerName);
		}

		// ---------------------------------------------------------------------
		// Bind the UserProfileProvider
		// ---------------------------------------------------------------------
		$providerName = \Config::get('gponster/laravel-oauth-server::auth.profile');

		// Have user profile provider configuration
		if(! empty($providerName)) {
			if(! class_exists($providerName)) {
				throw new \RuntimeException(
					sprintf('User profile provider class \'%s\' does not exist.',
						$providerName));
			}

			$reflClass = new \ReflectionClass($providerName);
			if(! $reflClass->implementsInterface(
				'Gponster\\OAuth\\Provider\\UserProfileProviderInterface')) {
				throw new \RuntimeException(
					sprintf(
						'User profile provider \'%s\' must implements interface Gponster\\OAuth\\Provider\\UserProfileProviderInterface.',
						$providerName));
			}

			$this->app->bind('Gponster\\OAuth\\Provider\\UserProfileProviderInterface',
				$providerName);
		}
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register() {
		$this->app['gponster/oauth-server'] = $this->app->share(
			function ($app) {
				// Create new OAuth Server with config
				$config = $this->app['config']->get(
					'gponster/laravel-oauth-server::storages');

				if(is_string($config)) {
					$className = $config;
					if(! class_exists($className)) {
						throw new \RuntimeException(
							sprintf('Storage class \'%s\' does not exist.', $className));
					}

					return new Server(new $className());
				} else if(is_array($config)) {
					$storages = [];
					foreach($config as $name => $className) {
						if(! class_exists($className)) {
							throw new \RuntimeException(
								sprintf('Storage class \'%s\' does not exist.',
									$className));
						}

						$storages[$name] = new $className();
					}

					return new Server(new $className());
				}

				throw new \RuntimeException('Invalid OAuth storage configuration.');
			});
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides() {
		return [
			'gponster/oauth-server'
		];
	}
}
