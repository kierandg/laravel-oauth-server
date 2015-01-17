<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

/**
 *
 * @author Gponster
 * @example php artisan migrate:make create_oauth_consumers_table --bench="gponster/laravel-oauth-server"
 *          php artisan generate:migration create_oauth_consumers_table --bench="gponster/laravel-oauth-server"
 *
 *          Run migrate
 *          php artisan migrate --bench="gponster/laravel-oauth-server"
 *
 */
class CreateOAuthConsumersTable extends Migration {

	/**
	 * Run the migrations.
	 *
	 * @return void
	 */
	public function up() {
		Schema::create('oauth_consumers',
			function ($table) {
				$table->increments('id');
				$table->string('consumer_key', 64);
				$table->string('consumer_secret', 64);
				$table->string('name', 64);
				$table->string('publisher', 64)
					->nullable();
				$table->string('type', 32);
				$table->string('category', 32);
				$table->string('website_url');
				$table->string('email', 32);
				$table->string('description')
					->nullable();
				$table->string('callback_url');
				$table->tinyInteger('enabled');
				$table->timestamps();
			});
	}

	/**
	 * Reverse the migrations.
	 *
	 * @return void
	 */
	public function down() {
		Schema::drop('oauth_consumers');
	}
}
