<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOAuthNoncesTable extends Migration {

	/**
	 * Run the migrations.
	 *
	 * @return void
	 */
	public function up() {
		Schema::create('oauth_nonces',
			function ($table) {
				$table->increments('id');
				$table->string('consumer_key', 64);
				$table->string('token', 64);
				$table->timestamp('timestamp');
				$table->string('nonce', 64);
				$table->timestamps();
			});
	}

	/**
	 * Reverse the migrations.
	 *
	 * @return void
	 */
	public function down() {
		Schema::drop('oauth_nonces');
	}

}
