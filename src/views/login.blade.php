<h2 class="welcome">@lang('gponster/laravel-oauth-server::pages.login.desc')</h2>
{{ Form::open([
	'url'=>URL::to(Config::get('gponster/laravel-oauth-server::routes.authorize')) . '?oauth_token=' . $token,
	'role'=>'form', 'class'=> 'col-md-4', 'method' => 'POST']) }}
	<div class="form-group">&nbsp;</div>

	@if($errors->count())
	<ul class="error">
		@if($errors->first())
		<li>{{ $errors->first() }}</li>
		@endif
	</ul>
	@endif
	@if(Session::has('message'))
	<p class="alert">{{ Session::get('message') }}</p></p>
	@endif
	<div class="form-group @if($errors->has('username')) has-error @endif">
		{{ Form::text('username', Input::old('username'),
			['class'=>'form-control input-sm',
			'placeholder'=>trans('gponster/laravel-oauth-server::form.username.placeholder')]) }}
	</div>

	<div class="form-group @if($errors->has('password')) has-error @endif">
		{{ Form::password('password',
			['class'=>'form-control input-sm',
			'placeholder'=>trans('gponster/laravel-oauth-server::form.password.placeholder')]) }}
	</div>

	<div class="checkbox">
		<label>{{ Form::checkbox('remember_me', false, false,
			['class'=>'checkbox-inline']) }}&nbsp;@lang('gponster/laravel-oauth-server::form.remember_me.label')</label>
	</div>

	<div class="form-group">
		{{ Form::hidden('authorize_login', '1') }}
		{{ Form::submit(trans('pages.login.submit'), ['class'=>'btn btn-primary']) }}
	</div>
{{ Form::close() }}