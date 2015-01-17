<h2 class="welcome">@lang('gponster/laravel-oauth-server::pages.authorize.desc')</h2>
{{ Form::open([
	'url'=>URL::to(Config::get('gponster/laravel-oauth-server::routes.authorize')) . '?oauth_token=' . $token,
	'role'=>'form', 'class'=> 'col-md-12', 'method' => 'POST']) }}
	<div class="form-group">&nbsp;</div>

	@if($authorized)
	<div class="form-group">
		<p class="success">
			@lang('gponster/laravel-oauth-server::pages.authorize.granted_to', [
				'name'=> $app->name ])
		</p>
		<h1 style="color: #0094C2; font-size: 3em; font-weight: 300;">{{$verifier}}</h1><br /><br />
		@lang('gponster/laravel-oauth-server::pages.authorize.pin_usage')
	</div>
	@endif

	@if($form)
	<div class="form-group">
		<h4>@lang('gponster/laravel-oauth-server::pages.authorize.connect')</h4>
		<p>@lang('gponster/laravel-oauth-server::pages.authorize.app_info', [
			'name' => $app->name,
			'publisher' => $app->publisher
		])<br /><br /></p>

		{{ Form::submit(trans('gponster/laravel-oauth-server::pages.authorize.confirm'),
			['class'=>'btn btn-primary', 'name'=>'confirm']) }}&nbsp;
		{{ Form::submit(trans('gponster/laravel-oauth-server::pages.authorize.deny'),
			['class'=>'btn btn-default', 'name'=>'deny']) }}

		@if(Auth::check())
		&nbsp;@lang('gponster/laravel-oauth-server::pages.authorize.logged_in_as', [
			'name'=> Auth::user()->display_name,
			'link' => URL::to('/logout')
		])
		@endif
	</div>
	@endif
{{ Form::close() }}