<h2 class="welcome">@lang('gponster/laravel-oauth-server::pages.error.desc')</h2>
@if(!empty($error))
	<p class="col-md-12 error">{{ $error }}</p>
	<p class="col-md-12">
		@lang('gponster/laravel-oauth-server::pages.authorize.warning')
	</p>
@endif

@if(Session::has('message'))
<p class="col-md-12">{{ Session::get('message') }}</p>
@endif
