<?php
/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
namespace Gponster\OAuth\Provider\Facades;

use Illuminate\Support\Facades\Facade;

class OAuthServer extends Facade
{

    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'gponster/oauth-server';
    }
}