<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Issuer Name
    |--------------------------------------------------------------------------
    | Shown in authenticator apps (e.g. Google Authenticator) next to the
    | account entry. Defaults to your app name when null.
    |--------------------------------------------------------------------------
    */

    'issuer' => env('MFA_ISSUER', 'MyApp'),

    /*
    |--------------------------------------------------------------------------
    | TOTP Settings
    |--------------------------------------------------------------------------
    */

    'totp' => [
        'digits'    => 6,
        'period'    => 30,   // seconds per time-step
        'window'    => 1,    // ±1 period tolerance for clock drift
        'algorithm' => 'sha1',
    ],

];
