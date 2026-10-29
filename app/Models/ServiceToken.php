<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ServiceToken extends Model
{
    protected $guarded = [];

    protected $casts = [
        'scopes' => 'array',
        'expires_at' => 'datetime',
        'activated_at' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];
}
