<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SsoSession extends Model
{
    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    protected $casts = [
        'auth_time' => 'datetime',
        'last_seen_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'amr' => 'array',
    ];

    public function isValid(): bool
    {
        if ($this->revoked_at !== null || $this->expires_at->isPast()) {
            return false;
        }

        return $this->last_seen_at->addSeconds((int) config('vylaris.ttl.sso_idle'))->isFuture();
    }
}
