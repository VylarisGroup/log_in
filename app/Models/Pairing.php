<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Pairing extends Model
{
    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    protected $hidden = ['sealed_credentials'];

    protected $casts = [
        'redirect_uris' => 'array',
        'post_logout_uris' => 'array',
        'scopes' => 'array',
        'challenge_used' => 'boolean',
        'expires_at' => 'datetime',
        'dash_approved_at' => 'datetime',
        'confirmed_at' => 'datetime',
        'credentials_acked_at' => 'datetime',
    ];

    public const TERMINAL = ['active', 'rejected', 'expired', 'cancelled', 'failed'];

    public function isTerminal(): bool
    {
        return in_array($this->state, self::TERMINAL, true);
    }

    public function isExpired(): bool
    {
        return ! $this->isTerminal() && $this->expires_at->isPast();
    }
}
