<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BootstrapAdmin extends Model
{
    protected $guarded = [];

    protected $hidden = ['password_hash', 'totp_secret_enc'];

    protected $casts = ['expires_at' => 'datetime', 'disabled_at' => 'datetime', 'locked_until' => 'datetime'];

    public function isUsable(): bool
    {
        return $this->disabled_at === null && $this->expires_at->isFuture();
    }
}
