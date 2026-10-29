<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SigningKey extends Model
{
    protected $primaryKey = 'kid';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected $hidden = ['private_enc'];

    protected $casts = ['activated_at' => 'datetime', 'retire_after' => 'datetime'];
}
