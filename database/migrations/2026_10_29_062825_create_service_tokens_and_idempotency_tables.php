<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Service-API-Token (Dash -> log_in). Nur der SHA-256-Hash wird gespeichert.
        Schema::create('service_tokens', function (Blueprint $t) {
            $t->id();
            $t->string('token_hash', 64)->unique();
            $t->string('installation_id', 128)->index();
            $t->json('scopes');
            $t->string('status', 16)->default('active'); // active | revoked
            $t->string('revoked_reason', 64)->nullable();
            $t->timestamp('expires_at');
            $t->timestamp('activated_at')->nullable();
            $t->unsignedBigInteger('rotated_from')->nullable();
            $t->timestamp('last_used_at')->nullable();
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();
        });

        // Idempotency-Key fuer schreibende Maschinenrequests.
        Schema::create('idempotency_keys', function (Blueprint $t) {
            $t->id();
            $t->string('installation_id', 128);
            $t->string('idem_key', 128);
            $t->string('request_hash', 64);
            $t->unsignedSmallInteger('response_status')->nullable();
            $t->longText('response_body')->nullable();
            $t->timestamp('expires_at')->index();
            $t->timestamps();
            $t->unique(['installation_id', 'idem_key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('idempotency_keys');
        Schema::dropIfExists('service_tokens');
    }
};
