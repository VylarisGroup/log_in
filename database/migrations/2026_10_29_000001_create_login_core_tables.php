<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Laravel-Web-Sessions (Setup-Admin, Login-Formular). Keine Benutzertabelle: Dash fuehrt die Identitaeten.
        Schema::create('sessions', function (Blueprint $t) {
            $t->string('id')->primary();
            $t->foreignId('user_id')->nullable()->index();
            $t->string('ip_address', 45)->nullable();
            $t->text('user_agent')->nullable();
            $t->longText('payload');
            $t->integer('last_activity')->index();
        });

        Schema::create('settings', function (Blueprint $t) {
            $t->string('key')->primary();
            $t->text('value')->nullable();
            $t->timestamps();
        });

        Schema::create('signing_keys', function (Blueprint $t) {
            $t->string('kid', 64)->primary();
            $t->string('alg', 16)->default('RS256');
            $t->text('public_pem');
            $t->longText('private_enc'); // mit APP_KEY verschluesselt
            $t->string('status', 16)->index(); // active | retired | revoked
            $t->timestamp('activated_at')->nullable();
            $t->timestamp('retire_after')->nullable(); // Ende der JWKS-Publikation nach Rotation
            $t->timestamps();
        });

        Schema::create('oidc_clients', function (Blueprint $t) {
            $t->string('client_id', 64)->primary();
            $t->string('installation_id', 128)->unique();
            $t->string('name');
            $t->string('domain');
            $t->string('version', 32)->nullable();
            $t->boolean('confidential')->default(true);
            $t->string('secret_hash', 64)->nullable(); // sha256 eines 256-Bit-Zufallsgeheimnisses
            $t->string('previous_secret_hash', 64)->nullable();
            $t->timestamp('previous_secret_until')->nullable();
            $t->json('redirect_uris');
            $t->json('post_logout_uris')->nullable();
            $t->json('scopes');
            $t->string('status', 16)->index(); // pending | active | error | disconnected | suspended
            $t->boolean('is_dash')->default(false);
            $t->string('pairing_id', 64)->nullable()->index();
            $t->text('tool_public_key')->nullable();     // Ed25519 (Pairing-Nachweis)
            $t->text('tool_box_public_key')->nullable(); // X25519 (Versiegelung der Zugangsdaten)
            $t->string('last_error')->nullable();
            $t->timestamp('disconnected_at')->nullable();
            $t->timestamps();
        });

        Schema::create('sso_sessions', function (Blueprint $t) {
            $t->string('id', 64)->primary();
            $t->string('public_sid', 32)->unique(); // oeffentliche Sitzungs-ID (sid-Claim), nicht die interne ID
            $t->string('sub', 128)->index();
            $t->string('tenant_id', 128)->nullable();
            $t->timestamp('auth_time');
            $t->timestamp('last_seen_at');
            $t->timestamp('expires_at')->index();
            $t->timestamp('revoked_at')->nullable();
            $t->string('revoked_reason')->nullable();
            $t->json('amr')->nullable();
            $t->timestamps();
        });

        Schema::create('oidc_auth_codes', function (Blueprint $t) {
            $t->string('id', 100)->primary();
            $t->string('user_id', 128);
            $t->string('client_id', 64)->index();
            $t->json('scopes');
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at');
            $t->string('nonce')->nullable();
            $t->string('sid', 64)->nullable();
            $t->timestamp('auth_time')->nullable();
        });

        Schema::create('oidc_access_tokens', function (Blueprint $t) {
            $t->string('id', 100)->primary();
            $t->string('user_id', 128)->nullable()->index();
            $t->string('client_id', 64)->index();
            $t->json('scopes');
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at');
            $t->string('sid', 64)->nullable()->index();
            $t->timestamp('created_at')->nullable();
        });

        Schema::create('oidc_refresh_tokens', function (Blueprint $t) {
            $t->string('id', 100)->primary();
            $t->string('access_token_id', 100)->index();
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at');
        });

        Schema::create('pairings', function (Blueprint $t) {
            $t->string('id', 64)->primary(); // von Dash vergeben
            $t->string('state', 24)->index(); // requested | dash_approved | active | rejected | expired | cancelled | failed
            $t->string('installation_id', 128)->index();
            $t->string('name');
            $t->string('domain');
            $t->string('version', 32)->nullable();
            $t->json('redirect_uris');
            $t->json('post_logout_uris')->nullable();
            $t->json('scopes');
            $t->text('tool_sign_public_key'); // Ed25519, base64
            $t->text('tool_box_public_key');  // X25519, base64 (Versiegelung der Zugangsdaten)
            $t->string('challenge', 64);
            $t->boolean('challenge_used')->default(false);
            $t->timestamp('expires_at')->index();
            $t->timestamp('dash_approved_at')->nullable();
            $t->timestamp('confirmed_at')->nullable();
            $t->string('client_id', 64)->nullable();
            $t->longText('sealed_credentials')->nullable();
            $t->timestamp('credentials_acked_at')->nullable();
            $t->string('failure_reason')->nullable();
            $t->timestamps();
        });

        Schema::create('api_nonces', function (Blueprint $t) {
            $t->string('nonce', 64)->primary();
            $t->string('key_id', 64);
            $t->timestamp('expires_at')->index();
        });

        Schema::create('bootstrap_admins', function (Blueprint $t) {
            $t->id();
            $t->string('username')->unique();
            $t->string('password_hash');
            $t->text('totp_secret_enc')->nullable();
            $t->timestamp('expires_at');
            $t->timestamp('disabled_at')->nullable();
            $t->string('disabled_reason')->nullable();
            $t->unsignedSmallInteger('failed_attempts')->default(0);
            $t->timestamp('locked_until')->nullable();
            $t->timestamps();
        });

        Schema::create('recovery_tokens', function (Blueprint $t) {
            $t->id();
            $t->string('token_hash', 64)->unique();
            $t->timestamp('expires_at');
            $t->timestamp('used_at')->nullable();
            $t->timestamps();
        });

        Schema::create('audit_logs', function (Blueprint $t) {
            $t->id();
            $t->string('event', 64)->index();
            $t->string('actor', 128)->nullable();
            $t->string('subject', 128)->nullable();
            $t->json('context')->nullable(); // nie Tokens, Geheimnisse oder Passwoerter
            $t->string('ip', 45)->nullable();
            $t->timestamp('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        foreach (['audit_logs', 'recovery_tokens', 'bootstrap_admins', 'api_nonces', 'pairings', 'oidc_refresh_tokens', 'oidc_access_tokens', 'oidc_auth_codes', 'sso_sessions', 'oidc_clients', 'signing_keys', 'settings', 'sessions'] as $t) {
            Schema::dropIfExists($t);
        }
    }
};
