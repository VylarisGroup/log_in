<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('pairings', function (Blueprint $t) {
            $t->string('tool_id', 64)->nullable()->after('installation_id');
            $t->string('base_url', 255)->nullable()->after('domain');
            $t->json('approved_scopes')->nullable()->after('scopes');
        });
        Schema::table('oidc_clients', function (Blueprint $t) {
            $t->string('tool_id', 64)->nullable()->after('installation_id');
            $t->string('base_url', 255)->nullable()->after('domain');
        });
    }

    public function down(): void
    {
        Schema::table('oidc_clients', function (Blueprint $t) {
            $t->dropColumn(['tool_id', 'base_url']);
        });
        Schema::table('pairings', function (Blueprint $t) {
            $t->dropColumn(['tool_id', 'base_url', 'approved_scopes']);
        });
    }
};
