<?php

namespace App\Services\Vylaris;

/**
 * Ed25519-Signaturen fuer die Server-zu-Server-Kommunikation (log_in <-> Dash, Pairing-Nachweise).
 * Alle Schluessel und Signaturen sind Standard-Base64.
 */
final class Signer
{
    public const VERSION = 'VYLARIS-V1';

    /** @return array{public: string, secret: string} */
    public static function generateKeypair(): array
    {
        $kp = sodium_crypto_sign_keypair();

        return [
            'public' => base64_encode(sodium_crypto_sign_publickey($kp)),
            'secret' => base64_encode(sodium_crypto_sign_secretkey($kp)),
        ];
    }

    /** @return array{public: string, secret: string} X25519 fuer versiegelte Zugangsdaten */
    public static function generateBoxKeypair(): array
    {
        $kp = sodium_crypto_box_keypair();

        return [
            'public' => base64_encode(sodium_crypto_box_publickey($kp)),
            'secret' => base64_encode(sodium_crypto_box_secretkey($kp)),
        ];
    }

    public static function requestCanonical(string $method, string $pathWithQuery, int $timestamp, string $nonce, string $body): string
    {
        return implode("\n", [self::VERSION, strtoupper($method), $pathWithQuery, (string) $timestamp, $nonce, hash('sha256', $body)]);
    }

    /** Antwortsignatur ist an die Nonce der Anfrage gebunden (kein Antwort-Replay). */
    public static function responseCanonical(int $status, string $requestNonce, int $timestamp, string $body): string
    {
        return implode("\n", [self::VERSION.'-RESP', (string) $status, $requestNonce, (string) $timestamp, hash('sha256', $body)]);
    }

    public static function sign(string $message, string $secretKeyB64): string
    {
        $sk = base64_decode($secretKeyB64, true);
        if ($sk === false || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('Ungueltiger Signaturschluessel');
        }

        return base64_encode(sodium_crypto_sign_detached($message, $sk));
    }

    public static function verify(string $message, string $signatureB64, string $publicKeyB64): bool
    {
        $sig = base64_decode($signatureB64, true);
        $pk = base64_decode($publicKeyB64, true);
        if ($sig === false || $pk === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($sig, $message, $pk);
    }

    public static function fingerprint(string $publicKeyB64): string
    {
        $raw = base64_decode($publicKeyB64, true) ?: '';

        return strtoupper(implode(':', str_split(substr(hash('sha256', $raw), 0, 32), 4)));
    }

    public static function randomNonce(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    }

    /** Versiegelt Zugangsdaten fuer den Empfaenger (nur dessen privater Schluessel kann sie oeffnen). */
    public static function seal(string $plaintext, string $recipientBoxPublicB64): string
    {
        $pk = base64_decode($recipientBoxPublicB64, true);
        if ($pk === false || strlen($pk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException('Ungueltiger Box-Schluessel');
        }

        return base64_encode(sodium_crypto_box_seal($plaintext, $pk));
    }

    public static function unseal(string $sealedB64, string $boxSecretB64, string $boxPublicB64): ?string
    {
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey(base64_decode($boxSecretB64), base64_decode($boxPublicB64));
        $r = sodium_crypto_box_seal_open(base64_decode($sealedB64), $kp);

        return $r === false ? null : $r;
    }
}
