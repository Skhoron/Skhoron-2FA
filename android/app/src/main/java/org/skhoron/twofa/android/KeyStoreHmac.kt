// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.android

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.security.keystore.StrongBoxUnavailableException
import org.skhoron.twofa.core.Algorithm
import org.skhoron.twofa.core.Totp
import java.security.KeyStore
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec

enum class UnlockMode {
    /** Один успешный вход открывает ключ на timedSeconds секунд. */
    TIMED,

    /** Каждое использование ключа требует биометрию через BiometricPrompt.CryptoObject. */
    EVERY_USE,
}

/**
 * Секрет TOTP живёт только как HMAC-ключ в Android Keystore. Приложение не может его прочитать
 * после импорта: наружу выходит только результат HMAC.
 */
class KeystoreHmac(private val timedSeconds: Int = 60) {
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun importSecret(alias: String, secret: ByteArray, algorithm: Algorithm, mode: UnlockMode) {
        val key = SecretKeySpec(secret, algorithm.jcaName)
        // По документации Android, StrongBox поддерживает только HMAC-SHA256 с ключом 8..64 байта.
        // Для SHA-1/SHA-512 пробовать StrongBox бессмысленно - сразу обычное хранилище.
        if (algorithm == Algorithm.SHA256 && secret.size in 8..64) {
            try {
                store(alias, key, algorithm, mode, strongBox = true)
                return
            } catch (e: Exception) {
                if (!isStrongBoxUnavailable(e)) throw e
            }
        }
        store(alias, key, algorithm, mode, strongBox = false)
    }

    fun newMac(alias: String, algorithm: Algorithm): Mac {
        val key = keyStore.getKey(alias, null) ?: throw NoSuchElementException("нет ключа $alias")
        // init может бросить UserNotAuthenticatedException (TIMED, окно истекло)
        // или KeyPermanentlyInvalidatedException (EVERY_USE, добавлен новый отпечаток).
        return Mac.getInstance(algorithm.jcaName).apply { init(key) }
    }

    /** Новый Mac на каждый вызов: операция Keystore одноразовая. */
    fun hmacFor(alias: String, algorithm: Algorithm) =
        Totp.HmacFunction { message -> newMac(alias, algorithm).doFinal(message) }

    fun delete(alias: String) = keyStore.deleteEntry(alias)

    fun aliases(): List<String> = keyStore.aliases().toList()

    /** Где реально лежит ключ: StrongBox, TEE или программно. */
    fun securityLevel(alias: String): String {
        val key = keyStore.getKey(alias, null) as SecretKey
        val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "программно"
                else -> "неизвестно"
            }
        }
        @Suppress("DEPRECATION")
        val insideHardware = info.isInsideSecureHardware
        return if (insideHardware) "аппаратное" else "программно"
    }

    private fun store(alias: String, key: SecretKey, algorithm: Algorithm, mode: UnlockMode, strongBox: Boolean) {
        val builder = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            .setDigests(digestOf(algorithm)) // для HMAC допустим ровно один digest
            .setUserAuthenticationRequired(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
        when (mode) {
            UnlockMode.TIMED -> builder.setUserAuthenticationParameters(
                timedSeconds,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            UnlockMode.EVERY_USE -> builder
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                // Действует только для ключей с авторизацией на каждое использование.
                .setInvalidatedByBiometricEnrollment(true)
        }
        keyStore.setEntry(alias, KeyStore.SecretKeyEntry(key), builder.build())
    }

    private fun digestOf(algorithm: Algorithm) = when (algorithm) {
        Algorithm.SHA1 -> KeyProperties.DIGEST_SHA1
        Algorithm.SHA256 -> KeyProperties.DIGEST_SHA256
        Algorithm.SHA512 -> KeyProperties.DIGEST_SHA512
    }

    private fun isStrongBoxUnavailable(e: Throwable) =
        e is StrongBoxUnavailableException || e.cause is StrongBoxUnavailableException

    companion object {
        /** Все наши ключи начинаются с этого префикса; по нему ищутся ключи-сироты. */
        const val ALIAS_PREFIX = "otp."
        private const val PROVIDER = "AndroidKeyStore"
    }
}