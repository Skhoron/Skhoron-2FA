// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.android

import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import javax.crypto.Mac

class UnlockGate(private val activity: AppCompatActivity) {
    private val executor = ContextCompat.getMainExecutor(activity)

    /** Для TIMED-ключей: CryptoObject не нужен, Keystore сам откроет ключ на заданное время. */
    fun unlockTimed(onDone: (Boolean) -> Unit) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Разблокировка Skhoron-2FA")
            // С DEVICE_CREDENTIAL кнопку "Отмена" задавать нельзя.
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            .build()
        BiometricPrompt(activity, executor, callback { onDone(it != null) }).authenticate(info)
    }

    /** Для EVERY_USE-ключей: Mac, уже инициализированный ключом, оборачивается в CryptoObject. */
    fun authorizeMac(mac: Mac, onDone: (Mac?) -> Unit) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Подтвердите код")
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Отмена")
            .build()
        BiometricPrompt(activity, executor, callback { onDone(it?.cryptoObject?.mac) })
            .authenticate(info, BiometricPrompt.CryptoObject(mac))
    }

    private fun callback(onDone: (BiometricPrompt.AuthenticationResult?) -> Unit) =
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onDone(result)

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onDone(null)
        }
}