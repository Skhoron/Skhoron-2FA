// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.android

import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import org.skhoron.twofa.core.OtpEntry
import org.skhoron.twofa.core.VaultExport
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * Резервная копия при добавлении аккаунта и восстановление из файла. Секрет после добавления на устройстве
 * не хранится, поэтому копию можно сделать только сейчас; Argon2id считается в фоновом потоке.
 */
class BackupController(
    private val activity: AppCompatActivity,
    private val onRestored: (List<OtpEntry>) -> Unit,
) {
    private val worker = Executors.newSingleThreadExecutor()
    private var pendingFile: ByteArray? = null

    private val createLauncher = activity.registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        val data = pendingFile
        pendingFile = null
        if (uri == null || data == null) {
            toast("Копия не сохранена")
        } else {
            try {
                activity.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(data) }
                toast("Копия сохранена")
            } catch (e: Exception) {
                toast("Не удалось записать файл: ${e.message}")
            }
        }
    }

    private val openLauncher = activity.registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) readAndAskPassword(uri)
    }

    /** Берёт на себя entries: после диалога секреты обнуляются. */
    fun offerBackup(entries: List<OtpEntry>) {
        showPasswordDialog(
            title = "Резервная копия: пароль для файла",
            confirm = true,
            onOk = { password -> encryptInBackground(entries, password) },
            onCancel = {
                entries.forEach { it.wipe() }
                toast("Копии нет: при потере телефона этот аккаунт не восстановить")
            },
        )
    }

    fun startRestore() = openLauncher.launch(arrayOf("*/*"))

    private fun encryptInBackground(entries: List<OtpEntry>, password: String) {
        toast("Шифрование, подождите несколько секунд")
        worker.execute {
            val result = runCatching {
                VaultExport.encrypt(entries, password, VaultExport.KdfParams.DEFAULT, SecureRandom())
            }
            activity.runOnUiThread {
                entries.forEach { it.wipe() }
                result.onSuccess { text ->
                    pendingFile = text.toByteArray(Charsets.UTF_8)
                    createLauncher.launch("Skhoron-2FA-" + System.currentTimeMillis() / 1000 + ".json")
                }.onFailure { toast("Не удалось зашифровать: ${it.message}") }
            }
        }
    }

    private fun readAndAskPassword(uri: android.net.Uri) {
        val text = try {
            val stream = activity.contentResolver.openInputStream(uri) ?: throw IOException("нет доступа к файлу")
            stream.use { String(readLimited(it, 1 shl 20), Charsets.UTF_8) }
        } catch (e: Exception) {
            toast("Не удалось прочитать файл: ${e.message}")
            return
        }
        showPasswordDialog(
            title = "Восстановление: пароль от файла",
            confirm = false,
            onOk = { password -> decryptInBackground(text, password) },
            onCancel = { },
        )
    }

    private fun decryptInBackground(text: String, password: String) {
        toast("Расшифровка, подождите несколько секунд")
        worker.execute {
            val result = runCatching { VaultExport.decrypt(text, password) }
            activity.runOnUiThread {
                result.onSuccess { onRestored(it) }.onFailure {
                    toast(
                        when (it) {
                            is GeneralSecurityException -> "Неверный пароль или файл повреждён"
                            is IllegalArgumentException -> "Файл не распознан: ${it.message}"
                            else -> "Ошибка: ${it.message}"
                        },
                    )
                }
            }
        }
    }

    private fun showPasswordDialog(title: String, confirm: Boolean, onOk: (String) -> Unit, onCancel: () -> Unit) {
        val first = passwordField("Пароль")
        val second = passwordField("Повторите пароль")
        val form = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
            addView(first)
            if (confirm) addView(second)
        }
        AlertDialog.Builder(activity)
            .setTitle(title)
            .setView(form)
            .setCancelable(false)
            .setPositiveButton("Продолжить") { _, _ ->
                val password = first.text.toString()
                when {
                    confirm && password.length < 8 -> {
                        toast("Пароль короче 8 символов")
                        showPasswordDialog(title, confirm, onOk, onCancel)
                    }
                    confirm && password != second.text.toString() -> {
                        toast("Пароли не совпали")
                        showPasswordDialog(title, confirm, onOk, onCancel)
                    }
                    password.isEmpty() -> onCancel()
                    else -> onOk(password)
                }
            }
            .setNegativeButton(if (confirm) "Пропустить" else "Отмена") { _, _ -> onCancel() }
            .show()
    }

    private fun passwordField(label: String) = EditText(activity).apply {
        hint = label
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun readLimited(stream: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = stream.read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > max) throw IOException("файл слишком большой")
        }
        return out.toByteArray()
    }

    private fun toast(message: String) = Toast.makeText(activity, message, Toast.LENGTH_LONG).show()
}