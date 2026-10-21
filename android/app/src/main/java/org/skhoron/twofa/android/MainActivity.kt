// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.android

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.skhoron.twofa.core.Algorithm
import org.skhoron.twofa.core.OtpAuthUri
import org.skhoron.twofa.core.OtpEntry
import org.skhoron.twofa.core.Totp
import java.security.GeneralSecurityException
import java.util.UUID

class MainActivity : SecureActivity() {
    private enum class AddResult { ADDED, DUPLICATE, FAILED }

    private lateinit var store: EntryStore
    private lateinit var gate: UnlockGate
    private lateinit var list: LinearLayout
    private val keys = KeystoreHmac()
    private val handler = Handler(Looper.getMainLooper())
    private var promptShown = false

    // registerForActivityResult допустим только до STARTED, поэтому контроллер создаётся при инициализации
    private val backup = BackupController(this) { entries -> restoreEntries(entries) }

    private val ticker = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = EntryStore(this)
        gate = UnlockGate(this)

        val input = EditText(this).apply { hint = "otpauth://totp/..." }
        val add = Button(this).apply {
            text = "Добавить"
            setOnClickListener {
                addFromUri(input.text.toString())
                input.text.clear()
            }
        }
        val restore = Button(this).apply {
            text = "Восстановить из копии"
            setOnClickListener { backup.startRestore() }
        }
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            addView(input, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            addView(add)
            addView(restore)
            addView(list)
        }
        setContentView(ScrollView(this).apply { addView(column) })
        reconcileKeys()
    }

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        handler.removeCallbacks(ticker)
        super.onPause()
    }

    /**
     * Удаляет ключи-сироты: ключ создан, а запись не сохранилась (сбой или завершение процесса между шагами).
     * Если список записей нельзя прочитать целиком, ничего не удаляем: иначе можно уничтожить живые ключи.
     */
    private fun reconcileKeys() {
        val loaded = store.load()
        if (loaded.problems > 0) {
            toast("Список записей повреждён: добавление и удаление отключены, ключи не тронуты")
            return
        }
        val known = loaded.entries.map { it.alias }.toSet()
        keys.aliases()
            .filter { it.startsWith(KeystoreHmac.ALIAS_PREFIX) && it !in known }
            .forEach { runCatching { keys.delete(it) } }
    }

    private fun addFromUri(text: String) {
        val parsed = try {
            OtpAuthUri.parse(text)
        } catch (e: IllegalArgumentException) {
            toast("Неверный URI: ${e.message}")
            return
        }
        try {
            addParsed(parsed)
        } finally {
            parsed.secret.fill(0)
        }
    }

    private fun addParsed(parsed: OtpAuthUri) {
        if (parsed.type != "totp") {
            toast("HOTP пока не поддерживается")
            return
        }
        val result = addEntry(parsed.issuer, parsed.account, parsed.secret, parsed.algorithm, parsed.digits, parsed.period, true)
        // Секрет дальше нигде не хранится: копию можно сделать только сейчас. Контроллер обнулит свою копию.
        if (result == AddResult.ADDED) backup.offerBackup(listOf(OtpEntry.from(parsed)))
    }

    /** Секреты восстановленных записей обнуляются здесь. */
    private fun restoreEntries(entries: List<OtpEntry>) {
        var added = 0
        var duplicates = 0
        var failed = 0
        for (entry in entries) {
            try {
                if (entry.type != "totp") {
                    failed++
                    continue
                }
                when (addEntry(entry.issuer, entry.account, entry.secret, entry.algorithm, entry.digits, entry.period, false)) {
                    AddResult.ADDED -> added++
                    AddResult.DUPLICATE -> duplicates++
                    AddResult.FAILED -> failed++
                }
            } finally {
                entry.wipe()
            }
        }
        toast("Восстановлено: $added, уже были: $duplicates, не добавлено (в т.ч. HOTP): $failed")
    }

    private fun addEntry(
        issuer: String,
        account: String,
        secret: ByteArray,
        algorithm: Algorithm,
        digits: Int,
        period: Int,
        notify: Boolean,
    ): AddResult {
        val loaded = store.load()
        if (loaded.problems > 0) {
            if (notify) toast("Список записей повреждён: добавление отключено")
            return AddResult.FAILED
        }
        val entry = StoredEntry(KeystoreHmac.ALIAS_PREFIX + UUID.randomUUID(), issuer, account, algorithm, digits, period)
        if (loaded.entries.any { it.sameAccountAs(entry) }) {
            if (notify) toast("Такая запись уже есть")
            return AddResult.DUPLICATE
        }
        var keyCreated = false
        try {
            keys.importSecret(entry.alias, secret, entry.algorithm, UnlockMode.TIMED)
            keyCreated = true
            check(store.add(entry)) { "не удалось сохранить запись" }
        } catch (e: Exception) {
            if (keyCreated) runCatching { keys.delete(entry.alias) }
            if (notify) toast("Не добавлено: ${e.message}")
            return AddResult.FAILED
        }
        if (notify) {
            val level = runCatching { keys.securityLevel(entry.alias) }.getOrDefault("уровень неизвестен")
            toast("Ключ сохранён: $level")
        }
        return AddResult.ADDED
    }

    private fun render() {
        list.removeAllViews()
        val now = System.currentTimeMillis() / 1000
        for (entry in store.all()) {
            val code = codeFor(entry, now)
            val left = Totp.secondsRemaining(now, entry.period)
            list.addView(
                TextView(this).apply {
                    textSize = 18f
                    setPadding(0, 24, 0, 24)
                    text = "${entry.issuer} ${entry.account}\n${code ?: "••• •••"}  ($left с)"
                    setOnLongClickListener {
                        // Сначала запись, потом ключ: сбой между шагами оставит сироту, которую уберёт reconcileKeys().
                        if (store.remove(entry.alias)) {
                            runCatching { keys.delete(entry.alias) }
                        } else {
                            toast("Не удалось удалить запись")
                        }
                        true
                    }
                },
            )
        }
    }

    private fun codeFor(entry: StoredEntry, now: Long): String? = try {
        val raw = Totp.generate(keys.hmacFor(entry.alias, entry.algorithm), now, entry.period, entry.digits)
        val half = (raw.length + 1) / 2
        raw.substring(0, half) + " " + raw.substring(half)
    } catch (e: UserNotAuthenticatedException) {
        requestUnlock()
        null
    } catch (e: KeyPermanentlyInvalidatedException) {
        "ключ недействителен"
    } catch (e: NoSuchElementException) {
        "ключ отсутствует"
    } catch (e: GeneralSecurityException) {
        "ошибка: ${e.javaClass.simpleName}"
    }

    private fun requestUnlock() {
        if (promptShown) return
        promptShown = true
        gate.unlockTimed {
            promptShown = false
            if (it) render()
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}