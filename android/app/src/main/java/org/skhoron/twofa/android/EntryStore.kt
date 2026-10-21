// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.skhoron.twofa.core.Algorithm

/** Метаданные записи. Секрета здесь нет: он только в Keystore под именем alias. */
data class StoredEntry(
    val alias: String,
    val issuer: String,
    val account: String,
    val algorithm: Algorithm,
    val digits: Int,
    val period: Int,
) {
    fun sameAccountAs(other: StoredEntry) = issuer.equals(other.issuer, ignoreCase = true) &&
        account.equals(other.account, ignoreCase = true) &&
        algorithm == other.algorithm && digits == other.digits && period == other.period
}

class EntryStore(context: Context) {
    /** problems > 0: список нельзя читать целиком (битый JSON или записи с ошибками). */
    data class Loaded(val entries: List<StoredEntry>, val problems: Int)

    private val prefs = context.getSharedPreferences("entries", Context.MODE_PRIVATE)

    fun load(): Loaded {
        val raw = prefs.getString(KEY, null) ?: return Loaded(emptyList(), 0)
        val array = try {
            JSONArray(raw)
        } catch (e: Exception) {
            return Loaded(emptyList(), 1)
        }
        val entries = ArrayList<StoredEntry>()
        var problems = 0
        for (i in 0 until array.length()) {
            val entry = try {
                parseItem(array.getJSONObject(i))
            } catch (e: Exception) {
                null
            }
            if (entry == null) problems++ else entries.add(entry)
        }
        return Loaded(entries, problems)
    }

    fun all(): List<StoredEntry> = load().entries

    /** false: запись не сохранена. При повреждённом списке не пишем, чтобы не затереть его. */
    fun add(entry: StoredEntry): Boolean {
        val loaded = load()
        return loaded.problems == 0 && save(loaded.entries + entry)
    }

    fun remove(alias: String): Boolean {
        val loaded = load()
        return loaded.problems == 0 && save(loaded.entries.filter { it.alias != alias })
    }

    private fun parseItem(o: JSONObject) = StoredEntry(
        o.getString("alias"), o.getString("issuer"), o.getString("account"),
        Algorithm.parse(o.getString("algorithm")), o.getInt("digits"), o.getInt("period"),
    )

    /** commit(), а не apply(): нужен результат записи, иначе сбой останется незамеченным. */
    private fun save(entries: List<StoredEntry>): Boolean {
        val array = JSONArray()
        entries.forEach {
            array.put(
                JSONObject()
                    .put("alias", it.alias).put("issuer", it.issuer).put("account", it.account)
                    .put("algorithm", it.algorithm.name).put("digits", it.digits).put("period", it.period),
            )
        }
        return prefs.edit().putString(KEY, array.toString()).commit()
    }

    private companion object {
        const val KEY = "list"
    }
}