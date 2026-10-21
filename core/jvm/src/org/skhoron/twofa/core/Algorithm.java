// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.util.Locale;

/** Алгоритмы HMAC, допустимые в TOTP/HOTP. */
public enum Algorithm {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512");

    /** Имя алгоритма для javax.crypto.Mac и для Android Keystore. */
    public final String jcaName;

    Algorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    public static Algorithm parse(String name) {
        switch (name.toUpperCase(Locale.ROOT)) {
            case "SHA1":
                return SHA1;
            case "SHA256":
                return SHA256;
            case "SHA512":
                return SHA512;
            default:
                throw new IllegalArgumentException("неподдерживаемый алгоритм: " + name);
        }
    }
}