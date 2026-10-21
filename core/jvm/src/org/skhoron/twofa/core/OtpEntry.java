// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.util.Arrays;
import java.util.Locale;

/** Запись аккаунта вместе с секретом. Нужна только в момент добавления, экспорта и восстановления. */
public final class OtpEntry {
    public final String type;
    public final String issuer;
    public final String account;
    public final byte[] secret;
    public final Algorithm algorithm;
    public final int digits;
    public final int period;
    public final long counter;

    public OtpEntry(String type, String issuer, String account, byte[] secret,
                    Algorithm algorithm, int digits, int period, long counter) {
        if (!type.equals("totp") && !type.equals("hotp")) {
            throw new IllegalArgumentException("тип должен быть totp или hotp");
        }
        Hotp.checkDigits(digits);
        if (period <= 0) {
            throw new IllegalArgumentException("period должен быть положительным");
        }
        if (counter < 0) {
            throw new IllegalArgumentException("отрицательный counter");
        }
        if (secret.length == 0) {
            throw new IllegalArgumentException("пустой секрет");
        }
        this.type = type;
        this.issuer = issuer;
        this.account = account;
        this.secret = secret;
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
        this.counter = counter;
    }

    /** Копирует секрет: исходный OtpAuthUri можно обнулять независимо. */
    public static OtpEntry from(OtpAuthUri uri) {
        return new OtpEntry(uri.type, uri.issuer, uri.account, uri.secret.clone(),
                uri.algorithm, uri.digits, uri.period, uri.counter);
    }

    public String dedupeKey() {
        StringBuilder key = new StringBuilder();
        key.append(type).append('|').append(issuer.toLowerCase(Locale.ROOT)).append('|')
                .append(account.toLowerCase(Locale.ROOT)).append('|').append(Base32.encode(secret)).append('|')
                .append(algorithm.name()).append('|').append(digits).append('|').append(period);
        return key.toString();
    }

    public void wipe() {
        Arrays.fill(secret, (byte) 0);
    }
}