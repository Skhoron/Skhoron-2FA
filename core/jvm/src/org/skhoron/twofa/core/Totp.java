// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** TOTP (RFC 6238). Источник HMAC подключаемый: программный ключ или ключ из Android Keystore. */
public final class Totp {
    private Totp() {
    }

    /** Считает HMAC от сообщения. Для Keystore-ключей должна создавать и инициализировать Mac на каждый вызов. */
    public interface HmacFunction {
        byte[] mac(byte[] message) throws GeneralSecurityException;
    }

    public static String generate(HmacFunction hmac, long unixSeconds, int period, int digits)
            throws GeneralSecurityException {
        if (period <= 0) {
            throw new IllegalArgumentException("period должен быть положительным");
        }
        Hotp.checkDigits(digits);
        long counter = Math.floorDiv(unixSeconds, (long) period);
        return Hotp.code(hmac.mac(Hotp.counterBytes(counter)), digits);
    }

    public static int secondsRemaining(long unixSeconds, int period) {
        if (period <= 0) {
            throw new IllegalArgumentException("period должен быть положительным");
        }
        return period - (int) Math.floorMod(unixSeconds, (long) period);
    }

    /** Программный HMAC: для тестов и платформ без аппаратного хранилища. */
    public static HmacFunction softwareHmac(Algorithm algorithm, byte[] secret) {
        if (secret.length == 0) {
            throw new IllegalArgumentException("пустой секрет");
        }
        byte[] copy = secret.clone();
        return message -> {
            Mac mac = Mac.getInstance(algorithm.jcaName);
            mac.init(new SecretKeySpec(copy, algorithm.jcaName));
            return mac.doFinal(message);
        };
    }
}