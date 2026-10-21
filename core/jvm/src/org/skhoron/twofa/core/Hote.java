// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

/** Динамическое усечение из RFC 4226. HMAC считает вызывающая сторона (в Android - Keystore). */
public final class Hotp {
    private Hotp() {
    }

    public static void checkDigits(int digits) {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("digits должно быть 6, 7 или 8");
        }
    }

    public static byte[] counterBytes(long counter) {
        if (counter < 0) {
            throw new IllegalArgumentException("отрицательный счётчик");
        }
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }
        return out;
    }

    public static String code(byte[] hmac, int digits) {
        checkDigits(digits);
        int offset = hmac[hmac.length - 1] & 0x0F;
        int binary = ((hmac[offset] & 0x7F) << 24)
                | ((hmac[offset + 1] & 0xFF) << 16)
                | ((hmac[offset + 2] & 0xFF) << 8)
                | (hmac[offset + 3] & 0xFF);
        int modulus = 1;
        for (int i = 0; i < digits; i++) {
            modulus *= 10;
        }
        StringBuilder text = new StringBuilder(Integer.toString(binary % modulus));
        while (text.length() < digits) {
            text.insert(0, '0');
        }
        return text.toString();
    }
}