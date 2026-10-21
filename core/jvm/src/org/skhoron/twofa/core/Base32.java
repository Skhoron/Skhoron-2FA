// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.io.ByteArrayOutputStream;

/** Base32 (RFC 4648) с допусками: пробелы, дефисы, нижний регистр, отсутствие "=". */
public final class Base32 {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32() {
    }

    public static byte[] decode(String text) {
        StringBuilder clean = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c) || c == '-' || c == '=') {
                continue;
            }
            clean.append(Character.toUpperCase(c));
        }
        int length = clean.length();
        if (length == 0) {
            throw new IllegalArgumentException("пустой base32");
        }
        int mod = length % 8;
        if (mod == 1 || mod == 3 || mod == 6) {
            throw new IllegalArgumentException("недопустимая длина base32");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < length; i++) {
            int index = ALPHABET.indexOf(clean.charAt(i));
            if (index < 0) {
                throw new IllegalArgumentException("недопустимый символ base32");
            }
            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
                buffer &= (1 << bits) - 1;
            }
        }
        return out.toByteArray();
    }

    public static String encode(byte[] data) {
        StringBuilder out = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(ALPHABET.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0) {
            out.append(ALPHABET.charAt((buffer << (5 - bits)) & 31));
        }
        return out.toString();
    }
}