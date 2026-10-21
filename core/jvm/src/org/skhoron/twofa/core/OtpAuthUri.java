// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Разбор otpauth:// (Key URI). Поведение совпадает с эталоном skhoron2fa/otpauth.py. */
public final class OtpAuthUri {
    /** Верхняя граница длины входной строки; совпадает с MAX_URI_LENGTH в эталоне. */
    public static final int MAX_URI_LENGTH = 2048;

    public final String type;
    public final String issuer;
    public final String account;
    public final byte[] secret;
    public final Algorithm algorithm;
    public final int digits;
    public final int period;
    public final long counter;

    private OtpAuthUri(String type, String issuer, String account, byte[] secret,
                       Algorithm algorithm, int digits, int period, long counter) {
        this.type = type;
        this.issuer = issuer;
        this.account = account;
        this.secret = secret;
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
        this.counter = counter;
    }

    public static OtpAuthUri parse(String uri) {
        if (uri.length() > MAX_URI_LENGTH) {
            throw new IllegalArgumentException("слишком длинный URI");
        }
        String text = uri.trim();
        int hash = text.indexOf('#');
        if (hash >= 0) {
            text = text.substring(0, hash);
        }
        int schemeEnd = text.indexOf("://");
        if (schemeEnd < 0 || !text.substring(0, schemeEnd).equalsIgnoreCase("otpauth")) {
            throw new IllegalArgumentException("ожидается схема otpauth://");
        }
        String rest = text.substring(schemeEnd + 3);
        String queryText = "";
        int question = rest.indexOf('?');
        if (question >= 0) {
            queryText = rest.substring(question + 1);
            rest = rest.substring(0, question);
        }
        int slash = rest.indexOf('/');
        String host = (slash >= 0 ? rest.substring(0, slash) : rest).toLowerCase(Locale.ROOT);
        String rawLabel = slash >= 0 ? rest.substring(slash + 1) : "";
        if (!host.equals("totp") && !host.equals("hotp")) {
            throw new IllegalArgumentException("тип должен быть totp или hotp");
        }

        Map<String, String> query = new HashMap<>();
        for (String pair : queryText.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            String value = eq >= 0 ? pair.substring(eq + 1) : "";
            query.put(percentDecode(key, true).toLowerCase(Locale.ROOT), percentDecode(value, true));
        }

        if (!query.containsKey("secret")) {
            throw new IllegalArgumentException("нет параметра secret");
        }
        byte[] secret = Base32.decode(query.get("secret"));
        Algorithm algorithm = Algorithm.parse(query.getOrDefault("algorithm", "SHA1"));
        int digits = Integer.parseInt(query.getOrDefault("digits", "6"));
        Hotp.checkDigits(digits);
        int period = Integer.parseInt(query.getOrDefault("period", "30"));
        if (period <= 0) {
            throw new IllegalArgumentException("period должен быть положительным");
        }
        long counter = 0;
        if (host.equals("hotp")) {
            if (!query.containsKey("counter")) {
                throw new IllegalArgumentException("для hotp нужен counter");
            }
            counter = Long.parseLong(query.get("counter"));
            if (counter < 0) {
                throw new IllegalArgumentException("отрицательный counter");
            }
        }

        // Делим по первому ":" до раскодирования; если его нет - по первому %3A.
        String issuer = "";
        String account = percentDecode(rawLabel, false).trim();
        int separator = rawLabel.indexOf(':');
        int width = 1;
        if (separator < 0) {
            separator = rawLabel.toUpperCase(Locale.ROOT).indexOf("%3A");
            width = 3;
        }
        if (separator >= 0) {
            issuer = percentDecode(rawLabel.substring(0, separator), false).trim();
            account = percentDecode(rawLabel.substring(separator + width), false).trim();
        }
        String issuerParam = query.get("issuer");
        if (issuerParam != null && !issuerParam.isEmpty()) {
            issuer = issuerParam;
        }
        return new OtpAuthUri(host, issuer, account, secret, algorithm, digits, period, counter);
    }

    static String percentDecode(String text, boolean plusIsSpace) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            if (b == '%' && i + 2 < bytes.length && hex(bytes[i + 1]) >= 0 && hex(bytes[i + 2]) >= 0) {
                out.write(hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]));
                i += 2;
            } else if (b == '+' && plusIsSpace) {
                out.write(' ');
            } else {
                out.write(b);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static int hex(byte b) {
        if (b >= '0' && b <= '9') {
            return b - '0';
        }
        if (b >= 'a' && b <= 'f') {
            return b - 'a' + 10;
        }
        if (b >= 'A' && b <= 'F') {
            return b - 'A' + 10;
        }
        return -1;
    }
}