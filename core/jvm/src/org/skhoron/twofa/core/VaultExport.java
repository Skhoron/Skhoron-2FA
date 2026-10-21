// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Зашифрованный экспорт v1 (docs/EXPORT_FORMAT.md): Argon2id + AES-256-GCM.
 * Совместим с эталоном core/reference-python/skhoron2fa/vault.py. Читает строже эталона:
 * неизвестные поля заголовка отклоняются, nonce только 12 байт, соль от 8 байт.
 */
public final class VaultExport {
    public static final String FORMAT = "skhoron-2fa-export";
    public static final int VERSION = 1;
    static final int MAX_FILE_CHARS = 1 << 20;
    static final int MAX_MEMORY_KIB = 262144;
    static final int MAX_ITERATIONS = 10;
    static final int MAX_LANES = 16;

    private VaultExport() {
    }

    public static final class KdfParams {
        public static final KdfParams DEFAULT = new KdfParams(3, 65536, 4);

        public final int iterations;
        public final int memoryKib;
        public final int lanes;

        public KdfParams(int iterations, int memoryKib, int lanes) {
            checkBounds(iterations, memoryKib, lanes);
            this.iterations = iterations;
            this.memoryKib = memoryKib;
            this.lanes = lanes;
        }
    }

    private static void checkBounds(long iterations, long memoryKib, long lanes) {
        if (lanes < 1 || lanes > MAX_LANES || iterations < 1 || iterations > MAX_ITERATIONS
                || memoryKib > MAX_MEMORY_KIB || memoryKib < 8 * lanes) {
            throw new IllegalArgumentException("параметры KDF вне допустимых границ");
        }
    }

    public static String encrypt(List<OtpEntry> entries, String password, KdfParams params, SecureRandom random)
            throws GeneralSecurityException {
        if (password.isEmpty()) {
            throw new IllegalArgumentException("пустой пароль");
        }
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        random.nextBytes(salt);
        random.nextBytes(nonce);
        String saltText = Base64.getEncoder().encodeToString(salt);
        String nonceText = Base64.getEncoder().encodeToString(nonce);
        byte[] key = deriveKey(password, salt, params.iterations, params.memoryKib, params.lanes);
        byte[] plain = plaintext(entries).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] sealed = crypt(Cipher.ENCRYPT_MODE, key, nonce, aad(nonceText, params.iterations,
                    params.memoryKib, params.lanes, saltText), plain);
            return "{\n"
                    + "  \"format\": \"" + FORMAT + "\",\n"
                    + "  \"version\": " + VERSION + ",\n"
                    + "  \"kdf\": {\n"
                    + "    \"name\": \"argon2id\",\n"
                    + "    \"salt\": \"" + saltText + "\",\n"
                    + "    \"iterations\": " + params.iterations + ",\n"
                    + "    \"memory_kib\": " + params.memoryKib + ",\n"
                    + "    \"lanes\": " + params.lanes + "\n"
                    + "  },\n"
                    + "  \"cipher\": {\n"
                    + "    \"name\": \"aes-256-gcm\",\n"
                    + "    \"nonce\": \"" + nonceText + "\"\n"
                    + "  },\n"
                    + "  \"ciphertext\": \"" + Base64.getEncoder().encodeToString(sealed) + "\"\n"
                    + "}\n";
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Неверный пароль или испорченные данные дают javax.crypto.AEADBadTagException. */
    public static List<OtpEntry> decrypt(String text, String password) throws GeneralSecurityException {
        if (text.length() > MAX_FILE_CHARS) {
            throw new IllegalArgumentException("файл слишком большой");
        }
        Map<String, Object> root = asObject(Json.parse(text), "корень");
        requireKeys(root, "format", "version", "kdf", "cipher", "ciphertext");
        if (!FORMAT.equals(root.get("format")) || !Long.valueOf(VERSION).equals(root.get("version"))) {
            throw new IllegalArgumentException("неизвестный формат или версия файла");
        }
        Map<String, Object> kdf = asObject(root.get("kdf"), "kdf");
        Map<String, Object> cipher = asObject(root.get("cipher"), "cipher");
        requireKeys(kdf, "name", "salt", "iterations", "memory_kib", "lanes");
        requireKeys(cipher, "name", "nonce");
        if (!"argon2id".equals(kdf.get("name")) || !"aes-256-gcm".equals(cipher.get("name"))) {
            throw new IllegalArgumentException("неподдерживаемые алгоритмы в файле");
        }
        long iterations = number(kdf, "iterations");
        long memoryKib = number(kdf, "memory_kib");
        long lanes = number(kdf, "lanes");
        checkBounds(iterations, memoryKib, lanes);
        String saltText = string(kdf, "salt");
        String nonceText = string(cipher, "nonce");
        byte[] salt = Base64.getDecoder().decode(saltText);
        byte[] nonce = Base64.getDecoder().decode(nonceText);
        byte[] sealed = Base64.getDecoder().decode(string(root, "ciphertext"));
        if (salt.length < 8 || nonce.length != 12 || sealed.length < 16) {
            throw new IllegalArgumentException("неверные размеры соли, nonce или данных");
        }
        byte[] key = deriveKey(password, salt, (int) iterations, (int) memoryKib, (int) lanes);
        byte[] plain = null;
        try {
            plain = crypt(Cipher.DECRYPT_MODE, key, nonce,
                    aad(nonceText, (int) iterations, (int) memoryKib, (int) lanes, saltText), sealed);
            return parseEntries(new String(plain, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(key, (byte) 0);
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    /** Заголовок без ciphertext: ключи по алфавиту, без пробелов (как json.dumps(sort_keys) в эталоне). */
    private static byte[] aad(String nonce, int iterations, int memoryKib, int lanes, String salt) {
        String json = "{\"cipher\":{\"name\":\"aes-256-gcm\",\"nonce\":\"" + nonce + "\"},"
                + "\"format\":\"" + FORMAT + "\","
                + "\"kdf\":{\"iterations\":" + iterations + ",\"lanes\":" + lanes
                + ",\"memory_kib\":" + memoryKib + ",\"name\":\"argon2id\",\"salt\":\"" + salt + "\"},"
                + "\"version\":" + VERSION + "}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] deriveKey(String password, byte[] salt, int iterations, int memoryKib, int lanes) {
        byte[] pw = Normalizer.normalize(password, Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
        try {
            return Argon2id.hash(pw, salt, iterations, memoryKib, lanes, 32, new byte[0], new byte[0]);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(data);
    }

    static String plaintext(List<OtpEntry> entries) {
        StringBuilder b = new StringBuilder("{\"entries\":[");
        for (int i = 0; i < entries.size(); i++) {
            OtpEntry e = entries.get(i);
            if (i > 0) {
                b.append(',');
            }
            b.append("{\"type\":").append(Json.quote(e.type))
                    .append(",\"issuer\":").append(Json.quote(e.issuer))
                    .append(",\"account\":").append(Json.quote(e.account))
                    .append(",\"secret\":").append(Json.quote(Base32.encode(e.secret)))
                    .append(",\"algorithm\":").append(Json.quote(e.algorithm.name()))
                    .append(",\"digits\":").append(e.digits)
                    .append(",\"period\":").append(e.period)
                    .append(",\"counter\":").append(e.counter).append('}');
        }
        return b.append("]}").toString();
    }

    static List<OtpEntry> parseEntries(String plainJson) {
        Map<String, Object> root = asObject(Json.parse(plainJson), "содержимое");
        requireKeys(root, "entries");
        List<Object> items = asList(root.get("entries"));
        List<OtpEntry> result = new ArrayList<>();
        for (Object item : items) {
            Map<String, Object> o = asObject(item, "запись");
            requireKeys(o, "type", "issuer", "account", "secret", "algorithm", "digits", "period", "counter");
            result.add(new OtpEntry(string(o, "type"), string(o, "issuer"), string(o, "account"),
                    Base32.decode(string(o, "secret")), Algorithm.parse(string(o, "algorithm")),
                    (int) number(o, "digits"), (int) number(o, "period"), number(o, "counter")));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value, String what) {
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException(what + ": ожидался объект");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object value) {
        if (!(value instanceof List)) {
            throw new IllegalArgumentException("ожидался массив");
        }
        return (List<Object>) value;
    }

    private static void requireKeys(Map<String, Object> map, String... names) {
        if (map.size() != names.length) {
            throw new IllegalArgumentException("неожиданный набор полей");
        }
        for (String name : names) {
            if (!map.containsKey(name)) {
                throw new IllegalArgumentException("нет поля " + name);
            }
        }
    }

    private static String string(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (!(v instanceof String)) {
            throw new IllegalArgumentException("поле " + key + " должно быть строкой");
        }
        return (String) v;
    }

    private static long number(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (!(v instanceof Long)) {
            throw new IllegalArgumentException("поле " + key + " должно быть целым числом");
        }
        return (Long) v;
    }
}