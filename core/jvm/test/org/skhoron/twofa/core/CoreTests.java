// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/** Тесты без внешних зависимостей. Запуск: java tools/run-jvm-tests.java */
public final class CoreTests {
    private static int passed;
    private static int failed;

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
        } else {
            failed++;
            System.out.println("ПРОВАЛ: " + name);
        }
    }

    private static void equal(String name, Object expected, Object actual) {
        boolean ok = expected.equals(actual);
        if (!ok) {
            System.out.println("  ожидалось " + expected + ", получено " + actual);
        }
        check(name, ok);
    }

    private static void rejects(String name, Runnable action) {
        try {
            action.run();
            check(name + " (должно быть исключение)", false);
        } catch (IllegalArgumentException expected) {
            check(name, true);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static List<String> rows(Path file) throws Exception {
        return Files.readAllLines(file, StandardCharsets.UTF_8).stream()
                .filter(l -> !l.isBlank() && !l.startsWith("#")).toList();
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void throwsOf(String name, Class<? extends Throwable> kind, Action action) {
        try {
            action.run();
            check(name + " (должно быть исключение)", false);
        } catch (Throwable t) {
            boolean ok = kind.isInstance(t);
            if (!ok) {
                System.out.println("  получено " + t);
            }
            check(name, ok);
        }
    }

    private static List<OtpEntry> entriesFrom(Path file) throws Exception {
        return VaultExport.parseEntries(Files.readString(file, StandardCharsets.UTF_8));
    }

    private static boolean sameEntries(List<OtpEntry> a, List<OtpEntry> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            OtpEntry x = a.get(i);
            OtpEntry y = b.get(i);
            if (!x.dedupeKey().equals(y.dedupeKey()) || x.counter != y.counter
                    || !x.issuer.equals(y.issuer) || !x.account.equals(y.account)) {
                return false;
            }
        }
        return true;
    }

    private static void extra(Path vectors, String outDir) throws Exception {
        HexFormat hex = HexFormat.of();

        int blake = 0;
        for (String line : rows(vectors.resolve("blake2b.tsv"))) {
            String[] f = line.split("\\t", -1);
            equal("blake2b " + blake, f[2], hex.formatHex(Blake2b.hash(Integer.parseInt(f[0]), hex.parseHex(f[1]))));
            blake++;
        }
        check("blake2b: векторов не меньше 50", blake >= 50);

        int argon = 0;
        for (String line : rows(vectors.resolve("argon2id.tsv"))) {
            String[] f = line.split("\\t", -1);
            long started = System.nanoTime();
            byte[] got = Argon2id.hash(hex.parseHex(f[0]), hex.parseHex(f[1]), Integer.parseInt(f[4]),
                    Integer.parseInt(f[5]), Integer.parseInt(f[6]), Integer.parseInt(f[7]),
                    hex.parseHex(f[2]), hex.parseHex(f[3]));
            equal("argon2id " + argon + " t=" + f[4] + " m=" + f[5] + " p=" + f[6] + " len=" + f[7],
                    f[8], hex.formatHex(got));
            if (Integer.parseInt(f[5]) >= 65536) {
                System.out.println("  argon2id m=" + f[5] + " t=" + f[4] + " p=" + f[6] + ": "
                        + (System.nanoTime() - started) / 1_000_000 + " мс");
            }
            argon++;
        }
        check("argon2id: векторов не меньше 12", argon >= 12);
        rejects("argon2id: короткая соль", () -> Argon2id.hash(new byte[1], new byte[7], 1, 8, 1, 32, new byte[0], new byte[0]));
        rejects("argon2id: memory < 8*lanes", () -> Argon2id.hash(new byte[1], new byte[8], 1, 15, 2, 32, new byte[0], new byte[0]));

        Object parsed = Json.parse("{\"a\":[1,-2,\"x\\u0041\\n\\\"\",true,null,{\"b\":{}}]}");
        check("json: объект", parsed instanceof java.util.Map);
        List<?> list = (List<?>) ((java.util.Map<?, ?>) parsed).get("a");
        equal("json: число", 1L, list.get(0));
        equal("json: отрицательное", -2L, list.get(1));
        equal("json: строка с экранированием", "xA\n\"", list.get(2));
        equal("json: true", Boolean.TRUE, list.get(3));
        check("json: null", list.get(4) == null);
        equal("json: quote", "\"a\\\"b\\\\c\\n\\u0001\"", Json.quote("a\"b\\c\n\u0001"));
        String[] badJson = {"{\"a\":1,\"a\":2}", "{\"a\":1} x", "{\"a\":1.5}", "{\"a\":01}", "[", "{\"a\":\"\\x\"}",
            "{\"a\":\"line\nbreak\"}", "{\"a\":-}", "[".repeat(17) + "1" + "]".repeat(17), "{\"a\":1e5}", ""};
        for (String bad : badJson) {
            rejects("json отклонён: " + bad.replace("\n", "\\n"), () -> Json.parse(bad));
        }

        String pyFile = Files.readString(vectors.resolve("export_python.json"), StandardCharsets.UTF_8);
        List<OtpEntry> expected = entriesFrom(vectors.resolve("export_expected.json"));
        String password = "пароль-тест";
        check("Java читает файл, созданный Python", sameEntries(VaultExport.decrypt(pyFile, password), expected));
        throwsOf("файл Python, неверный пароль", javax.crypto.AEADBadTagException.class,
                () -> VaultExport.decrypt(pyFile, password + "x"));
        String lanes = pyFile.replace("\"lanes\": 2", "\"lanes\": 3");
        check("правка lanes применилась", !lanes.equals(pyFile));
        throwsOf("lanes изменён: ключ другой", javax.crypto.AEADBadTagException.class, () -> VaultExport.decrypt(lanes, password));
        int at = pyFile.indexOf("\"ciphertext\": \"") + 15;
        char flipped = pyFile.charAt(at) == 'A' ? 'B' : 'A';
        String tampered = pyFile.substring(0, at) + flipped + pyFile.substring(at + 1);
        throwsOf("шифртекст изменён", javax.crypto.AEADBadTagException.class, () -> VaultExport.decrypt(tampered, password));
        String extraField = pyFile.replace("\"version\": 1,", "\"version\": 1,\n  \"extra\": 1,");
        check("добавление поля применилось", !extraField.equals(pyFile));
        throwsOf("лишнее поле заголовка", IllegalArgumentException.class, () -> VaultExport.decrypt(extraField, password));
        String hugeMemory = pyFile.replace("\"memory_kib\": 1024", "\"memory_kib\": 10000000");
        check("правка memory применилась", !hugeMemory.equals(pyFile));
        throwsOf("memory вне границ", IllegalArgumentException.class, () -> VaultExport.decrypt(hugeMemory, password));
        String otherVersion = pyFile.replace("\"version\": 1", "\"version\": 2");
        throwsOf("версия 2", IllegalArgumentException.class, () -> VaultExport.decrypt(otherVersion, password));
        throwsOf("слишком большой файл", IllegalArgumentException.class,
                () -> VaultExport.decrypt(" ".repeat(VaultExport.MAX_FILE_CHARS + 1), password));

        VaultExport.KdfParams fast = new VaultExport.KdfParams(2, 1024, 2);
        String mine = VaultExport.encrypt(expected, password, fast, new SecureRandom());
        String mineAgain = VaultExport.encrypt(expected, password, fast, new SecureRandom());
        check("Java: шифрование и расшифровка", sameEntries(VaultExport.decrypt(mine, password), expected));
        check("Java: каждый файл со своей солью и nonce", !mine.equals(mineAgain));
        java.util.Map<?, ?> first = (java.util.Map<?, ?>) Json.parse(mine);
        java.util.Map<?, ?> second = (java.util.Map<?, ?>) Json.parse(mineAgain);
        check("Java: nonce не повторяется",
                !((java.util.Map<?, ?>) first.get("cipher")).get("nonce").equals(((java.util.Map<?, ?>) second.get("cipher")).get("nonce")));
        check("Java: соль не повторяется",
                !((java.util.Map<?, ?>) first.get("kdf")).get("salt").equals(((java.util.Map<?, ?>) second.get("kdf")).get("salt")));
        check("Java: секрет не виден в файле", !mine.contains(Base32.encode(expected.get(0).secret)) && !mine.contains("alice"));
        throwsOf("Java: неверный пароль", javax.crypto.AEADBadTagException.class, () -> VaultExport.decrypt(mine, "другой"));
        throwsOf("Java: пустой пароль", IllegalArgumentException.class, () -> VaultExport.encrypt(expected, "", fast, new SecureRandom()));
        check("Java: нормализация NFKC пароля",
                sameEntries(VaultExport.decrypt(VaultExport.encrypt(expected, "caf\u00e9", fast, new SecureRandom()), "cafe\u0301"), expected));
        rejects("KdfParams: iterations=0", () -> new VaultExport.KdfParams(0, 1024, 1));
        rejects("KdfParams: memory слишком большая", () -> new VaultExport.KdfParams(1, 10_000_000, 1));
        rejects("KdfParams: lanes=17", () -> new VaultExport.KdfParams(1, 4096, 17));
        if (outDir != null) {
            Files.writeString(Path.of(outDir, "java_export.json"), mine, StandardCharsets.UTF_8);
        }
    }

    public static void main(String[] args) throws Exception {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        Path vectors = Path.of(args[0]);

        // RFC 4226, приложение D
        String[] hotp = {"755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"};
        Totp.HmacFunction sha1 = Totp.softwareHmac(Algorithm.SHA1, ascii("12345678901234567890"));
        for (int c = 0; c < hotp.length; c++) {
            equal("RFC4226 счётчик " + c, hotp[c], Hotp.code(sha1.mac(Hotp.counterBytes(c)), 6));
        }

        // RFC 6238, приложение B (8 цифр)
        byte[][] secrets = {
                ascii("12345678901234567890"),
                ascii("12345678901234567890123456789012"),
                ascii("1234567890123456789012345678901234567890123456789012345678901234")};
        Algorithm[] algos = {Algorithm.SHA1, Algorithm.SHA256, Algorithm.SHA512};
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[][] expected = {
                {"94287082", "46119246", "90693936"},
                {"07081804", "68084774", "25091201"},
                {"14050471", "67062674", "99943326"},
                {"89005924", "91819424", "93441116"},
                {"69279037", "90698825", "38618901"},
                {"65353130", "77737706", "47863826"}};
        for (int t = 0; t < times.length; t++) {
            for (int a = 0; a < 3; a++) {
                String got = Totp.generate(Totp.softwareHmac(algos[a], secrets[a]), times[t], 30, 8);
                equal("RFC6238 t=" + times[t] + " " + algos[a], expected[t][a], got);
            }
        }

        // 300 независимых векторов, посчитанных Python-генератором
        int cross = 0;
        for (String line : rows(vectors.resolve("cross.tsv"))) {
            String[] f = line.split("\t", -1);
            Totp.HmacFunction mac = Totp.softwareHmac(Algorithm.parse(f[1]), Base32.decode(f[0]));
            String got = Totp.generate(mac, Long.parseLong(f[4]), Integer.parseInt(f[3]), Integer.parseInt(f[2]));
            equal("cross " + cross, f[5], got);
            cross++;
        }
        equal("число cross-векторов", 300, cross);

        // URI: общие векторы с Python
        int uriCount = 0;
        for (String line : rows(vectors.resolve("uri.tsv"))) {
            String[] f = line.split("\t", -1);
            OtpAuthUri e = OtpAuthUri.parse(f[0]);
            String got = String.join("|", e.issuer, e.account, HexFormat.of().formatHex(e.secret),
                    e.algorithm.name(), String.valueOf(e.digits), String.valueOf(e.period), e.type,
                    String.valueOf(e.counter));
            String want = String.join("|", f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
            equal("uri " + f[0], want, got);
            uriCount++;
        }
        check("uri.tsv не пустой", uriCount >= 10);
        for (String bad : rows(vectors.resolve("uri_invalid.txt"))) {
            rejects("uri отклонён: " + bad, () -> OtpAuthUri.parse(bad));
        }

        // Base32
        equal("base32 допуски", "48656c6c6f21deadbeef",
                HexFormat.of().formatHex(Base32.decode("jbsw y3dp-ehpk 3pxp")));
        equal("base32 с =", "48656c6c6f21deadbeef",
                HexFormat.of().formatHex(Base32.decode("JBSWY3DPEHPK3PXP====")));
        for (int n = 1; n < 40; n++) {
            byte[] data = new byte[n];
            for (int i = 0; i < n; i++) {
                data[i] = (byte) i;
            }
            equal("base32 круг " + n, HexFormat.of().formatHex(data),
                    HexFormat.of().formatHex(Base32.decode(Base32.encode(data))));
        }
        for (String bad : new String[]{"", "!!!", "A", "1890"}) {
            rejects("base32 мусор '" + bad + "'", () -> Base32.decode(bad));
        }

        // Границы параметров и окна
        rejects("digits=5", () -> Hotp.checkDigits(5));
        rejects("digits=9", () -> Hotp.checkDigits(9));
        rejects("пустой секрет", () -> Totp.softwareHmac(Algorithm.SHA1, new byte[0]));
        rejects("отрицательный счётчик", () -> Hotp.counterBytes(-1));
        rejects("MD5", () -> Algorithm.parse("MD5"));
        equal("остаток 0", 30, Totp.secondsRemaining(0, 30));
        equal("остаток 29", 1, Totp.secondsRemaining(29, 30));
        equal("остаток 30", 30, Totp.secondsRemaining(30, 30));
        equal("граница окна", Totp.generate(sha1, 59, 30, 6), Totp.generate(sha1, 30, 30, 6));
        check("следующее окно другое", !Totp.generate(sha1, 59, 30, 6).equals(Totp.generate(sha1, 60, 30, 6)));

        extra(vectors, args.length > 1 ? args[1] : null);

        System.out.println("Java-ядро: пройдено " + passed + ", провалено " + failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}