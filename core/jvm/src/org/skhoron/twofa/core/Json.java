// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Минимальный строгий JSON: объекты, массивы, строки, целые числа, true/false/null. */
final class Json {
    private static final int MAX_DEPTH = 16;
    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json parser = new Json(text);
        parser.skipWhitespace();
        Object value = parser.value(0);
        parser.skipWhitespace();
        if (parser.pos != text.length()) {
            throw parser.error("лишние данные после значения");
        }
        return value;
    }

    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    b.append("\\\"");
                    break;
                case '\\':
                    b.append("\\\\");
                    break;
                case '\n':
                    b.append("\\n");
                    break;
                case '\r':
                    b.append("\\r");
                    break;
                case '\t':
                    b.append("\\t");
                    break;
                case '\b':
                    b.append("\\b");
                    break;
                case '\f':
                    b.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("JSON: " + message + " (позиция " + pos + ")");
    }

    private void skipWhitespace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= text.length()) {
            throw error("неожиданный конец");
        }
        return text.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char c) {
        if (next() != c) {
            pos--;
            throw error("ожидался символ " + c);
        }
    }

    private Object value(int depth) {
        char c = peek();
        if (c == '{') {
            return object(depth + 1);
        }
        if (c == '[') {
            return array(depth + 1);
        }
        if (c == '"') {
            return string();
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return number();
        }
        if (text.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (text.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        if (text.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw error("неожиданный символ");
    }

    private Map<String, Object> object(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("слишком глубокая вложенность");
        }
        pos++;
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw error("ожидался ключ-строка");
            }
            String key = string();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            Object v = value(depth);
            if (map.containsKey(key)) {
                throw error("повторяющийся ключ " + key);
            }
            map.put(key, v);
            skipWhitespace();
            char c = next();
            if (c == '}') {
                return map;
            }
            if (c != ',') {
                pos--;
                throw error("ожидалась запятая или }");
            }
        }
    }

    private List<Object> array(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("слишком глубокая вложенность");
        }
        pos++;
        List<Object> list = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipWhitespace();
            list.add(value(depth));
            skipWhitespace();
            char c = next();
            if (c == ']') {
                return list;
            }
            if (c != ',') {
                pos--;
                throw error("ожидалась запятая или ]");
            }
        }
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private String string() {
        pos++;
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') {
                return b.toString();
            }
            if (c < 0x20) {
                pos--;
                throw error("управляющий символ в строке");
            }
            if (c != '\\') {
                b.append(c);
                continue;
            }
            char e = next();
            switch (e) {
                case '"':
                    b.append('"');
                    break;
                case '\\':
                    b.append('\\');
                    break;
                case '/':
                    b.append('/');
                    break;
                case 'b':
                    b.append('\b');
                    break;
                case 'f':
                    b.append('\f');
                    break;
                case 'n':
                    b.append('\n');
                    break;
                case 'r':
                    b.append('\r');
                    break;
                case 't':
                    b.append('\t');
                    break;
                case 'u':
                    if (pos + 4 > text.length()) {
                        throw error("обрыв \\u-последовательности");
                    }
                    int code = 0;
                    for (int i = 0; i < 4; i++) {
                        int d = hex(text.charAt(pos + i));
                        if (d < 0) {
                            throw error("неверная \\u-последовательность");
                        }
                        code = code * 16 + d;
                    }
                    pos += 4;
                    b.append((char) code);
                    break;
                default:
                    pos--;
                    throw error("неизвестное экранирование");
            }
        }
    }

    private Long number() {
        int start = pos;
        if (text.charAt(pos) == '-') {
            pos++;
        }
        int digits = pos;
        while (pos < text.length() && text.charAt(pos) >= '0' && text.charAt(pos) <= '9') {
            pos++;
        }
        if (pos == digits) {
            throw error("ожидались цифры");
        }
        if (text.charAt(digits) == '0' && pos - digits > 1) {
            throw error("ведущий ноль");
        }
        if (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == '.' || c == 'e' || c == 'E') {
                throw error("дробные числа не поддерживаются");
            }
        }
        try {
            return Long.valueOf(text.substring(start, pos));
        } catch (NumberFormatException e) {
            throw error("число вне диапазона");
        }
    }
}