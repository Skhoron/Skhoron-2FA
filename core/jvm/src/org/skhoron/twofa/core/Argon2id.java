// SPDX-License-Identifier: Apache-2.0
package org.skhoron.twofa.core;

import java.util.Arrays;

/**
 * Argon2id (RFC 9106, версия 0x13) на чистой Java, один поток. В Android нет встроенного Argon2.
 * Проверяется по Python cryptography (OpenSSL) на общих векторах, включая вектор из RFC 9106.
 * Это не реализация с защитой от всех побочных каналов.
 */
public final class Argon2id {
    private static final int VERSION = 0x13;
    private static final int TYPE_ID = 2;
    private static final int SYNC_POINTS = 4;
    private static final int WORDS = 128;

    private final long[][] memory;
    private final int lanes;
    private final int iterations;
    private final int blockCount;
    private final int laneLength;
    private final int segmentLength;
    private final long[] scratchR = new long[WORDS];
    private final long[] scratchTmp = new long[WORDS];

    private Argon2id(int memoryKib, int lanes, int iterations) {
        this.lanes = lanes;
        this.iterations = iterations;
        this.blockCount = 4 * lanes * (memoryKib / (4 * lanes));
        this.laneLength = blockCount / lanes;
        this.segmentLength = laneLength / SYNC_POINTS;
        this.memory = new long[blockCount][WORDS];
    }

    public static byte[] hash(byte[] password, byte[] salt, int iterations, int memoryKib, int lanes,
                              int tagLength, byte[] secret, byte[] ad) {
        if (lanes < 1 || lanes > 0xFFFFFF) {
            throw new IllegalArgumentException("lanes вне диапазона");
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations должно быть не меньше 1");
        }
        if (memoryKib < 8 * lanes) {
            throw new IllegalArgumentException("memory меньше 8 * lanes");
        }
        if (salt.length < 8) {
            throw new IllegalArgumentException("соль короче 8 байт");
        }
        if (tagLength < 4) {
            throw new IllegalArgumentException("длина тега меньше 4");
        }
        Argon2id a = new Argon2id(memoryKib, lanes, iterations);
        byte[] h0 = initialHash(password, salt, secret, ad, lanes, tagLength, memoryKib, iterations);
        a.fillFirstBlocks(h0);
        Arrays.fill(h0, (byte) 0);
        for (int pass = 0; pass < iterations; pass++) {
            for (int slice = 0; slice < SYNC_POINTS; slice++) {
                for (int lane = 0; lane < lanes; lane++) {
                    a.fillSegment(pass, lane, slice);
                }
            }
        }
        return a.finish(tagLength);
    }

    private static byte[] initialHash(byte[] pw, byte[] salt, byte[] secret, byte[] ad,
                                      int lanes, int tag, int memoryKib, int iterations) {
        byte[] in = new byte[40 + pw.length + salt.length + secret.length + ad.length];
        int pos = 0;
        putLe32(in, pos, lanes);
        putLe32(in, pos += 4, tag);
        putLe32(in, pos += 4, memoryKib);
        putLe32(in, pos += 4, iterations);
        putLe32(in, pos += 4, VERSION);
        putLe32(in, pos += 4, TYPE_ID);
        putLe32(in, pos += 4, pw.length);
        pos += 4;
        System.arraycopy(pw, 0, in, pos, pw.length);
        pos += pw.length;
        putLe32(in, pos, salt.length);
        pos += 4;
        System.arraycopy(salt, 0, in, pos, salt.length);
        pos += salt.length;
        putLe32(in, pos, secret.length);
        pos += 4;
        System.arraycopy(secret, 0, in, pos, secret.length);
        pos += secret.length;
        putLe32(in, pos, ad.length);
        pos += 4;
        System.arraycopy(ad, 0, in, pos, ad.length);
        byte[] h0 = Blake2b.hash(64, in);
        Arrays.fill(in, (byte) 0);
        return h0;
    }

    private void fillFirstBlocks(byte[] h0) {
        byte[] seed = new byte[72];
        System.arraycopy(h0, 0, seed, 0, 64);
        for (int lane = 0; lane < lanes; lane++) {
            putLe32(seed, 68, lane);
            putLe32(seed, 64, 0);
            bytesToBlock(hPrime(1024, seed), memory[lane * laneLength]);
            putLe32(seed, 64, 1);
            bytesToBlock(hPrime(1024, seed), memory[lane * laneLength + 1]);
        }
        Arrays.fill(seed, (byte) 0);
    }

    private void fillSegment(int pass, int lane, int slice) {
        boolean independent = pass == 0 && slice < 2;
        long[] input = null;
        long[] address = null;
        long[] zero = null;
        if (independent) {
            input = new long[WORDS];
            address = new long[WORDS];
            zero = new long[WORDS];
            input[0] = pass;
            input[1] = lane;
            input[2] = slice;
            input[3] = blockCount;
            input[4] = iterations;
            input[5] = TYPE_ID;
        }
        int start = 0;
        if (pass == 0 && slice == 0) {
            start = 2;
            if (independent) {
                nextAddresses(zero, input, address);
            }
        }
        int cur = lane * laneLength + slice * segmentLength + start;
        int prev = (cur % laneLength == 0) ? cur + laneLength - 1 : cur - 1;
        for (int i = start; i < segmentLength; i++, cur++, prev++) {
            if (cur % laneLength == 1) {
                prev = cur - 1;
            }
            long pseudoRand;
            if (independent) {
                if (i % WORDS == 0) {
                    nextAddresses(zero, input, address);
                }
                pseudoRand = address[i % WORDS];
            } else {
                pseudoRand = memory[prev][0];
            }
            int refLane = (int) ((pseudoRand >>> 32) % lanes);
            if (pass == 0 && slice == 0) {
                refLane = lane;
            }
            int refIndex = indexAlpha(pass, slice, i, refLane == lane, pseudoRand & 0xFFFFFFFFL);
            fillBlock(memory[prev], memory[refLane * laneLength + refIndex], memory[cur], pass != 0);
        }
    }

    private int indexAlpha(int pass, int slice, int index, boolean sameLane, long pseudoRand) {
        long area;
        if (pass == 0) {
            if (slice == 0) {
                area = index - 1;
            } else if (sameLane) {
                area = (long) slice * segmentLength + index - 1;
            } else {
                area = (long) slice * segmentLength + (index == 0 ? -1 : 0);
            }
        } else if (sameLane) {
            area = laneLength - segmentLength + index - 1;
        } else {
            area = laneLength - segmentLength + (index == 0 ? -1 : 0);
        }
        long rel = (pseudoRand * pseudoRand) >>> 32;
        rel = area - 1 - ((area * rel) >>> 32);
        long start = 0;
        if (pass != 0) {
            start = (slice == SYNC_POINTS - 1) ? 0 : (long) (slice + 1) * segmentLength;
        }
        return (int) ((start + rel) % laneLength);
    }

    private void nextAddresses(long[] zero, long[] input, long[] address) {
        input[6]++;
        fillBlock(zero, input, address, false);
        fillBlock(zero, address, address, false);
    }

    private void fillBlock(long[] prev, long[] ref, long[] next, boolean xor) {
        long[] r = scratchR;
        long[] tmp = scratchTmp;
        for (int i = 0; i < WORDS; i++) {
            r[i] = ref[i] ^ prev[i];
            tmp[i] = xor ? r[i] ^ next[i] : r[i];
        }
        for (int i = 0; i < 8; i++) {
            int b = 16 * i;
            round(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }
        for (int i = 0; i < 8; i++) {
            int b = 2 * i;
            round(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }
        for (int i = 0; i < WORDS; i++) {
            next[i] = tmp[i] ^ r[i];
        }
    }

    private static void round(long[] v, int i0, int i1, int i2, int i3, int i4, int i5, int i6, int i7,
                              int i8, int i9, int i10, int i11, int i12, int i13, int i14, int i15) {
        g(v, i0, i4, i8, i12);
        g(v, i1, i5, i9, i13);
        g(v, i2, i6, i10, i14);
        g(v, i3, i7, i11, i15);
        g(v, i0, i5, i10, i15);
        g(v, i1, i6, i11, i12);
        g(v, i2, i7, i8, i13);
        g(v, i3, i4, i9, i14);
    }

    private static void g(long[] v, int a, int b, int c, int d) {
        v[a] = blaMka(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = blaMka(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = blaMka(v[a], v[b]);
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = blaMka(v[c], v[d]);
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static long blaMka(long x, long y) {
        return x + y + 2L * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
    }

    private byte[] finish(int tagLength) {
        long[] last = memory[laneLength - 1].clone();
        for (int lane = 1; lane < lanes; lane++) {
            long[] block = memory[lane * laneLength + laneLength - 1];
            for (int i = 0; i < WORDS; i++) {
                last[i] ^= block[i];
            }
        }
        byte[] bytes = blockToBytes(last);
        byte[] tag = hPrime(tagLength, bytes);
        for (long[] row : memory) {
            Arrays.fill(row, 0L);
        }
        Arrays.fill(last, 0L);
        Arrays.fill(bytes, (byte) 0);
        return tag;
    }

    /** Функция H' из RFC 9106: BLAKE2b с произвольной длиной вывода. */
    static byte[] hPrime(int outLen, byte[] in) {
        byte[] prefixed = new byte[4 + in.length];
        putLe32(prefixed, 0, outLen);
        System.arraycopy(in, 0, prefixed, 4, in.length);
        if (outLen <= 64) {
            return Blake2b.hash(outLen, prefixed);
        }
        int r = (outLen + 31) / 32 - 2;
        byte[] out = new byte[outLen];
        byte[] v = Blake2b.hash(64, prefixed);
        System.arraycopy(v, 0, out, 0, 32);
        int pos = 32;
        for (int i = 2; i <= r; i++) {
            v = Blake2b.hash(64, v);
            System.arraycopy(v, 0, out, pos, 32);
            pos += 32;
        }
        int tail = outLen - 32 * r;
        v = Blake2b.hash(tail, v);
        System.arraycopy(v, 0, out, pos, tail);
        return out;
    }

    private static void putLe32(byte[] dst, int pos, int value) {
        dst[pos] = (byte) value;
        dst[pos + 1] = (byte) (value >>> 8);
        dst[pos + 2] = (byte) (value >>> 16);
        dst[pos + 3] = (byte) (value >>> 24);
    }

    private static void bytesToBlock(byte[] src, long[] dst) {
        for (int i = 0; i < WORDS; i++) {
            long w = 0;
            for (int j = 7; j >= 0; j--) {
                w = (w << 8) | (src[8 * i + j] & 0xFFL);
            }
            dst[i] = w;
        }
    }

    private static byte[] blockToBytes(long[] block) {
        byte[] out = new byte[1024];
        for (int i = 0; i < WORDS; i++) {
            for (int j = 0; j < 8; j++) {
                out[8 * i + j] = (byte) (block[i] >>> (8 * j));
            }
        }
        return out;
    }
}