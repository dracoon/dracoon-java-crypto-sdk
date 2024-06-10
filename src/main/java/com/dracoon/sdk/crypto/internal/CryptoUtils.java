package com.dracoon.sdk.crypto.internal;

import org.bouncycastle.util.Strings;

public class CryptoUtils {

    private CryptoUtils() {

    }

    public static <T extends CryptoVersion> T findCryptoVersionEnum(T[] enums, String value) {
        if (value == null) {
            return null;
        }

        for (T e : enums) {
            if (value.equals(e.getValue())) {
                return e;
            }
        }
        return null;
    }

    public static char[] toUtf8CharArray(char[] chars) {
        byte[] utf8Bytes = Strings.toUTF8ByteArray(chars);
        return toCharArray(utf8Bytes);
    }

    private static char[] toCharArray(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) (bytes[i] & 0xFF);
        }
        return chars;
    }

}
