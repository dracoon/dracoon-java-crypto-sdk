package com.dracoon.sdk.crypto.internal;

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

}
