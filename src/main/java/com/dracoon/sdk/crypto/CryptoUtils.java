package com.dracoon.sdk.crypto;

import org.spongycastle.util.encoders.Base64;

/**
 * Provides helper methods.
 */
public class CryptoUtils {

    private CryptoUtils() {

    }

    /**
     * Converts a byte array into a Base64 encoded string.
     *
     * @param bytes The byte array to convert.
     *
     * @return The Base64 encoded string.
     */
    public static String byteArrayToString(byte[] bytes) {
        return Base64.toBase64String(bytes);
    }

    /**
     * Converts a Base64 encoded string into a byte array.
     *
     * @param base64String The string to convert.
     *
     * @return The decoded byte array.
     */
    public static byte[] stringToByteArray(String base64String) {
        return Base64.decode(base64String);
    }

}
