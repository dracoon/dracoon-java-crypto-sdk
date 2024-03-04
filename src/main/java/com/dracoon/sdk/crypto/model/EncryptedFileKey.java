package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.internal.CryptoUtils;
import com.dracoon.sdk.crypto.internal.CryptoVersion;

/**
 * Encrypted file key model.<br>
 * <br>
 * This model holds encrypted file key data.
 */
public class EncryptedFileKey extends FileKey<EncryptedFileKey.Version> {

    /**
     * Available encrypted file key versions.
     */
    public enum Version implements CryptoVersion {

        RSA2048_AES256GCM("A"),
        RSA4096_AES256GCM("RSA-4096/AES-256-GCM");

        private final String value;

        Version(String value) {
            this.value = value;
        }

        @Override
        public String getValue() {
            return value;
        }

        /**
         * Finds a enumeration constant by its version value.
         *
         * @param value The version value of the constant to return.
         *
         * @return the appropriate enumeration constant
         *
         * @throws UnknownVersionException If no matching enumeration constant could be found.
         */
        public static Version getByValue(String value) throws UnknownVersionException {
            Version v = CryptoUtils.findCryptoVersionEnum(values(), value);
            if (v == null) {
                throw new UnknownVersionException("Unknown encrypted file key version.");
            }
            return v;
        }

    }

    /**
     * Constructs a new plain file key.
     *
     * @param version The file key version.
     * @param key     The encrypted file key.
     * @param iv      The encryption initialization vector.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public EncryptedFileKey(Version version, byte[] key, byte[] iv) throws IllegalArgumentException {
        super(version, key, iv);
    }

}
