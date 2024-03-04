package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.internal.CryptoUtils;
import com.dracoon.sdk.crypto.internal.CryptoVersion;

/**
 * Plain file key model.<br>
 * <br>
 * This model holds plain file key data.
 */
public class PlainFileKey extends FileKey<PlainFileKey.Version> {

    /**
     * Available plain file key versions.
     */
    public enum Version implements CryptoVersion {

        AES256GCM("A");

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
                throw new UnknownVersionException("Unknown plain file key version.");
            }
            return v;
        }

    }

    /**
     * Constructs a new plain file key.
     *
     * @param version The file key version.
     * @param key     The plain file key.
     * @param iv      The encryption initialization vector.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public PlainFileKey(Version version, byte[] key, byte[] iv) throws IllegalArgumentException {
        super(version, key, iv);
    }

}
