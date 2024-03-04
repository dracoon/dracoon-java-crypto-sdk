package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.internal.CryptoUtils;
import com.dracoon.sdk.crypto.internal.CryptoVersion;
import com.dracoon.sdk.crypto.internal.Validator;

/**
 * Plain file key model.<br>
 * <br>
 * This model holds plain file key data.
 */
public class PlainFileKey {

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

    private final Version version;
    private final byte[] key;
    private final byte[] iv;

    private byte[] tag;

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
        Validator.validateNotNull("version", version);
        Validator.validateByteArray("key", key);
        Validator.validateByteArray("iv", iv);
        this.version = version;
        this.key = key;
        this.iv = iv;
    }

    /**
     * Returns the plain file key version.
     *
     * @return the version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Returns the plain file key.
     *
     * @return the file key
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * Returns the encryption initialization vector.
     *
     * @return the initialization vector
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * Returns the encryption tag.
     *
     * @return the tag
     */
    public byte[] getTag() {
        return tag;
    }

    /**
     * Set the encryption tag.
     *
     * @param tag The encryption tag.
     */
    public void setTag(byte[] tag) {
        this.tag = tag;
    }

}
