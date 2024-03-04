package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.internal.CryptoUtils;
import com.dracoon.sdk.crypto.internal.CryptoVersion;
import com.dracoon.sdk.crypto.internal.Validator;

/**
 * User key pair model.<br>
 * <br>
 * This model holds the user's private and public key.
 */
public class UserKeyPair {

    /**
     * Available user key pair versions.
     */
    public enum Version implements CryptoVersion {

        RSA2048("A"),
        RSA4096("RSA-4096");

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
                throw new UnknownVersionException("Unknown key pair version.");
            }
            return v;
        }

    }

    private final UserPrivateKey userPrivateKey;
    private final UserPublicKey userPublicKey;

    /**
     * Constructs a new user key pair.
     *
     * @param userPrivateKey The user's private key.
     * @param userPublicKey  The user's public key.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public UserKeyPair(UserPrivateKey userPrivateKey, UserPublicKey userPublicKey)
            throws IllegalArgumentException {
        Validator.validateNotNull("userPrivateKey", userPrivateKey);
        Validator.validateNotNull("userPublicKey", userPublicKey);
        Validator.validateEqual("userPrivateKey.version", userPrivateKey.getVersion(),
                "userPublicKey.version", userPublicKey.getVersion());
        this.userPrivateKey = userPrivateKey;
        this.userPublicKey = userPublicKey;
    }

    /**
     * Returns the user's private key.
     *
     * @return the private key
     */
    public UserPrivateKey getUserPrivateKey() {
        return userPrivateKey;
    }

    /**
     * Returns the user's public key.
     *
     * @return the public key
     */
    public UserPublicKey getUserPublicKey() {
        return userPublicKey;
    }

}
