package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.internal.Validator;

/**
 * User private key model.<br>
 * <br>
 * This model holds private key data.
 */
public class UserPrivateKey {

    private final UserKeyPair.Version version;
    private final String privateKey;

    /**
     * Constructs a new user private key.
     *
     * @param version    The private key version.
     * @param privateKey The PEM encoded private key string.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public UserPrivateKey(UserKeyPair.Version version, String privateKey)
            throws IllegalArgumentException {
        Validator.validateNotNull("version", version);
        Validator.validateString("privateKey", privateKey);
        this.version = version;
        this.privateKey = privateKey;
    }

    /**
     * Returns the private key version.
     *
     * @return the version
     */
    public UserKeyPair.Version getVersion() {
        return version;
    }

    /**
     * Returns the PEM encoded private key string.
     *
     * @return the string
     */
    public String getPrivateKey() {
        return privateKey;
    }

}
