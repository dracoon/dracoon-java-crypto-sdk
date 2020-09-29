package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.internal.Validator;

/**
 * User public key model.<br>
 * <br>
 * This model holds public key data.
 */
public class UserPublicKey {

    private final UserKeyPair.Version version;
    private final String publicKey;

    /**
     * Constructs a new user public key.
     *
     * @param version   The public key version.
     * @param publicKey The PEM encoded public key string.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public UserPublicKey(UserKeyPair.Version version, String publicKey)
            throws IllegalArgumentException {
        Validator.validateNotNull("version", version);
        Validator.validateString("publicKey", publicKey);
        this.version = version;
        this.publicKey = publicKey;
    }

    /**
     * Returns the public key version.
     *
     * @return the version
     */
    public UserKeyPair.Version getVersion() {
        return version;
    }

    /**
     * Returns the PEM encoded public key string.
     *
     * @return the string
     */
    public String getPublicKey() {
        return publicKey;
    }

}
