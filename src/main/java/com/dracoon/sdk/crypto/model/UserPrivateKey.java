package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.internal.Validator;

/**
 * User private key model.<br>
 * <br>
 * This model holds private key data.
 */
public class UserPrivateKey {

    private final UserKeyPair.Version version;
    private final char[] privateKey;

    /**
     * Constructs a new user private key.
     *
     * @param version    The private key version.
     * @param privateKey The PEM encoded private key.
     *
     * @throws IllegalArgumentException If a parameter is invalid (e.g. null or empty).
     */
    public UserPrivateKey(UserKeyPair.Version version, char[] privateKey)
            throws IllegalArgumentException {
        Validator.validateNotNull("version", version);
        Validator.validateCharArray("privateKey", privateKey);
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
     * Returns the PEM encoded private key.
     *
     * @return the private key
     */
    public char[] getPrivateKey() {
        return privateKey;
    }

}
