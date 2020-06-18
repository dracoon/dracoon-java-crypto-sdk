package com.dracoon.sdk.crypto.model;

/**
 * User public key model.<br>
 * <br>
 * This model holds public key data.
 */
public class UserPublicKey {

    private final String version;
    private final String publicKey;

    /**
     * Constructs a new user public key.
     *
     * @param version   The public key version.
     * @param publicKey The PEM encoded public key string.
     */
    public UserPublicKey(String version, String publicKey) {
        Validator.validateString("version", version);
        Validator.validateString("publicKey", publicKey);
        this.version = version;
        this.publicKey = publicKey;
    }

    /**
     * Returns the public key version.
     *
     * @return the version
     */
    public String getVersion() {
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
