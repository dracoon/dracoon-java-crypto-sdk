package com.dracoon.sdk.crypto.model;

/**
 * User private key model.<br>
 * <br>
 * This model holds private key data.
 */
public class UserPrivateKey {

    private final String version;
    private final String privateKey;

    /**
     * Constructs a new user private key.
     *
     * @param version    The private key version.
     * @param privateKey The PEM encoded private key string.
     */
    public UserPrivateKey(String version, String privateKey) {
        Validator.validateString("version", version);
        Validator.validateString("privateKey", privateKey);
        this.version = version;
        this.privateKey = privateKey;
    }

    /**
     * Returns the private key version.
     *
     * @return the version
     */
    public String getVersion() {
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
