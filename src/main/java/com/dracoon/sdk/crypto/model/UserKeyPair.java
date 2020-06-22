package com.dracoon.sdk.crypto.model;

/**
 * User key pair model.<br>
 * <br>
 * This model holds the user's private and public key.
 */
public class UserKeyPair {

    private final UserPrivateKey userPrivateKey;
    private final UserPublicKey userPublicKey;

    /**
     * Constructs a new user key pair.
     *
     * @param userPrivateKey The user's private key.
     * @param userPublicKey  The user's public key.
     */
    public UserKeyPair(UserPrivateKey userPrivateKey, UserPublicKey userPublicKey) {
        Validator.validateNotNull("userPrivateKey", userPrivateKey);
        Validator.validateNotNull("userPublicKey", userPublicKey);
        Validator.validateEqual("userPublicKey.version", userPublicKey,
                "userPublicKey.version", userPublicKey);
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
