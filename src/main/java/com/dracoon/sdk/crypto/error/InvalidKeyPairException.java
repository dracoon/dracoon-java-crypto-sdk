package com.dracoon.sdk.crypto.error;

/**
 * Signals a problem with the user's key pair.
 */
public class InvalidKeyPairException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public InvalidKeyPairException() {

    }

    public InvalidKeyPairException(String message) {
        super(message);
    }

    public InvalidKeyPairException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidKeyPairException(Throwable cause) {
        super(cause);
    }

}
