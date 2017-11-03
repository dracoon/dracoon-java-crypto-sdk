package com.dracoon.sdk.crypto;

/**
 * Signals a problem with the password.
 */
public class InvalidPasswordException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public InvalidPasswordException() {

    }

    public InvalidPasswordException(String message) {
        super(message);
    }

    public InvalidPasswordException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidPasswordException(Throwable cause) {
        super(cause);
    }

}
