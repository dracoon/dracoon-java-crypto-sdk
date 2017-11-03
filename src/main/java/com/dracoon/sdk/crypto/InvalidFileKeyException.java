package com.dracoon.sdk.crypto;

/**
 * Signals a problem with the file key.
 */
public class InvalidFileKeyException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public InvalidFileKeyException() {

    }

    public InvalidFileKeyException(String message) {
        super(message);
    }

    public InvalidFileKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidFileKeyException(Throwable cause) {
        super(cause);
    }

}
