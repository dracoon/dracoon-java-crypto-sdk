package com.dracoon.sdk.crypto.error;

/**
 * Signals a problem with the file.
 */
public class BadFileException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public BadFileException() {

    }

    public BadFileException(String message) {
        super(message);
    }

    public BadFileException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadFileException(Throwable cause) {
        super(cause);
    }

}
