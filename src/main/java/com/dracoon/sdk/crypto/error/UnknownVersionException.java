package com.dracoon.sdk.crypto.error;

/**
 * Signals a unknown crypto version.
 */
public class UnknownVersionException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public UnknownVersionException() {

    }

    public UnknownVersionException(String message) {
        super(message);
    }

    public UnknownVersionException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnknownVersionException(Throwable cause) {
        super(cause);
    }

}
