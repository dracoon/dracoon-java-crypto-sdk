package com.dracoon.sdk.crypto.error;

/**
 * Signals that an unexpected crypto error occurred. (Mostly missing algorithms, unsupported
 * padding, ...)
 */
public class CryptoSystemException extends CryptoException {

    private static final long serialVersionUID = 6541184110536021381L;

    public CryptoSystemException() {

    }

    public CryptoSystemException(String message) {
        super(message);
    }

    public CryptoSystemException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoSystemException(Throwable cause) {
        super(cause);
    }

}
