package com.dracoon.sdk.crypto;

/**
 * Signals a crypto problem.
 *
 * @see InvalidPasswordException
 * @see InvalidKeyPairException
 * @see InvalidFileKeyException
 * @see BadFileException
 * @see CryptoSystemException
 */
public class CryptoException extends Exception {

	private static final long serialVersionUID = 7708230805284554913L;

	public CryptoException() {

    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(Throwable cause) {
        super(cause);
    }

}
