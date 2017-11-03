package com.dracoon.sdk.crypto;

import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

/**
 * Implements the Dracoon file decryption.
 */
public class FileDecryptionCipher extends FileCipher {

    FileDecryptionCipher(PlainFileKey fileKey) throws CryptoSystemException {
        try {
            init(false, fileKey);
        } catch (IllegalArgumentException e) {
            throw new CryptoSystemException("Could not create decryption cipher.", e);
        }
    }

    /**
     * Decrypts some bytes.
     *
     * @param encData The data container with the bytes to decrypt.
     *
     * @return The data container with the decrypted bytes.
     *
     * @throws IllegalArgumentException If the data container is invalid.
     * @throws IllegalStateException    If the cipher is in an inappropriate state.
     * @throws CryptoSystemException    If a unknown error occurred.
     */
	public PlainDataContainer processBytes(EncryptedDataContainer encData)
	        throws IllegalArgumentException, IllegalStateException, CryptoSystemException {
	    if (encData == null) {
	        throw new IllegalArgumentException("Data container cannot be null.");
	    }
	    if (encData.getContent() == null) {
	        throw new IllegalArgumentException("Data container content cannot be null.");
	    }
	    if (encData.getTag() != null) {
	        throw new IllegalArgumentException("Data container tag must be null.");
	    }

        byte[] pData;
        try {
            pData = process(encData.getContent(), false);
        } catch (BadFileException e) {
            throw new CryptoSystemException("Could not decrypt file. Decryption failed.", e);
        }

        return new PlainDataContainer(pData);
    }

	/**
     * Completes the decryption. After this method is called no further calls of
     * {@link #processBytes(EncryptedDataContainer encData) processBytes} and
     * {@link #doFinal(EncryptedDataContainer encData) doFinal} are possible.
     *
     * @param encData The data container with the previously calculated tag.
     *
     * @return The data container with the decrypted bytes.
     *
     * @throws BadFileException         If the file content has been modified.
     * @throws IllegalArgumentException If the data container is invalid.
     * @throws IllegalStateException    If the cipher is in an inappropriate state.
     * @throws CryptoSystemException    If a unknown error occurred.
     */
	public PlainDataContainer doFinal(EncryptedDataContainer encData)
	        throws BadFileException, IllegalArgumentException, IllegalStateException,
	        CryptoSystemException {
	    if (encData == null) {
            throw new IllegalArgumentException("Data container cannot be null.");
        }
        if (encData.getContent() != null) {
            throw new IllegalArgumentException("Data container content must be null.");
        }
        if (encData.getTag() == null) {
            throw new IllegalArgumentException("Data container tag cannot be null.");
        }

        byte[] pData = process(encData.getTag(), true);

        return new PlainDataContainer(pData);
	}

}
