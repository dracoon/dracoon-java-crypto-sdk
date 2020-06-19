package com.dracoon.sdk.crypto;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

/**
 * Implements the Dracoon file encryption.
 */
public class FileEncryptionCipher extends FileCipher {

    FileEncryptionCipher(PlainFileKey fileKey) throws CryptoSystemException {
        try {
            init(true, fileKey);
        } catch (IllegalArgumentException e) {
            throw new CryptoSystemException("Could not create encryption cipher.", e);
        }
    }

	/**
     * Encrypts some bytes.
     *
     * @param plainData The data container with the bytes to encrypt.
     *
     * @return The data container with the encrypted bytes.
     *
     * @throws IllegalArgumentException If the data container is invalid.
     * @throws IllegalStateException    If the cipher is in an inappropriate state.
	 * @throws CryptoSystemException    If a unknown error occurred.
     */
    public EncryptedDataContainer processBytes(PlainDataContainer plainData)
            throws IllegalArgumentException, IllegalStateException, CryptoSystemException {
        if (plainData == null) {
            throw new IllegalArgumentException("Data container cannot be null.");
        }
        if (plainData.getContent() == null) {
            throw new IllegalArgumentException("Data container content cannot be null.");
        }

        byte[] eData;
        try {
            eData = process(plainData.getContent(), false);
        } catch (BadFileException e) {
            throw new CryptoSystemException("Could not encrypt file. Encryption failed.", e);
        }

        return new EncryptedDataContainer(eData, null);
    }

    /**
     * Completes the encryption. After this method is called no further calls of
     * {@link #processBytes(PlainDataContainer plainData) processBytes} and
     * {@link #doFinal() doFinal} are possible.
     *
     * @return The data container with the encrypted bytes and the calculated tag.
     *
     * @throws IllegalStateException If the cipher is in an inappropriate state.
     * @throws CryptoSystemException If a unknown error occurred.
     */
    public EncryptedDataContainer doFinal() throws IllegalStateException, CryptoSystemException {
        byte[] eData;
        try {
            eData = process(new byte[]{}, true);
        } catch (BadFileException e) {
            throw new CryptoSystemException("Could not encrypt file. Encryption failed.", e);
        }

        byte[] content = new byte[eData.length - TAG_SIZE];
        byte[] tag = new byte[TAG_SIZE];
        System.arraycopy(eData, 0, content, 0, content.length);
        System.arraycopy(eData, content.length, tag, 0, tag.length);

        return new EncryptedDataContainer(content, tag);
    }

}
