package com.dracoon.sdk.crypto;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;

/**
 * Interface representing a cipher for the Dracoon file encryption.
 */
public interface FileEncryptionCipher {

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
    EncryptedDataContainer processBytes(PlainDataContainer plainData) throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException;

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
    EncryptedDataContainer doFinal() throws IllegalStateException, CryptoSystemException;

}
