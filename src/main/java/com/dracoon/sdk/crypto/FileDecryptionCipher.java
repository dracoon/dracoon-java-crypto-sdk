package com.dracoon.sdk.crypto;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;

/**
 * Interface representing a cipher for the Dracoon file decryption.
 */
public interface FileDecryptionCipher {

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
    PlainDataContainer processBytes(EncryptedDataContainer encData) throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException;

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
    PlainDataContainer doFinal(EncryptedDataContainer encData) throws BadFileException,
            IllegalArgumentException, IllegalStateException, CryptoSystemException;

}
