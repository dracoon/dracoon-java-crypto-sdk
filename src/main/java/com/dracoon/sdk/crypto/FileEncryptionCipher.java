package com.dracoon.sdk.crypto;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;

/**
 * Interface representing a cipher for the Dracoon file encryption.
 */
public interface FileEncryptionCipher {

    /**
     * Encrypts some bytes.<br>
     * <br>
     * IMPORTANT!!!: After all plain bytes have been processed, {@link #doFinal() doFinal} must be
     * called to complete the encryption. Otherwise the encryption is not finished and the encrypted
     * bytes can't later be decrypted.
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
     * Completes the encryption and calculates a kind of checksum which is later used at the
     * decryption to verify the integrity of decrypted bytes.<br>
     * <br>
     * After this method is called no further calls of {@link
     * #processBytes(PlainDataContainer plainData) processBytes} and {@link #doFinal() doFinal} are
     * possible.
     *
     * @return The data container with the encrypted bytes and the calculated tag.
     *
     * @throws IllegalStateException If the cipher is in an inappropriate state.
     * @throws CryptoSystemException If a unknown error occurred.
     */
    EncryptedDataContainer doFinal() throws IllegalStateException, CryptoSystemException;

}
