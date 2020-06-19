package com.dracoon.sdk.crypto.internal;

import com.dracoon.sdk.crypto.FileEncryptionCipher;
import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

public class AesGcmFileEncryptionCipher extends AesGcmFileCipher implements FileEncryptionCipher {

    public AesGcmFileEncryptionCipher(PlainFileKey fileKey) throws CryptoSystemException {
        try {
            init(true, fileKey);
        } catch (IllegalArgumentException e) {
            throw new CryptoSystemException("Could not create encryption cipher.", e);
        }
    }

	@Override
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

    @Override
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
