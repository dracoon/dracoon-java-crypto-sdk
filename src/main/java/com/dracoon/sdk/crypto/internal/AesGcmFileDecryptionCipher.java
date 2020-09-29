package com.dracoon.sdk.crypto.internal;

import com.dracoon.sdk.crypto.FileDecryptionCipher;
import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

public class AesGcmFileDecryptionCipher extends AesGcmFileCipher implements FileDecryptionCipher {

    public AesGcmFileDecryptionCipher(PlainFileKey fileKey) throws CryptoSystemException {
        try {
            init(false, fileKey);
        } catch (IllegalArgumentException e) {
            throw new CryptoSystemException("Could not create decryption cipher.", e);
        }
    }

    @Override
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

    @Override
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
