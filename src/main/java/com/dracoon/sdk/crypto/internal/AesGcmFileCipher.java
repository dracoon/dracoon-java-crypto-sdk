package com.dracoon.sdk.crypto.internal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public abstract class AesGcmFileCipher {

    protected static final int BLOCK_SIZE = 16;
    protected static final int TAG_SIZE = 16;

    protected GCMModeCipher realCipher;

    protected void init(boolean encryption, PlainFileKey fileKey) throws IllegalArgumentException {
        byte[] key = fileKey.getKey();
        byte[] iv = fileKey.getIv();
        AEADParameters parameters = new AEADParameters(new KeyParameter(key), 8 * TAG_SIZE, iv);
        realCipher = GCMBlockCipher.newInstance(new AESFastEngine());
        realCipher.init(encryption, parameters);
    }

    protected byte[] process(byte[] block, boolean isLastBlock) throws BadFileException,
            IllegalStateException, CryptoSystemException {
        try (ByteArrayInputStream in = new ByteArrayInputStream(block);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[BLOCK_SIZE];
            byte[] encBuffer = new byte[BLOCK_SIZE + TAG_SIZE];
            int bytesRead;
            int bytesEncrypted;
            while ((bytesRead = in.read(buffer)) != -1) {
                bytesEncrypted = realCipher.processBytes(buffer, 0, bytesRead, encBuffer, 0);
                out.write(encBuffer, 0, bytesEncrypted);
            }

            if (isLastBlock) {
                bytesEncrypted = realCipher.doFinal(encBuffer, 0);
                out.write(encBuffer, 0, bytesEncrypted);
            }

            out.flush();
            return out.toByteArray();
        } catch (IOException e) {
            throw new CryptoSystemException("Could not en/decrypt file. Buffer read/write failed.",
                    e);
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Could not en/decrypt file. Cipher is in a illegal " +
                    "state.", e);
        } catch (InvalidCipherTextException e) {
            throw new BadFileException("Could not en/decrypt file. File content is bad.", e);
        }
    }

}
