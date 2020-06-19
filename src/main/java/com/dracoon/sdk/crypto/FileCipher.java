package com.dracoon.sdk.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public abstract class FileCipher {

    protected static final int BLOCK_SIZE = 16;
    protected static final int TAG_SIZE = 16;

    protected GCMBlockCipher realCipher;

    protected void init(boolean encryption, PlainFileKey fileKey) throws IllegalArgumentException {
        byte[] key = CryptoUtils.stringToByteArray(fileKey.getKey());
        byte[] iv = CryptoUtils.stringToByteArray(fileKey.getIv());
        AEADParameters parameters = new AEADParameters(new KeyParameter(key), 8 * TAG_SIZE, iv);
        realCipher = new GCMBlockCipher(new AESFastEngine());
        realCipher.init(encryption, parameters);
    }

    protected byte[] process(byte[] block, boolean isLastBlock) throws BadFileException,
            IllegalStateException, CryptoSystemException {
        ByteArrayInputStream in = null;
        ByteArrayOutputStream out = null;
        try {
            in = new ByteArrayInputStream(block);
            out = new ByteArrayOutputStream();

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
        } catch(IOException e) {
            throw new CryptoSystemException("Could not en/decrypt file. Buffer read/write failed.",
                    e);
        } catch (IllegalStateException e) {
            throw new IllegalStateException("Could not en/decrypt file. Cipher is in a illegal " +
                    "state.", e);
        } catch (InvalidCipherTextException e) {
            throw new BadFileException("Could not en/decrypt file. File content is bad.", e);
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                // Nothing to do here
            }
        }
    }

}
