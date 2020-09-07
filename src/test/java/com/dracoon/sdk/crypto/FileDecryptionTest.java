package com.dracoon.sdk.crypto;

import java.io.IOException;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import org.junit.Test;

import static com.dracoon.sdk.crypto.TestHelper.*;

public class FileDecryptionTest extends FileDecryptionBaseTest {

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptSingleBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("aes256gcm/enc_file.txt"),
                file("plain_file.txt"),
                true);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedContent() throws BadFileException,
            IllegalArgumentException, IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("aes256gcm/enc_file_modified.txt"),
                null,
                null);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedTag() throws BadFileException,
            IllegalArgumentException, IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_general/plain_file_key_bad_tag.json"),
                file("aes256gcm/enc_file.txt"),
                null,
                null);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedKey() throws BadFileException,
            IllegalArgumentException, IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_general/plain_file_key_bad_key.json"),
                file("aes256gcm/enc_file.txt"),
                null,
                null);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedIv() throws BadFileException,
            IllegalArgumentException, IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_general/plain_file_key_bad_iv.json"),
                file("aes256gcm/enc_file.txt"),
                null,
                null);
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptMultiBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testDecryptMultiBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("aes256gcm/enc_file.txt"),
                file("plain_file.txt"),
                true);
    }

    // ### ILLEGAL DATA CONTAINER TESTS ###

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataContainer() throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testDecryptProcessArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataContent() throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testDecryptProcessArguments(new EncryptedDataContainer(null, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataTag() throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testDecryptProcessArguments(new EncryptedDataContainer(new byte[]{}, new byte[]{}));
    }

    protected void testDecryptProcessArguments(EncryptedDataContainer edc)
            throws IllegalArgumentException, IllegalStateException, CryptoSystemException {
        testDecryptProcessArguments(data("fk_rsa2048_aes256gcm/plain_file_key.json"), edc);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataContainer() throws BadFileException,
            IllegalArgumentException, IllegalStateException, CryptoSystemException {
        testDecryptDoFinalArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataContent() throws BadFileException,
            IllegalArgumentException, IllegalStateException, CryptoSystemException {
        testDecryptDoFinalArguments(new EncryptedDataContainer(null, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataTag() throws BadFileException,
            IllegalArgumentException, IllegalStateException, CryptoSystemException {
        testDecryptDoFinalArguments(new EncryptedDataContainer(new byte[]{}, new byte[]{}));
    }

    protected void testDecryptDoFinalArguments(EncryptedDataContainer edc)
            throws BadFileException, IllegalArgumentException, IllegalStateException,
            CryptoSystemException {
        testDecryptDoFinalArguments(data("fk_rsa2048_aes256gcm/plain_file_key.json"), edc);
    }

}
