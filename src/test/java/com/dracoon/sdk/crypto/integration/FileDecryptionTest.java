package com.dracoon.sdk.crypto.integration;

import java.io.IOException;

import com.dracoon.sdk.crypto.FileDecryptionBaseTest;
import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(IntegrationTest.class)
public abstract class FileDecryptionTest extends FileDecryptionBaseTest {

    public abstract String data(String subPath);

    public abstract String file(String subPath);

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptSingleBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testDecryptSingleBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("aes256gcm/enc_file.b64"),
                file("plain_file.b64"),
                true);
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptMultiBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testDecryptMultiBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("aes256gcm/enc_file.b64"),
                file("plain_file.b64"),
                true);
    }

}
