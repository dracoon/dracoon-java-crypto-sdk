package com.dracoon.sdk.crypto.integration;

import java.io.IOException;

import com.dracoon.sdk.crypto.FileEncryptionBaseTest;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(IntegrationTest.class)
public abstract class FileEncryptionTest extends FileEncryptionBaseTest {

    public abstract String data(String subPath);

    public abstract String file(String subPath);

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    @Test
    public void testEncryptSingleBlock_Success() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptSingleBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("plain_file.b64"),
                file("aes256gcm/enc_file.b64"),
                true,
                true);
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    @Test
    public void testEncryptMultiBlock_Success() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptMultiBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("plain_file.b64"),
                file("aes256gcm/enc_file.b64"),
                true,
                true);
    }

}
