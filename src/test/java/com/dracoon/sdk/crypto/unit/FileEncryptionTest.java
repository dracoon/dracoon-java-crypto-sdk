package com.dracoon.sdk.crypto.unit;

import java.io.IOException;

import com.dracoon.sdk.crypto.FileEncryptionBaseTest;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import org.junit.Test;

import static com.dracoon.sdk.crypto.unit.TestHelper.*;

public class FileEncryptionTest extends FileEncryptionBaseTest {

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

    @Test
    public void testEncryptSingleBlock_DifferentContent() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptSingleBlock(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                file("plain_file_modified.b64"),
                file("aes256gcm/enc_file.b64"),
                false,
                null);
    }

    @Test
    public void testEncryptSingleBlock_DifferentTag() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptSingleBlock(
                data("fk_general/plain_file_key_bad_tag.json"),
                file("plain_file.b64"),
                file("aes256gcm/enc_file.b64"),
                null,
                false);
    }

    @Test
    public void testEncryptSingleBlock_DifferentKey() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptSingleBlock(
                data("fk_general/plain_file_key_bad_key.json"),
                file("plain_file.b64"),
                file("aes256gcm/enc_file.b64"),
                false,
                false);
    }

    @Test
    public void testEncryptSingleBlock_DifferentIv() throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        testEncryptSingleBlock(
                data("fk_general/plain_file_key_bad_iv.json"),
                file("plain_file.b64"),
                file("aes256gcm/enc_file.b64"),
                false,
                false);
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

    // ### ILLEGAL DATA CONTAINER TESTS ###

    @Test(expected=IllegalArgumentException.class)
    public void testEncryptProcessArguments_InvalidDataContainer() throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testEncryptProcessArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testEncryptProcessArguments_InvalidDataContent() throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testEncryptProcessArguments(new PlainDataContainer(null));
    }

    public void testEncryptProcessArguments(PlainDataContainer pdc) throws IllegalArgumentException,
            IllegalStateException, CryptoSystemException {
        testEncryptProcessArguments(data("fk_rsa2048_aes256gcm/plain_file_key.json"), pdc);
    }

}
