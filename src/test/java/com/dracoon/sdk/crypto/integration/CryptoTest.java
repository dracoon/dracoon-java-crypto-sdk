package com.dracoon.sdk.crypto.integration;

import com.dracoon.sdk.crypto.CryptoBaseTest;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.error.InvalidFileKeyException;
import com.dracoon.sdk.crypto.error.InvalidKeyPairException;
import com.dracoon.sdk.crypto.error.InvalidPasswordException;
import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(IntegrationTest.class)
public abstract class CryptoTest extends CryptoBaseTest {

    public abstract String password(UserKeyPair.Version version);

    public abstract String data(String subPath);

    public abstract String file(String subPath);

    // ### KEY PAIR CHECK TESTS ###

    @Test
    public void testCheckUserKeyPair_Rsa2048_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa2048/private_key.json"),
                data("kp_rsa2048/public_key.json"),
                password(UserKeyPair.Version.RSA2048),
                true);
    }

    @Test
    public void testCheckUserKeyPair_Rsa4096_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa4096/private_key.json"),
                data("kp_rsa4096/public_key.json"),
                password(UserKeyPair.Version.RSA4096),
                true);
    }

    @Test
    public void testCheckUserKeyPair_Rsa4096_KdfV2_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa4096_kdfv2/private_key.json"),
                data("kp_rsa4096_kdfv2/public_key.json"),
                password(UserKeyPair.Version.RSA4096),
                true);
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    @Test
    public void testEncryptFileKey_Rsa2048_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey(data("fk_rsa2048_aes256gcm/enc_file_key.json"));

        EncryptedFileKey testEfk = encryptFileKey(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                data("kp_rsa2048/public_key.json"));

        validateEncryptedFileKey(efk, testEfk);
    }

    @Test
    public void testEncryptFileKey_Rsa4096_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey(data("fk_rsa4096_aes256gcm/enc_file_key.json"));

        EncryptedFileKey testEfk = encryptFileKey(
                data("fk_rsa4096_aes256gcm/plain_file_key.json"),
                data("kp_rsa4096/public_key.json"));

        validateEncryptedFileKey(efk, testEfk);
    }

    // ### FILE KEY DECRYPTION TESTS ###

    @Test
    public void testDecryptFileKey_Rsa2048_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey(data("fk_rsa2048_aes256gcm/plain_file_key.json"));

        PlainFileKey testPfk = decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_rsa2048/private_key.json"),
                password(UserKeyPair.Version.RSA2048));

        validatePlainFileKey(pfk, testPfk);
    }

    @Test
    public void testDecryptFileKey_Rsa4096_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey(data("fk_rsa4096_aes256gcm/plain_file_key.json"));

        PlainFileKey testPfk = decryptFileKey(
                data("fk_rsa4096_aes256gcm/enc_file_key.json"),
                data("kp_rsa4096/private_key.json"),
                password(UserKeyPair.Version.RSA4096));

        validatePlainFileKey(pfk, testPfk);
    }

    // ### FILE ENCRYPTION CIPHER TESTS ###

    @Test
    public void testCreateFileEncryptionCipher_Rsa2048_Success() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(data("fk_rsa2048_aes256gcm/plain_file_key.json"));
    }

    @Test
    public void testCreateFileEncryptionCipher_Rsa4096_Success() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(data("fk_rsa4096_aes256gcm/plain_file_key.json"));
    }

    // ### FILE DECRYPTION CIPHER TESTS ###

    @Test
    public void testCreateFileDecryptionCipher_Rsa2048_Success() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(data("fk_rsa2048_aes256gcm/plain_file_key.json"));
    }

    @Test
    public void testCreateFileDecryptionCipher_Rsa4096_Success() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(data("fk_rsa4096_aes256gcm/plain_file_key.json"));
    }

}
