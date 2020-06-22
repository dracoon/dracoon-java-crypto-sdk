package com.dracoon.sdk.crypto;

import static org.junit.Assert.*;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.error.InvalidFileKeyException;
import com.dracoon.sdk.crypto.error.InvalidKeyPairException;
import com.dracoon.sdk.crypto.error.InvalidPasswordException;
import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import com.dracoon.sdk.crypto.model.UserPrivateKey;
import com.dracoon.sdk.crypto.model.UserPublicKey;
import org.junit.Test;

public class CryptoTest {

    // ### KEY PAIR CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateUserKeyPair_Success() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = testGenerateUserKeyPair("A", "Qwer1234!");

        assertNotNull("Key pair is null!", testUkp);

        UserPrivateKey testPrik = testUkp.getUserPrivateKey();
        assertNotNull("Private key container is null!", testPrik);
        assertNotNull("Private key version is null!", testPrik.getVersion());
        assertFalse("Private key version is empty!", testPrik.getVersion().isEmpty());
        assertEquals("Private key version is invalid!", "A", testPrik.getVersion());
        assertNotNull("Private key is null!", testPrik.getPrivateKey());
        assertTrue("Private key is invalid!", testPrik.getPrivateKey().startsWith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        UserPublicKey testPubk = testUkp.getUserPublicKey();
        assertNotNull("Public key container is null!", testPubk);
        assertNotNull("Public key version is null!", testPubk.getVersion());
        assertFalse("Public key version is empty!", testPubk.getVersion().isEmpty());
        assertEquals("Public key version is invalid!", "A", testPubk.getVersion());
        assertNotNull("Public key is null!", testPubk.getPublicKey());
        assertTrue("Public key is invalid!", testPubk.getPublicKey().startsWith(
                "-----BEGIN PUBLIC KEY-----"));
    }

    // --- Tests for invalid version ---

    @Test(expected=InvalidKeyPairException.class)
    public void testGenerateUserKeyPair_VersionNull() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair(null, "Qwer1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testGenerateUserKeyPair_VersionInvalid() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("Z", "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected=InvalidPasswordException.class)
    public void testGenerateUserKeyPair_PasswordNull() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("A", null);
    }

    @Test(expected=InvalidPasswordException.class)
    public void testGenerateUserKeyPair_PasswordEmpty() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("A", "");
    }

    // --- Test helper method ---

    private UserKeyPair testGenerateUserKeyPair(String version, String password)
            throws InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        return Crypto.generateUserKeyPair(version, password);
    }

    // ### KEY PAIR CHECK TESTS ###

    // --- Test for success ---

    @Test
    public void testCheckUserKeyPair_Success() throws InvalidKeyPairException,
            CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    // --- Tests for invalid key pair ---

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_KeyPairNull() throws InvalidKeyPairException,
            CryptoSystemException {
        Crypto.checkUserKeyPair(null, null);
    }

    // --- Tests for invalid private key ---

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadVersion() throws InvalidKeyPairException,
            CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_version.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadPem() throws InvalidKeyPairException,
            CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_pem.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    @Test
    public void testCheckUserKeyPair_PrivateKeyBadAsn1() throws InvalidKeyPairException,
            CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_general/private_key_bad_asn1.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadValue() throws InvalidKeyPairException,
            CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_value.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test
    public void testCheckUserKeyPair_PasswordNull() throws InvalidKeyPairException,
            CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                null);

        assertFalse("User key pair check was successful!", testCheck);
    }

    @Test
    public void testCheckUserKeyPair_PasswordInvalid() throws InvalidKeyPairException,
            CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                "Invalid-Password");

        assertFalse("User key pair check was successful!", testCheck);
    }

    // --- Test helper method ---

    private boolean testCheckUserKeyPair(String uprkFileName, String upukFileName, String pw)
            throws InvalidKeyPairException, CryptoSystemException {
        UserPrivateKey uprk = TestUtils.readData(UserPrivateKey.class, uprkFileName);
        UserPublicKey upuk = TestUtils.readData(UserPublicKey.class, upukFileName);
        UserKeyPair ukp = new UserKeyPair(uprk, upuk);
        return Crypto.checkUserKeyPair(ukp, pw);
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testEncryptFileKey_Success() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = TestUtils.readData(
                EncryptedFileKey.class,
                "data/fk_rsa2048_aes256gcm/enc_file_key.json");

        EncryptedFileKey testEfk = testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_rsa2048/public_key.json");

        assertNotNull("File key is null!", testEfk.getKey());
        assertEquals("Initialization vector is incorrect!", efk.getIv(), testEfk.getIv());
        assertEquals("Tag is incorrect!", efk.getTag(), testEfk.getTag());
        assertEquals("Version is incorrect!", efk.getVersion(), testEfk.getVersion());
    }

    // --- Tests for invalid file key ---

    @Test(expected=InvalidFileKeyException.class)
    public void testEncryptFileKey_FileKeyNull() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                null,
                "data/kp_rsa2048/public_key.json");
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testEncryptFileKey_FileKeyBadVersion() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_general/plain_file_key_bad_version.json",
                "data/kp_rsa2048/public_key.json");
    }

    // --- Tests for invalid public key ---

    @Test(expected=InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyNull() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                null);
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadVersion() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_version.json");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadPem() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_pem.json");
    }

    // TODO: Add test for bad ASN.1 encoding.

    @Test(expected=InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadValue() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_value.json");
    }

    // --- Test helper method ---

    public EncryptedFileKey testEncryptFileKey(String pfkFileName, String upkFileName)
            throws InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        UserPublicKey upk = TestUtils.readData(UserPublicKey.class, upkFileName);
        return Crypto.encryptFileKey(pfk, upk);
    }

    // ### FILE KEY DECRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testDecryptFileKey_Success() throws InvalidFileKeyException, InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(
                PlainFileKey.class,
                "data/fk_rsa2048_aes256gcm/plain_file_key.json");

        PlainFileKey testPfk = testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");

        assertEquals("File key is incorrect!", pfk.getKey(), testPfk.getKey());
        assertEquals("Initialization vector is incorrect!", pfk.getIv(), testPfk.getIv());
        assertEquals("Tag is incorrect!", pfk.getTag(), testPfk.getTag());
        assertEquals("Version is incorrect!", pfk.getVersion(), testPfk.getVersion());
    }

    // --- Tests for invalid file key ---

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyNull() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                null,
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadVersion() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_general/enc_file_key_bad_version.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadKey() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_general/enc_file_key_bad_key.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    // --- Tests for invalid private key ---

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyNull() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                null,
                "Qwer1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadVersion() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_version.json",
                "Qwer1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadPem() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_pem.json",
                "Qwer1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadValue() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_value.json",
                "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected=InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordNull() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                null);
    }

    @Test(expected=InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordInvalid() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                "Invalid-Password");
    }

    // --- Test helper method ---

    private PlainFileKey testDecryptFileKey(String efkFileName, String upkFileName, String pw)
            throws InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        EncryptedFileKey efk = TestUtils.readData(EncryptedFileKey.class, efkFileName);
        UserPrivateKey upk = TestUtils.readData(UserPrivateKey.class, upkFileName);
        return Crypto.decryptFileKey(efk, upk, pw);
    }

    // ### FILE KEY CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateFileKey_Success() {
        PlainFileKey testPfk = Crypto.generateFileKey();
        assertNotNull("File key is null!", testPfk);
        assertEquals("File key version is invalid!", "A", testPfk.getVersion());
    }

    // --- Tests for invalid version ---

    @Test(expected=InvalidFileKeyException.class)
    public void testGenerateFileKey_VersionNull() throws InvalidFileKeyException {
        Crypto.generateFileKey(null);
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testGenerateFileKey_VersionInvalid() throws InvalidFileKeyException {
        Crypto.generateFileKey("Z");
    }

    // ### FILE ENCRYPTION CIPHER TESTS ###

    // --- Test for success ---

    @Test
    public void testCreateFileEncryptionCipher_Success() throws InvalidFileKeyException,
            CryptoSystemException {
        FileEncryptionCipher cipher = testCreateFileEncryptionCipher(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    // --- Tests for invalid file key ---

    @Test(expected=InvalidFileKeyException.class)
    public void testCreateFileEncryptionCipher_FileKeyNull() throws InvalidFileKeyException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(null);
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testCreateFileEncryptionCipher_FileKeyBadVersion() throws InvalidFileKeyException,
            CryptoSystemException {
        testCreateFileEncryptionCipher("data/fk_general/plain_file_key_bad_version.json");
    }

    // --- Test helper method ---

    private FileEncryptionCipher testCreateFileEncryptionCipher(String pfkFileName)
            throws InvalidFileKeyException, CryptoSystemException {
        PlainFileKey efk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        return Crypto.createFileEncryptionCipher(efk);
    }

    // ### FILE DECRYPTION CIPHER TESTS ###

    // --- Test for success ---

    @Test
    public void testCreateFileDecryptionCipher_Success() throws InvalidFileKeyException,
            CryptoSystemException {
        FileDecryptionCipher cipher = testCreateFileDecryptionCipher(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    // --- Tests for invalid file key ---

    @Test(expected=InvalidFileKeyException.class)
    public void testCreateFileDecryptionCipher_FileKeyNull() throws InvalidFileKeyException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(null);
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testCreateFileDecryptionCipher_FileKeyBadVersion() throws InvalidFileKeyException,
            CryptoSystemException {
        testCreateFileDecryptionCipher("data/fk_general/plain_file_key_bad_version.json");
    }

    // --- Test helper method ---

    private FileDecryptionCipher testCreateFileDecryptionCipher(String pfkFileName)
            throws InvalidFileKeyException, CryptoSystemException {
        PlainFileKey efk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        return Crypto.createFileDecryptionCipher(efk);
    }

}
