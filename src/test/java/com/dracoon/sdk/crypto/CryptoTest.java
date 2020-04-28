package com.dracoon.sdk.crypto;

import static org.junit.Assert.*;

import org.junit.Test;

import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import com.dracoon.sdk.crypto.model.UserPrivateKey;
import com.dracoon.sdk.crypto.model.UserPublicKey;

public class CryptoTest {

    // ### KEY PAIR CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateUserKeyPair_Success() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = testGenerateUserKeyPair("A", "Qwer1234");

        assertNotNull("Key pair is null!", testUkp);

        UserPrivateKey testPrik = testUkp.getUserPrivateKey();
        assertNotNull("Private key container is null!", testPrik);
        assertNotNull("Private key version is null!", testPrik.getVersion());
        assertTrue("Private key version is empty!", !testPrik.getVersion().isEmpty());
        assertTrue("Private key version is invalid!", testPrik.getVersion().equals("A"));
        assertNotNull("Private key is null!", testPrik.getPrivateKey());
        assertTrue("Private key is invalid!", testPrik.getPrivateKey().startsWith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        UserPublicKey testPubk = testUkp.getUserPublicKey();
        assertNotNull("Public key container is null!", testPubk);
        assertNotNull("Public key version is null!", testPubk.getVersion());
        assertTrue("Public key version is empty!", !testPubk.getVersion().isEmpty());
        assertTrue("Public key version is invalid!", testPubk.getVersion().equals("A"));
        assertNotNull("Public key is null!", testPubk.getPublicKey());
        assertTrue("Public key is invalid!", testPubk.getPublicKey().startsWith(
                "-----BEGIN PUBLIC KEY-----"));
    }

    // --- Tests for invalid version ---

    @Test(expected=InvalidKeyPairException.class)
    public void testGenerateUserKeyPair_VersionNull() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair(null, "Qwer1234");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testGenerateUserKeyPair_VersionInvalid() throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("Z", "Qwer1234");
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
        boolean testCheck = testCheckUserKeyPair("data/private_key.json", "Pass1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    // --- Tests for invalid private key ---

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyNull() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testCheckUserKeyPair(null, "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadVersion() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testCheckUserKeyPair("data/private_key_bad_version.json", "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadPem() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testCheckUserKeyPair("data/private_key_bad_pem.json", "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadValue() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testCheckUserKeyPair("data/private_key_bad_value.json", "Pass1234!");
    }

    // --- Tests for invalid password ---

    @Test
    public void testCheckUserKeyPair_PasswordNull() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair("data/private_key.json", null);

        assertFalse("User key pair check was successful!", testCheck);
    }

    @Test
    public void testCheckUserKeyPair_PasswordInvalid() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair("data/private_key.json", "Invalid-Password");

        assertFalse("User key pair check was successful!", testCheck);
    }

    // --- Test helper method ---

    private boolean testCheckUserKeyPair(String upkFileName, String pw)
            throws InvalidKeyPairException, CryptoSystemException {
        UserKeyPair ukp = new UserKeyPair();
        ukp.setUserPrivateKey(TestUtils.readData(UserPrivateKey.class, upkFileName));
        return Crypto.checkUserKeyPair(ukp, pw);
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testEncryptFileKey_Success() throws InvalidFileKeyException,
            InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = TestUtils.readData(EncryptedFileKey.class, "data/enc_file_key.json");
        EncryptedFileKey testEfk = testEncryptFileKey("data/plain_file_key.json",
                                                      "data/public_key.json");

        assertNotNull("File key is null!", testEfk.getKey());
        assertEquals("Initialization vector is incorrect!", efk.getIv(), testEfk.getIv());
        assertEquals("Tag is incorrect!", efk.getTag(), testEfk.getTag());
        assertEquals("Version is incorrect!", efk.getVersion(), testEfk.getVersion());
    }

    // --- Tests for invalid file key ---

    // TODO !!!

    // --- Tests for invalid public key ---

    // TODO !!!

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
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key.json");
        PlainFileKey testPfk = testDecryptFileKey("data/enc_file_key.json",
                                                  "data/private_key.json",
                                                  "Pass1234!");

        assertEquals("File key is incorrect!", pfk.getKey(), testPfk.getKey());
        assertEquals("Initialization vector is incorrect!", pfk.getIv(), testPfk.getIv());
        assertEquals("Tag is incorrect!", pfk.getTag(), testPfk.getTag());
        assertEquals("Version is incorrect!", pfk.getVersion(), testPfk.getVersion());
    }

    // --- Tests for invalid file key ---

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyNull() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey(null,
                           "data/private_key.json",
                           "Pass1234!");
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadVersion() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key_bad_version.json",
                           "data/private_key.json",
                           "Pass1234!");
    }

    @Test(expected=InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadKey() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key_bad_key.json",
                           "data/private_key.json",
                           "Pass1234!");
    }

    // --- Tests for invalid private key ---

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyNull() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           null,
                           "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadVersion() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           "data/private_key_bad_version.json",
                           "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadPem() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           "data/private_key_bad_pem.json",
                           "Pass1234!");
    }

    @Test(expected=InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadValue() throws InvalidFileKeyException,
    InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           "data/private_key_bad_value.json",
                           "Pass1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected=InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordNull() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           "data/private_key.json",
                           null);
    }

    @Test(expected=InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordInvalid() throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testDecryptFileKey("data/enc_file_key.json",
                           "data/private_key.json",
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

    // ### FILE ENCRYPTION CIPHER TESTS ###

    // TODO !!!

    // ### FILE DECRYPTION CIPHER TESTS ###

    // TODO !!!

}
