package com.dracoon.sdk.crypto;

import static org.junit.Assert.*;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.error.InvalidFileKeyException;
import com.dracoon.sdk.crypto.error.InvalidKeyPairException;
import com.dracoon.sdk.crypto.error.InvalidPasswordException;
import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.TestFileKey;
import com.dracoon.sdk.crypto.model.TestUserPrivateKey;
import com.dracoon.sdk.crypto.model.TestUserPublicKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import com.dracoon.sdk.crypto.model.UserPrivateKey;
import com.dracoon.sdk.crypto.model.UserPublicKey;
import org.junit.Test;

public class CryptoTest {

    // ### KEY PAIR CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateUserKeyPair_Rsa2048_Success() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = testGenerateUserKeyPair("A", "Qwer1234!");
        validateKeyPair(testUkp, "A");
    }

    @Test
    public void testGenerateUserKeyPair_Rsa4096_Success() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = testGenerateUserKeyPair("RSA-4096", "Qwer1234!");
        validateKeyPair(testUkp, "RSA-4096");
    }

    private void validateKeyPair(UserKeyPair testUkp, String version) {
        assertNotNull("Key pair is null!", testUkp);

        UserPrivateKey testPrik = testUkp.getUserPrivateKey();
        assertNotNull("Private key container is null!", testPrik);
        assertNotNull("Private key version is null!", testPrik.getVersion());
        assertEquals("Private key version is invalid!", version, testPrik.getVersion().getValue());
        assertNotNull("Private key is null!", testPrik.getPrivateKey());
        assertTrue("Private key is invalid!", testPrik.getPrivateKey().startsWith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        UserPublicKey testPubk = testUkp.getUserPublicKey();
        assertNotNull("Public key container is null!", testPubk);
        assertNotNull("Public key version is null!", testPubk.getVersion());
        assertEquals("Public key version is invalid!", version, testPubk.getVersion().getValue());
        assertNotNull("Public key is null!", testPubk.getPublicKey());
        assertTrue("Public key is invalid!", testPubk.getPublicKey().startsWith(
                "-----BEGIN PUBLIC KEY-----"));
    }

    // --- Tests for invalid version ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_VersionNull() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair(null, "Qwer1234!");
    }

    @Test(expected = UnknownVersionException.class)
    public void testGenerateUserKeyPair_VersionInvalid() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("Z", "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_PasswordNull() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("A", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_PasswordEmpty() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        testGenerateUserKeyPair("A", "");
    }

    // --- Test helper method ---

    public UserKeyPair testGenerateUserKeyPair(String version, String password)
            throws UnknownVersionException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        UserKeyPair.Version kpv = null;
        if (version != null) {
            kpv = UserKeyPair.Version.getByValue(version);
        }
        return Crypto.generateUserKeyPair(kpv, password);
    }

    // ### KEY PAIR CHECK TESTS ###

    // --- Test for success ---

    @Test
    public void testCheckUserKeyPair_Rsa2048_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    @Test
    public void testCheckUserKeyPair_Rsa4096_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa4096/private_key.json",
                "data/kp_rsa4096/public_key.json",
                "Qwer1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    // --- Tests for invalid key pair ---

    @Test(expected = IllegalArgumentException.class)
    public void testCheckUserKeyPair_KeyPairNull() throws InvalidKeyPairException,
            CryptoSystemException {
        Crypto.checkUserKeyPair(null, null);
    }

    // --- Tests for invalid private key ---

    @Test(expected = UnknownVersionException.class)
    public void testCheckUserKeyPair_PrivateKeyBadVersion() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_version.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadPem() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_pem.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    @Test
    public void testCheckUserKeyPair_PrivateKeyBadAsn1() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_general/private_key_bad_asn1.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");

        assertTrue("User key pair check failed!", testCheck);
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadValue() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                "data/kp_general/private_key_bad_value.json",
                "data/kp_rsa2048/public_key.json",
                "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testCheckUserKeyPair_PasswordNull() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                null);

        assertFalse("User key pair check was successful!", testCheck);
    }

    @Test
    public void testCheckUserKeyPair_PasswordInvalid() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        boolean testCheck = testCheckUserKeyPair(
                "data/kp_rsa2048/private_key.json",
                "data/kp_rsa2048/public_key.json",
                "Invalid-Password");

        assertFalse("User key pair check was successful!", testCheck);
    }

    // --- Test helper method ---

    private boolean testCheckUserKeyPair(String uprkFileName, String upukFileName, String pw)
            throws UnknownVersionException, InvalidKeyPairException, CryptoSystemException {
        UserPrivateKey uprk = readUserPrivateKey(uprkFileName);
        UserPublicKey upuk = readUserPublicKey(upukFileName);
        UserKeyPair ukp = new UserKeyPair(uprk, upuk);
        return Crypto.checkUserKeyPair(ukp, pw);
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testEncryptFileKey_Rsa2048_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey("data/fk_rsa2048_aes256gcm/enc_file_key.json");

        EncryptedFileKey testEfk = testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_rsa2048/public_key.json");

        validateEncryptedFileKey(efk, testEfk);
    }

    @Test
    public void testEncryptFileKey_Rsa4096_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey("data/fk_rsa4096_aes256gcm/enc_file_key.json");

        EncryptedFileKey testEfk = testEncryptFileKey(
                "data/fk_rsa4096_aes256gcm/plain_file_key.json",
                "data/kp_rsa4096/public_key.json");

        validateEncryptedFileKey(efk, testEfk);
    }

    private void validateEncryptedFileKey(EncryptedFileKey efk, EncryptedFileKey testEfk) {
        assertNotNull("File key is null!", testEfk.getKey());
        assertEquals("Initialization vector is incorrect!", efk.getIv(), testEfk.getIv());
        assertEquals("Tag is incorrect!", efk.getTag(), testEfk.getTag());
        assertEquals("Version is incorrect!", efk.getVersion(), testEfk.getVersion());
    }

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptFileKey_FileKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                null,
                "data/kp_rsa2048/public_key.json");
    }

    @Test(expected = UnknownVersionException.class)
    public void testEncryptFileKey_FileKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_general/plain_file_key_bad_version.json",
                "data/kp_rsa2048/public_key.json");
    }

    // --- Tests for invalid public key ---

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptFileKey_PublicKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testEncryptFileKey_PublicKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_version.json");
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadPem() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_pem.json");
    }

    // TODO: Add test for bad ASN.1 encoding.

    @Test(expected = InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadValue() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        testEncryptFileKey(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json",
                "data/kp_general/public_key_bad_value.json");
    }

    // --- Test helper method ---

    public EncryptedFileKey testEncryptFileKey(String pfkFileName, String upkFileName)
            throws UnknownVersionException, InvalidFileKeyException, InvalidKeyPairException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey(pfkFileName);
        UserPublicKey upk = readUserPublicKey(upkFileName);
        return Crypto.encryptFileKey(pfk, upk);
    }

    // ### FILE KEY DECRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testDecryptFileKey_Rsa2048_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey("data/fk_rsa2048_aes256gcm/plain_file_key.json");

        PlainFileKey testPfk = testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");

        validatePlainFileKey(pfk, testPfk);
    }

    @Test
    public void testDecryptFileKey_Rsa4096_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey("data/fk_rsa4096_aes256gcm/plain_file_key.json");

        PlainFileKey testPfk = testDecryptFileKey(
                "data/fk_rsa4096_aes256gcm/enc_file_key.json",
                "data/kp_rsa4096/private_key.json",
                "Qwer1234!");

        validatePlainFileKey(pfk, testPfk);
    }

    private void validatePlainFileKey(PlainFileKey pfk, PlainFileKey testPfk) {
        assertEquals("File key is incorrect!", pfk.getKey(), testPfk.getKey());
        assertEquals("Initialization vector is incorrect!", pfk.getIv(), testPfk.getIv());
        assertEquals("Tag is incorrect!", pfk.getTag(), testPfk.getTag());
        assertEquals("Version is incorrect!", pfk.getVersion(), testPfk.getVersion());
    }

    // --- Tests for version mismatch ---

    @Test(expected = InvalidFileKeyException.class)
    public void testDecryptFileKey_VersionMismatch() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa4096/private_key.json",
                "Qwer1234!");
    }

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_FileKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                null,
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    @Test(expected = UnknownVersionException.class)
    public void testDecryptFileKey_FileKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_general/enc_file_key_bad_version.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    @Test(expected = InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadKey() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_general/enc_file_key_bad_key.json",
                "data/kp_rsa2048/private_key.json",
                "Qwer1234!");
    }

    // --- Tests for invalid private key ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_PrivateKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                null,
                "Qwer1234!");
    }

    @Test(expected = UnknownVersionException.class)
    public void testDecryptFileKey_PrivateKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_version.json",
                "Qwer1234!");
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadPem() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_pem.json",
                "Qwer1234!");
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadValue() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_general/private_key_bad_value.json",
                "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_PasswordNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                null);
    }

    @Test(expected = InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordInvalid() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        testDecryptFileKey(
                "data/fk_rsa2048_aes256gcm/enc_file_key.json",
                "data/kp_rsa2048/private_key.json",
                "Invalid-Password");
    }

    // --- Test helper method ---

    private PlainFileKey testDecryptFileKey(String efkFileName, String upkFileName, String pw)
            throws UnknownVersionException, InvalidFileKeyException, InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey(efkFileName);
        UserPrivateKey upk = readUserPrivateKey(upkFileName);
        return Crypto.decryptFileKey(efk, upk, pw);
    }

    // ### FILE KEY CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateFileKey_Rsa2048_Success() throws UnknownVersionException {
        PlainFileKey testPfk = testGenerateFileKey("AES-256-GCM");
        validateFileKey(testPfk, "AES-256-GCM");
    }

    @Test
    public void testGenerateFileKey_Rsa4096_Success() throws UnknownVersionException {
        PlainFileKey testPfk = testGenerateFileKey("AES-256-GCM");
        validateFileKey(testPfk, "AES-256-GCM");
    }

    private void validateFileKey(PlainFileKey testPfk, String version) {
        assertNotNull("File key is null!", testPfk);
        assertEquals("File key version is invalid!", version, testPfk.getVersion().getValue());
    }

    // --- Tests for invalid version ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateFileKey_VersionNull() throws UnknownVersionException {
        testGenerateFileKey(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testGenerateFileKey_VersionInvalid() throws UnknownVersionException {
        testGenerateFileKey("Z");
    }

    // --- Test helper method ---

    private PlainFileKey testGenerateFileKey(String version) throws UnknownVersionException {
        PlainFileKey.Version pfkv = null;
        if (version != null) {
            pfkv = PlainFileKey.Version.getByValue(version);
        }
        return Crypto.generateFileKey(pfkv);
    }

    // ### FILE ENCRYPTION CIPHER TESTS ###

    // --- Test for success ---

    @Test
    public void testCreateFileEncryptionCipher_Rsa2048_Success() throws UnknownVersionException,
            CryptoSystemException {
        FileEncryptionCipher cipher = testCreateFileEncryptionCipher(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    @Test
    public void testCreateFileEncryptionCipher_Rsa4096_Success() throws UnknownVersionException,
            CryptoSystemException {
        FileEncryptionCipher cipher = testCreateFileEncryptionCipher(
                "data/fk_rsa4096_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testCreateFileEncryptionCipher_FileKeyNull() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testCreateFileEncryptionCipher_FileKeyBadVersion() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher("data/fk_general/plain_file_key_bad_version.json");
    }

    // --- Test helper method ---

    private FileEncryptionCipher testCreateFileEncryptionCipher(String pfkFileName)
            throws UnknownVersionException, CryptoSystemException {
        PlainFileKey efk = readPlainFileKey(pfkFileName);
        return Crypto.createFileEncryptionCipher(efk);
    }

    // ### FILE DECRYPTION CIPHER TESTS ###

    // --- Test for success ---

    @Test
    public void testCreateFileDecryptionCipher_Rsa2048_Success() throws UnknownVersionException,
            CryptoSystemException {
        FileDecryptionCipher cipher = testCreateFileDecryptionCipher(
                "data/fk_rsa2048_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    @Test
    public void testCreateFileDecryptionCipher_Rsa4096_Success() throws UnknownVersionException,
            CryptoSystemException {
        FileDecryptionCipher cipher = testCreateFileDecryptionCipher(
                "data/fk_rsa4096_aes256gcm/plain_file_key.json");

        assertNotNull("Cipher is null!", cipher);
    }

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testCreateFileDecryptionCipher_FileKeyNull() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testCreateFileDecryptionCipher_FileKeyBadVersion() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher("data/fk_general/plain_file_key_bad_version.json");
    }

    // --- Test helper method ---

    private FileDecryptionCipher testCreateFileDecryptionCipher(String pfkFileName)
            throws UnknownVersionException, CryptoSystemException {
        PlainFileKey efk = readPlainFileKey(pfkFileName);
        return Crypto.createFileDecryptionCipher(efk);
    }

    // ### HELPER METHODS ###

    private static UserPrivateKey readUserPrivateKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPrivateKey uk = TestUtils.readData(TestUserPrivateKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPrivateKey(v, uk.privateKey);
    }

    private static UserPublicKey readUserPublicKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPublicKey uk = TestUtils.readData(TestUserPublicKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPublicKey(v, uk.publicKey);
    }

    private static EncryptedFileKey readEncryptedFileKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestFileKey fk = TestUtils.readData(TestFileKey.class, fileName);
        EncryptedFileKey.Version v = EncryptedFileKey.Version.getByValue(fk.version);
        EncryptedFileKey efk = new EncryptedFileKey(v, fk.key, fk.iv);
        efk.setTag(fk.tag);
        return efk;
    }

    private static PlainFileKey readPlainFileKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestFileKey fk = TestUtils.readData(TestFileKey.class, fileName);
        PlainFileKey.Version v = PlainFileKey.Version.getByValue(fk.version);
        PlainFileKey pfk = new PlainFileKey(v, fk.key, fk.iv);
        pfk.setTag(fk.tag);
        return pfk;
    }

}
