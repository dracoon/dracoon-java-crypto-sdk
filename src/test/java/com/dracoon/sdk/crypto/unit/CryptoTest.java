package com.dracoon.sdk.crypto.unit;

import com.dracoon.sdk.crypto.Crypto;
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

import static com.dracoon.sdk.crypto.unit.TestHelper.*;

public class CryptoTest extends CryptoBaseTest {

    // ### KEY PAIR CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateUserKeyPair_Rsa2048_Success() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = generateUserKeyPair("A");
        validateKeyPair(testUkp, "A");
    }

    @Test
    public void testGenerateUserKeyPair_Rsa4096_Success() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        UserKeyPair testUkp = generateUserKeyPair("RSA-4096");
        validateKeyPair(testUkp, "RSA-4096");
    }

    // --- Tests for invalid version ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_VersionNull() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        generateUserKeyPair(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testGenerateUserKeyPair_VersionInvalid() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        generateUserKeyPair("Z");
    }

    private UserKeyPair generateUserKeyPair(String version) throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        return super.generateUserKeyPair(version, "Qwer1234!");
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_PasswordNull() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        generateUserKeyPair("A", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateUserKeyPair_PasswordEmpty() throws UnknownVersionException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        generateUserKeyPair("A", "");
    }

    // ### KEY PAIR CHECK TESTS ###

    // --- Test for success ---

    @Test
    public void testCheckUserKeyPair_Rsa2048_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa2048/private_key.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw.txt"),
                true);
    }

    @Test
    public void testCheckUserKeyPair_Rsa4096_Success() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa4096/private_key.json"),
                data("kp_rsa4096/public_key.json"),
                data("kp_general/pw.txt"),
                true);
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
                data("kp_general/private_key_bad_version.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw.txt"),
                null);
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadPem() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_general/private_key_bad_pem.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw.txt"),
                null);
    }

    @Test
    public void testCheckUserKeyPair_PrivateKeyBadAsn1() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_general/private_key_bad_asn1.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw.txt"),
                true);
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testCheckUserKeyPair_PrivateKeyBadValue() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_general/private_key_bad_value.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw.txt"),
                null);
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testCheckUserKeyPair_PasswordNull() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa2048/private_key.json"),
                data("kp_rsa2048/public_key.json"),
                null,
                false);
    }

    @Test
    public void testCheckUserKeyPair_PasswordInvalid() throws UnknownVersionException,
            InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa2048/private_key.json"),
                data("kp_rsa2048/public_key.json"),
                data("kp_general/pw_invalid.txt"),
                false);
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    // --- Test for success ---

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

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptFileKey_FileKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                null,
                data("kp_rsa2048/public_key.json"));
    }

    @Test(expected = UnknownVersionException.class)
    public void testEncryptFileKey_FileKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                data("fk_general/plain_file_key_bad_version.json"),
                data("kp_rsa2048/public_key.json"));
    }

    // --- Tests for invalid public key ---

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptFileKey_PublicKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testEncryptFileKey_PublicKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                data("kp_general/public_key_bad_version.json"));
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadPem() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                data("kp_general/public_key_bad_pem.json"));
    }

    // TODO: Add test for bad ASN.1 encoding.

    @Test(expected = InvalidKeyPairException.class)
    public void testEncryptFileKey_PublicKeyBadValue() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, CryptoSystemException {
        encryptFileKey(
                data("fk_rsa2048_aes256gcm/plain_file_key.json"),
                data("kp_general/public_key_bad_value.json"));
    }

    // ### FILE KEY DECRYPTION TESTS ###

    // --- Test for success ---

    @Test
    public void testDecryptFileKey_Rsa2048_Success() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey(data("fk_rsa2048_aes256gcm/plain_file_key.json"));

        PlainFileKey testPfk = decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_rsa2048/private_key.json"),
                data("kp_general/pw.txt"));

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
                data("kp_general/pw.txt"));

        validatePlainFileKey(pfk, testPfk);
    }

    // --- Tests for version mismatch ---

    @Test(expected = InvalidFileKeyException.class)
    public void testDecryptFileKey_VersionMismatch() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_rsa4096/private_key.json"),
                data("kp_general/pw.txt"));
    }

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_FileKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                null,
                data("kp_rsa2048/private_key.json"),
                data("kp_general/pw.txt"));
    }

    @Test(expected = UnknownVersionException.class)
    public void testDecryptFileKey_FileKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_general/enc_file_key_bad_version.json"),
                data("kp_rsa2048/private_key.json"),
                data("kp_general/pw.txt"));
    }

    @Test(expected = InvalidFileKeyException.class)
    public void testDecryptFileKey_FileKeyBadKey() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_general/enc_file_key_bad_key.json"),
                data("kp_rsa2048/private_key.json"),
                data("kp_general/pw.txt"));
    }

    // --- Tests for invalid private key ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_PrivateKeyNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                null,
                data("kp_general/pw.txt"));
    }

    @Test(expected = UnknownVersionException.class)
    public void testDecryptFileKey_PrivateKeyBadVersion() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_general/private_key_bad_version.json"),
                data("kp_general/pw.txt"));
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadPem() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_general/private_key_bad_pem.json"),
                data("kp_general/pw.txt"));
    }

    @Test(expected = InvalidKeyPairException.class)
    public void testDecryptFileKey_PrivateKeyBadValue() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_general/private_key_bad_value.json"),
                data("kp_general/pw.txt"));
    }

    // --- Tests for invalid password ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptFileKey_PasswordNull() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_rsa2048/private_key.json"),
                null);
    }

    @Test(expected = InvalidPasswordException.class)
    public void testDecryptFileKey_PasswordInvalid() throws UnknownVersionException,
            InvalidFileKeyException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        decryptFileKey(
                data("fk_rsa2048_aes256gcm/enc_file_key.json"),
                data("kp_rsa2048/private_key.json"),
                data("kp_general/pw_invalid.txt"));
    }

    // ### FILE KEY CREATION TESTS ###

    // --- Test for success ---

    @Test
    public void testGenerateFileKey_Rsa2048_Success() throws UnknownVersionException {
        PlainFileKey testPfk = generateFileKey("A");
        validateFileKey(testPfk, "A");
    }

    @Test
    public void testGenerateFileKey_Rsa4096_Success() throws UnknownVersionException {
        PlainFileKey testPfk = generateFileKey("A");
        validateFileKey(testPfk, "A");
    }

    // --- Tests for invalid version ---

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateFileKey_VersionNull() throws UnknownVersionException {
        generateFileKey(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testGenerateFileKey_VersionInvalid() throws UnknownVersionException {
        generateFileKey("Z");
    }

    // ### FILE ENCRYPTION CIPHER TESTS ###

    // --- Test for success ---

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

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testCreateFileEncryptionCipher_FileKeyNull() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testCreateFileEncryptionCipher_FileKeyBadVersion() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileEncryptionCipher(data("fk_general/plain_file_key_bad_version.json"));
    }

    // ### FILE DECRYPTION CIPHER TESTS ###

    // --- Test for success ---

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

    // --- Tests for invalid file key ---

    @Test(expected = IllegalArgumentException.class)
    public void testCreateFileDecryptionCipher_FileKeyNull() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(null);
    }

    @Test(expected = UnknownVersionException.class)
    public void testCreateFileDecryptionCipher_FileKeyBadVersion() throws UnknownVersionException,
            CryptoSystemException {
        testCreateFileDecryptionCipher(data("fk_general/plain_file_key_bad_version.json"));
    }

}
