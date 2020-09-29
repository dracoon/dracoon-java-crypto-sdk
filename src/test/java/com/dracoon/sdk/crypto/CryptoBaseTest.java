package com.dracoon.sdk.crypto;

import java.util.Objects;

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

import static org.junit.Assert.*;

public abstract class CryptoBaseTest {

    // ### KEY PAIR CREATION TESTS ###

    protected void validateKeyPair(UserKeyPair testUkp, String version) {
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

    protected UserKeyPair testGenerateUserKeyPair(String version, String password)
            throws UnknownVersionException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        UserKeyPair.Version kpv = null;
        if (version != null) {
            kpv = UserKeyPair.Version.getByValue(version);
        }
        return Crypto.generateUserKeyPair(kpv, password);
    }

    // ### KEY PAIR CHECK TESTS ###

    protected void testCheckUserKeyPair(String uprkFileName, String upukFileName, String pw,
            Boolean mustBeOk) throws UnknownVersionException, InvalidKeyPairException,
            CryptoSystemException {
        UserPrivateKey uprk = readUserPrivateKey(uprkFileName);
        UserPublicKey upuk = readUserPublicKey(upukFileName);
        UserKeyPair ukp = new UserKeyPair(uprk, upuk);
        boolean testCheck = Crypto.checkUserKeyPair(ukp, pw);

        if (Objects.equals(mustBeOk, Boolean.TRUE)) {
            assertTrue("User key pair check failed!", testCheck);
        } else if (Objects.equals(mustBeOk, Boolean.FALSE)) {
            assertFalse("User key pair check was successful!", testCheck);
        }
    }

    // ### FILE KEY ENCRYPTION TESTS ###

    protected void validateEncryptedFileKey(EncryptedFileKey efk, EncryptedFileKey testEfk) {
        assertNotNull("File key is null!", testEfk.getKey());
        assertEquals("Initialization vector is incorrect!", efk.getIv(), testEfk.getIv());
        assertEquals("Tag is incorrect!", efk.getTag(), testEfk.getTag());
        assertEquals("Version is incorrect!", efk.getVersion(), testEfk.getVersion());
    }

    protected EncryptedFileKey testEncryptFileKey(String pfkFileName, String upkFileName)
            throws UnknownVersionException, InvalidFileKeyException, InvalidKeyPairException,
            CryptoSystemException {
        PlainFileKey pfk = readPlainFileKey(pfkFileName);
        UserPublicKey upk = readUserPublicKey(upkFileName);
        return Crypto.encryptFileKey(pfk, upk);
    }

    // ### FILE KEY DECRYPTION TESTS ###

    protected void validatePlainFileKey(PlainFileKey pfk, PlainFileKey testPfk) {
        assertEquals("File key is incorrect!", pfk.getKey(), testPfk.getKey());
        assertEquals("Initialization vector is incorrect!", pfk.getIv(), testPfk.getIv());
        assertEquals("Tag is incorrect!", pfk.getTag(), testPfk.getTag());
        assertEquals("Version is incorrect!", pfk.getVersion(), testPfk.getVersion());
    }

    protected PlainFileKey testDecryptFileKey(String efkFileName, String upkFileName, String pw)
            throws UnknownVersionException, InvalidFileKeyException, InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey(efkFileName);
        UserPrivateKey upk = readUserPrivateKey(upkFileName);
        return Crypto.decryptFileKey(efk, upk, pw);
    }

    // ### FILE KEY CREATION TESTS ###

    protected void validateFileKey(PlainFileKey testPfk, String version) {
        assertNotNull("File key is null!", testPfk);
        assertEquals("File key version is invalid!", version, testPfk.getVersion().getValue());
    }

    protected PlainFileKey testGenerateFileKey(String version) throws UnknownVersionException {
        PlainFileKey.Version pfkv = null;
        if (version != null) {
            pfkv = PlainFileKey.Version.getByValue(version);
        }
        return Crypto.generateFileKey(pfkv);
    }

    // ### FILE ENCRYPTION CIPHER TESTS ###

    protected void testCreateFileEncryptionCipher(String pfkFileName)
            throws UnknownVersionException, CryptoSystemException {
        PlainFileKey efk = readPlainFileKey(pfkFileName);
        FileEncryptionCipher cipher = Crypto.createFileEncryptionCipher(efk);

        assertNotNull("Cipher is null!", cipher);
    }

    // ### FILE DECRYPTION CIPHER TESTS ###

    protected void testCreateFileDecryptionCipher(String pfkFileName)
            throws UnknownVersionException, CryptoSystemException {
        PlainFileKey efk = readPlainFileKey(pfkFileName);
        FileDecryptionCipher cipher = Crypto.createFileDecryptionCipher(efk);

        assertNotNull("Cipher is null!", cipher);
    }

    // ### HELPER METHODS ###

    protected static UserPrivateKey readUserPrivateKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPrivateKey uk = TestUtils.readData(TestUserPrivateKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPrivateKey(v, uk.privateKey);
    }

    protected static UserPublicKey readUserPublicKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPublicKey uk = TestUtils.readData(TestUserPublicKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPublicKey(v, uk.publicKey);
    }

    protected static EncryptedFileKey readEncryptedFileKey(String fileName)
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

    protected static PlainFileKey readPlainFileKey(String fileName)
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
