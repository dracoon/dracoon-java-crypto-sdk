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

        UserPrivateKey testPriKey = testUkp.getUserPrivateKey();
        assertNotNull("Private key container is null!", testPriKey);
        UserKeyPair.Version testPriKeyVer = testPriKey.getVersion();
        assertNotNull("Private key version is null!", testPriKeyVer);
        assertEquals("Private key version is invalid!", version, testPriKeyVer.getValue());
        char[] testPriKeyKey = testPriKey.getPrivateKey();
        assertNotNull("Private key is null!", testPriKeyKey);
        assertTrue("Private key is invalid!", toString(testPriKeyKey).startsWith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        UserPublicKey testPubKey = testUkp.getUserPublicKey();
        assertNotNull("Public key container is null!", testPubKey);
        UserKeyPair.Version testPubKeyVer = testPubKey.getVersion();
        assertNotNull("Public key version is null!", testPubKeyVer);
        assertEquals("Public key version is invalid!", version, testPubKeyVer.getValue());
        char[] testPubKeyKey = testPubKey.getPublicKey();
        assertNotNull("Public key is null!", testPubKeyKey);
        assertTrue("Public key is invalid!", toString(testPubKeyKey).startsWith(
                "-----BEGIN PUBLIC KEY-----"));
    }

    protected UserKeyPair generateUserKeyPair(String version, String pw)
            throws UnknownVersionException, InvalidKeyPairException, InvalidPasswordException,
            CryptoSystemException {
        UserKeyPair.Version kpv = null;
        if (version != null) {
            kpv = UserKeyPair.Version.getByValue(version);
        }
        return Crypto.generateUserKeyPair(kpv, toCharArray(pw));
    }

    // ### KEY PAIR CHECK TESTS ###

    protected void testCheckUserKeyPair(String uprkFileName, String upukFileName, String pw,
            Boolean mustBeOk) throws UnknownVersionException, InvalidKeyPairException,
            CryptoSystemException {
        UserPrivateKey uprk = readUserPrivateKey(uprkFileName);
        UserPublicKey upuk = readUserPublicKey(upukFileName);
        UserKeyPair ukp = new UserKeyPair(uprk, upuk);
        boolean testCheck = Crypto.checkUserKeyPair(ukp, toCharArray(pw));

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

    protected EncryptedFileKey encryptFileKey(String pfkFileName, String upkFileName)
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

    protected PlainFileKey decryptFileKey(String efkFileName, String upkFileName, String pw)
            throws UnknownVersionException, InvalidFileKeyException, InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        EncryptedFileKey efk = readEncryptedFileKey(efkFileName);
        UserPrivateKey upk = readUserPrivateKey(upkFileName);
        return Crypto.decryptFileKey(efk, upk, toCharArray(pw));
    }

    // ### FILE KEY CREATION TESTS ###

    protected void validateFileKey(PlainFileKey testPfk, String version) {
        assertNotNull("File key is null!", testPfk);
        assertEquals("File key version is invalid!", version, testPfk.getVersion().getValue());
    }

    protected PlainFileKey generateFileKey(String version) throws UnknownVersionException {
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

    private static char[] toCharArray(String s) {
        return s != null ? s.toCharArray() : null;
    }

    private static String toString(char[] cs) {
        return cs != null ? String.valueOf(cs) : null;
    }

    private static UserPrivateKey readUserPrivateKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPrivateKey uk = TestUtils.readData(TestUserPrivateKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPrivateKey(v, toCharArray(uk.privateKey));
    }

    private static UserPublicKey readUserPublicKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPublicKey uk = TestUtils.readData(TestUserPublicKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPublicKey(v, toCharArray(uk.publicKey));
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
