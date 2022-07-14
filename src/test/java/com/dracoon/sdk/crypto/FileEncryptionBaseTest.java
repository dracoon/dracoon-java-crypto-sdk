package com.dracoon.sdk.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

import static org.junit.Assert.*;

public abstract class FileEncryptionBaseTest {

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    protected void testEncryptSingleBlock(String pfkFileName, String pfcFileName, String efcFileName,
            Boolean mustFcMatch, Boolean mustFtMatch) throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile(pfcFileName);
        byte[] efc = TestUtils.readFile(efcFileName);

        FileEncryptionCipher c = Crypto.createFileEncryptionCipher(pfk);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        EncryptedDataContainer edc;

        // Encrypt block
        edc = c.processBytes(new PlainDataContainer(pfc));
        os.write(edc.getContent());
        // Complete encryption
        edc = c.doFinal();
        os.write(edc.getContent());

        byte[] testFt = edc.getTag();
        byte[] testEfc = os.toByteArray();

        assertFileContentMatch(mustFcMatch, efc, testEfc);
        assertFileTagMatch(mustFtMatch, ft, testFt);
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    protected void testEncryptMultiBlock(String pfkFileName, String pfcFileName, String efcFileName,
            Boolean mustFcMatch, Boolean mustFtMatch) throws IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile(pfcFileName);
        byte[] efc = TestUtils.readFile(efcFileName);

        FileEncryptionCipher c = Crypto.createFileEncryptionCipher(pfk);

        ByteArrayInputStream is = new ByteArrayInputStream(pfc);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] buffer = new byte[16];
        int count;

        // Encrypt blocks
        while ((count = is.read(buffer)) != -1) {
            byte[] bytes = createByteArray(buffer, count);
            EncryptedDataContainer testEdc = c.processBytes(new PlainDataContainer(bytes));
            os.write(testEdc.getContent());
        }

        // Complete encryption
        EncryptedDataContainer testEdc = c.doFinal();
        os.write(testEdc.getContent());

        byte[] testFt = testEdc.getTag();
        byte[] testEfc = os.toByteArray();

        assertFileContentMatch(mustFcMatch, efc, testEfc);
        assertFileTagMatch(mustFtMatch, ft, testFt);
    }

    private static byte[] createByteArray(byte[] bytes, int len) {
        byte[] b = new byte[len];
        System.arraycopy(bytes, 0, b, 0, len);
        return b;
    }

    // ### ILLEGAL DATA CONTAINER TESTS ###

    protected void testEncryptProcessArguments(String pfkFileName, PlainDataContainer pdc)
            throws IllegalArgumentException, IllegalStateException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        FileEncryptionCipher c = Crypto.createFileEncryptionCipher(pfk);
        c.processBytes(pdc);
    }

    // ### HELPER METHODS ###

    private static void assertFileContentMatch(Boolean mustFcMatch, byte[] pfc, byte[] testPfc) {
        boolean isFcEqual = Arrays.equals(pfc, testPfc);
        if (Objects.equals(mustFcMatch, Boolean.TRUE)) {
            assertTrue("File content does not match!", isFcEqual);
        } else if (Objects.equals(mustFcMatch, Boolean.FALSE)) {
            assertFalse("File content does match!", isFcEqual);
        }
    }

    private static void assertFileTagMatch(Boolean mustFtMatch, byte[] ft, byte[] testFt) {
        boolean isFtEqual = Arrays.equals(ft, testFt);
        if (Objects.equals(mustFtMatch, Boolean.TRUE)) {
            assertTrue("File tag does not match!", isFtEqual);
        } else if (Objects.equals(mustFtMatch, Boolean.FALSE)) {
            assertFalse("File tag does match!", isFtEqual);
        }
    }

}
