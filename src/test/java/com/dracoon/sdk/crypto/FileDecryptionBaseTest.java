package com.dracoon.sdk.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import com.dracoon.sdk.crypto.error.BadFileException;
import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

import static org.junit.Assert.*;

public abstract class FileDecryptionBaseTest {

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    protected void testDecryptSingleBlock(String pfkFileName, String efcFileName, String pfcFileName,
            Boolean mustFcMatch) throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile(efcFileName);
        byte[] pfc = TestUtils.readFile(pfcFileName);

        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PlainDataContainer pdc;

        // Decrypt block
        pdc = c.processBytes(new EncryptedDataContainer(efc, null));
        os.write(pdc.getContent());
        // Complete decryption
        pdc = c.doFinal(new EncryptedDataContainer(null, ft));
        os.write(pdc.getContent());

        byte[] testPfc = os.toByteArray();

        assertFileContentMatch(mustFcMatch, pfc, testPfc);
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    protected void testDecryptMultiBlock(String pfkFileName, String efcFileName, String pfcFileName,
            Boolean mustFcMatch) throws BadFileException, IllegalArgumentException,
            IllegalStateException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile(efcFileName);
        byte[] pfc = TestUtils.readFile(pfcFileName);

        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);

        ByteArrayInputStream is = new ByteArrayInputStream(efc);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] buffer = new byte[16];
        int count;

        // Decrypt blocks
        while ((count = is.read(buffer)) != -1) {
            byte[] bytes = createByteArray(buffer, count);
            PlainDataContainer testPdc = c.processBytes(new EncryptedDataContainer(bytes, null));
            os.write(testPdc.getContent());
        }

        // Complete decryption
        PlainDataContainer testPdc = c.doFinal(new EncryptedDataContainer(null, ft));
        os.write(testPdc.getContent());

        byte[] testPfc = os.toByteArray();

        assertFileContentMatch(mustFcMatch, pfc, testPfc);
    }

    private static byte[] createByteArray(byte[] bytes, int len) {
        byte[] b = new byte[len];
        System.arraycopy(bytes, 0, b, 0, len);
        return b;
    }

    // ### ILLEGAL DATA CONTAINER TESTS ###

    protected void testDecryptProcessArguments(String pfkFileName, EncryptedDataContainer edc)
            throws IllegalArgumentException, IllegalStateException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);
        c.processBytes(edc);
    }

    protected void testDecryptDoFinalArguments(String pfkFileName, EncryptedDataContainer edc)
            throws BadFileException, IllegalArgumentException, IllegalStateException,
            CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, pfkFileName);
        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);
        c.doFinal(edc);
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

}
