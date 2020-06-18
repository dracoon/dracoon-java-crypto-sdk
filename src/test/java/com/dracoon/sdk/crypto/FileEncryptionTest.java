package com.dracoon.sdk.crypto;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import org.junit.Test;

public class FileEncryptionTest {

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    @Test
    public void testEncryptSingleBlock_Success() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile("files/plain_file.txt");
        byte[] efc = TestUtils.readFile("files/enc_file.txt");

        PlainDataContainer testPdc = new PlainDataContainer(pfc);
        EncryptedDataContainer testEdc = testEncryptSingleBlock(pfk, testPdc);

        assertTrue("File content does not match!", Arrays.equals(efc, testEdc.getContent()));
        assertTrue("File tag does not match!", Arrays.equals(ft, testEdc.getTag()));
    }

    @Test
    public void testEncryptSingleBlock_DifferentContent() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key.json");
        byte[] pfc = TestUtils.readFile("files/plain_file_modified.txt");
        byte[] efc = TestUtils.readFile("files/enc_file.txt");

        PlainDataContainer testPdc = new PlainDataContainer(pfc);
        EncryptedDataContainer testEdc = testEncryptSingleBlock(pfk, testPdc);

        assertFalse("File content does match!", Arrays.equals(efc, testEdc.getContent()));
    }

    @Test
    public void testEncryptSingleBlock_DifferentTag() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key_bad_tag.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile("files/plain_file.txt");

        PlainDataContainer testPdc = new PlainDataContainer(pfc);
        EncryptedDataContainer testEdc = testEncryptSingleBlock(pfk, testPdc);

        assertFalse("File tag does not match!", Arrays.equals(ft, testEdc.getTag()));
    }

    @Test
    public void testEncryptSingleBlock_DifferentKey() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key_bad_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile("files/plain_file.txt");
        byte[] efc = TestUtils.readFile("files/enc_file.txt");

        PlainDataContainer testPdc = new PlainDataContainer(pfc);
        EncryptedDataContainer testEdc = testEncryptSingleBlock(pfk, testPdc);

        assertFalse("File content does match!", Arrays.equals(efc, testEdc.getContent()));
        assertFalse("File tag does match!", Arrays.equals(ft, testEdc.getTag()));
    }

    @Test
    public void testEncryptSingleBlock_DifferentIv() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key_bad_iv.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile("files/plain_file.txt");
        byte[] efc = TestUtils.readFile("files/enc_file.txt");

        PlainDataContainer testPdc = new PlainDataContainer(pfc);
        EncryptedDataContainer testEdc = testEncryptSingleBlock(pfk, testPdc);

        assertFalse("File content does match!", Arrays.equals(efc, testEdc.getContent()));
        assertFalse("File tag does match!", Arrays.equals(ft, testEdc.getTag()));
    }

    private EncryptedDataContainer testEncryptSingleBlock(PlainFileKey pfk, PlainDataContainer pdc)
            throws IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            IOException, CryptoSystemException {
        FileEncryptionCipher c = Crypto.createFileEncryptionCipher(pfk);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        EncryptedDataContainer edc;

        // Encrypt block
        edc = c.processBytes(pdc);
        os.write(edc.getContent());
        // Complete encryption
        edc = c.doFinal();
        os.write(edc.getContent());

        return new EncryptedDataContainer(os.toByteArray(), edc.getTag());
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    @Test
    public void testEncryptMultiBlock_Success() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] pfc = TestUtils.readFile("files/plain_file.txt");
        byte[] efc = TestUtils.readFile("files/enc_file.txt");

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

        assertTrue("File content does not match!", Arrays.equals(efc, testEfc));
        assertTrue("File tag does not match!", Arrays.equals(ft, testFt));
    }

    private static byte[] createByteArray(byte[] bytes, int len) {
        byte[] b = new byte[len];
        System.arraycopy(bytes, 0, b, 0, len);
        return b;
    }

    // ### ILLEGAL DATA CONTAINER TESTS ###

    @Test(expected=IllegalArgumentException.class)
    public void testEncryptProcessArguments_InvalidDataContainer() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        testEncryptProcessArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testEncryptProcessArguments_InvalidDataContent() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        testEncryptProcessArguments(new PlainDataContainer(null));
    }

    public void testEncryptProcessArguments(PlainDataContainer pdc) throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "data/plain_file_key.json");
        FileEncryptionCipher c = Crypto.createFileEncryptionCipher(pfk);
        c.processBytes(pdc);
    }

}
