package com.dracoon.sdk.crypto;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;

public class FileDecryptionTest {

    // ### SINGLE BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptSingleBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file.txt");
        byte[] pfc = TestUtils.readFile("/files/plain_file.txt");

        EncryptedDataContainer testEdc = new EncryptedDataContainer(efc, ft);
        PlainDataContainer testPdc = testDecryptSingleBlock(pfk, testEdc);

        assertTrue("File content does not match!", Arrays.equals(pfc, testPdc.getContent()));
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedContent() throws BadFileException,
            IllegalArgumentException, IllegalStateException, InvalidFileKeyException, IOException,
            CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file_modified.txt");

        EncryptedDataContainer testEdc = new EncryptedDataContainer(efc, ft);
        testDecryptSingleBlock(pfk, testEdc);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedTag() throws BadFileException, IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key_bad_tag.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file.txt");

        EncryptedDataContainer testEdc = new EncryptedDataContainer(efc, ft);
        testDecryptSingleBlock(pfk, testEdc);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedKey() throws BadFileException, IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key_bad_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file.txt");

        EncryptedDataContainer testEdc = new EncryptedDataContainer(efc, ft);
        testDecryptSingleBlock(pfk, testEdc);
    }

    @Test(expected=BadFileException.class)
    public void testDecryptSingleBlock_ModifiedIv() throws BadFileException, IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key_bad_iv.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file.txt");

        EncryptedDataContainer testEdc = new EncryptedDataContainer(efc, ft);
        testDecryptSingleBlock(pfk, testEdc);
    }

    private PlainDataContainer testDecryptSingleBlock(PlainFileKey pfk, EncryptedDataContainer edc)
            throws BadFileException, IllegalArgumentException, IllegalStateException,
            InvalidFileKeyException, IOException, CryptoSystemException {
        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PlainDataContainer pdc;

        // Decrypt block
        pdc = c.processBytes(new EncryptedDataContainer(edc.getContent(), null));
        os.write(pdc.getContent());
        // Complete decryption
        pdc = c.doFinal(new EncryptedDataContainer(null, edc.getTag()));
        os.write(pdc.getContent());

        return new PlainDataContainer(os.toByteArray());
    }

    // ### MULTI BLOCK ENCRYPTION TESTS ###

    @Test
    public void testDecryptMultiBlock_Success() throws BadFileException, IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, IOException, CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key.json");
        byte[] ft = CryptoUtils.stringToByteArray(pfk.getTag());
        byte[] efc = TestUtils.readFile("/files/enc_file.txt");
        byte[] pfc = TestUtils.readFile("/files/plain_file.txt");

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

        assertTrue("File content does not match!", Arrays.equals(pfc, testPfc));
    }

    private static byte[] createByteArray(byte[] bytes, int len) {
        byte[] b = new byte[len];
        System.arraycopy(bytes, 0, b, 0, len);
        return b;
    }

    // ### ILLEGAL DATA CONTAINER TESTS ###

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataContainer() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        testDecryptProcessArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataContent() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        testDecryptProcessArguments(new EncryptedDataContainer(null, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptProcessArguments_InvalidDataTag() throws IllegalArgumentException,
            IllegalStateException, InvalidFileKeyException, CryptoSystemException {
        testDecryptProcessArguments(new EncryptedDataContainer(new byte[]{}, new byte[]{}));
    }

    public void testDecryptProcessArguments(EncryptedDataContainer edc)
            throws IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            CryptoSystemException {
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key.json");
        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);
        c.processBytes(edc);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataContainer() throws BadFileException,
            IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            CryptoSystemException {
        testDecryptDoFinalArguments(null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataContent() throws BadFileException,
            IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            CryptoSystemException {
        testDecryptDoFinalArguments(new EncryptedDataContainer(null, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDecryptDoFinalArguments_InvalidDataTag() throws BadFileException,
            IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            CryptoSystemException {
        testDecryptDoFinalArguments(new EncryptedDataContainer(new byte[]{}, new byte[]{}));
    }

    public void testDecryptDoFinalArguments(EncryptedDataContainer edc) throws BadFileException,
            IllegalArgumentException, IllegalStateException, InvalidFileKeyException,
            CryptoSystemException{
        PlainFileKey pfk = TestUtils.readData(PlainFileKey.class, "/data/plain_file_key.json");
        FileDecryptionCipher c = Crypto.createFileDecryptionCipher(pfk);
        c.doFinal(edc);
    }

}
