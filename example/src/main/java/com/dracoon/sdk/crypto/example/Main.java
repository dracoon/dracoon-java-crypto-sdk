package com.dracoon.sdk.crypto.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.dracoon.sdk.crypto.Crypto;
import com.dracoon.sdk.crypto.CryptoUtils;
import com.dracoon.sdk.crypto.FileDecryptionCipher;
import com.dracoon.sdk.crypto.FileEncryptionCipher;
import com.dracoon.sdk.crypto.error.CryptoException;
import com.dracoon.sdk.crypto.model.EncryptedDataContainer;
import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainDataContainer;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;

/**
 * This class shows how to use the Dracoon Crypto Library.
 * <br>
 * (For the sake of simplicity, error handling is ignored.)
 */
public class Main {

    private static final char[] USER_PASSWORD = {'P','a','s','s','1','2','3','4','!'};

    private static final String DATA =
            "TestABCDEFGH 123\n" +
            "TestIJKLMNOP 456\n" +
            "TestQRSTUVWX 789";

    private static final int BLOCK_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // --- INITIALIZATION ---
        // Generate key pair
        UserKeyPair userKeyPair = Crypto.generateUserKeyPair(UserKeyPair.Version.RSA2048,
                USER_PASSWORD);
        // Check key pair
        if (!Crypto.checkUserKeyPair(userKeyPair, USER_PASSWORD)) {
            System.out.println("Invalid user password!");
            return;
        }

        byte[] plainData = DATA.getBytes("UTF8");

        System.out.println("Plain Data:");
        System.out.println(new String(plainData, "UTF8"));
        System.out.println("Plain Data: (BASE64)");
        System.out.println(CryptoUtils.byteArrayToBase64String(plainData));

        // --- ENCRYPTION ---
        // Generate plain file key
        // Important!!!: Never reuse the file key! Use the file key only for one file! If you reuse
        //               the file key, you compromise the privacy of the encrypted file!
        PlainFileKey fileKey = Crypto.generateFileKey(PlainFileKey.Version.AES256GCM);
        // Encrypt blocks
        byte[] encData = encryptData(fileKey, plainData);
        // Encrypt file key
        EncryptedFileKey encFileKey = Crypto.encryptFileKey(fileKey, userKeyPair.getUserPublicKey());

        System.out.println("Encrypted Data: (Base64)");
        System.out.println(CryptoUtils.byteArrayToBase64String(encData));

        // --- DECRYPTION ---
        // Decrypt file key
        PlainFileKey decFileKey = Crypto.decryptFileKey(encFileKey, userKeyPair.getUserPrivateKey(),
                USER_PASSWORD);
        // Decrypt blocks
        byte[] decData = decryptData(decFileKey, encData);

        System.out.println("Decrypted Data:");
        System.out.println(new String(decData, "UTF8"));
        System.out.println("Decrypted Data: (BASE64)");
        System.out.println(CryptoUtils.byteArrayToBase64String(plainData));
    }

    /**
     * Encrypts some bytes.
     *
     * @param fileKey The file key to use.
     * @param data The plain bytes.
     *
     * @return Encrypted bytes.
     *
     * @throws Exception
     */
    private static byte[] encryptData(PlainFileKey fileKey, byte[] data) throws Exception {

        // !!! This method is an example for encryption. It uses byte array streams for input and
        //     output. However, any kind of stream (e.g. FileInputStream) could be used here.

        FileEncryptionCipher cipher = Crypto.createFileEncryptionCipher(fileKey);

        ByteArrayInputStream is = new ByteArrayInputStream(data);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] buffer = new byte[BLOCK_SIZE];
        int count;
        byte[] encData;
        try {
            EncryptedDataContainer eDataContainer;

            // Encrypt blocks
            while ((count = is.read(buffer)) != -1) {
                byte[] pData = createByteArray(buffer, count);
                eDataContainer = cipher.processBytes(new PlainDataContainer(pData));
                os.write(eDataContainer.getContent());
            }

            // Complete encryption
            eDataContainer = cipher.doFinal();
            os.write(eDataContainer.getContent());
            fileKey.setTag(eDataContainer.getTag());

            encData = os.toByteArray();
        } catch (IOException e) {
            throw new Exception("Error while reading/writing data!", e);
        } catch (CryptoException e) {
            throw new Exception("Error while encrypting data!", e);
        } finally {
            try {
                os.close();
                is.close();
            } catch (IOException e) {
                // Nothing to do here
            }
        }

        return encData;
    }

    /**
     * Decrypts some bytes.
     *
     * @param fileKey The file key to use.
     * @param data The encrypted bytes.
     *
     * @return Plain bytes.
     *
     * @throws Exception
     */
    private static byte[] decryptData(PlainFileKey fileKey, byte[] data) throws Exception {

        // !!! This method is an example for decryption. Like the method 'encryptData(...)', it uses
        //     byte array streams for input and output. However, any kind of stream
        //     (e.g. FileInputStream) could be used here.

        FileDecryptionCipher cipher = Crypto.createFileDecryptionCipher(fileKey);

        ByteArrayInputStream is = new ByteArrayInputStream(data);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] buffer = new byte[BLOCK_SIZE];
        int count;
        byte[] decData;
        try {
            PlainDataContainer pDataContainer;

            // Decrypt blocks
            // Important!!!: The integrity of the plain data is not guaranteed till the decryption
            //               is completed.
            while ((count = is.read(buffer)) != -1) {
                byte[] eData = createByteArray(buffer, count);
                pDataContainer = cipher.processBytes(new EncryptedDataContainer(eData, null));
                os.write(pDataContainer.getContent());
            }

            // Complete decryption
            pDataContainer = cipher.doFinal(new EncryptedDataContainer(null, fileKey.getTag()));
            os.write(pDataContainer.getContent());

            decData = os.toByteArray();
        } catch (IOException e) {
            throw new Exception("Error while reading/writing data!", e);
        } catch (CryptoException e) {
            throw new Exception("Error while decrypting data!", e);
        } finally {
            try {
                os.close();
                is.close();
            } catch (IOException e) {
                // Nothing to do here
            }
        }

        return decData;
    }

    private static byte[] createByteArray(byte[] bytes, int len) {
        byte[] b = new byte[len];
        System.arraycopy(bytes, 0, b, 0, len);
        return b;
    }

}
