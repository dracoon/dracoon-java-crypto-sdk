package com.dracoon.sdk.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import com.dracoon.sdk.crypto.error.UnknownVersionException;
import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.TestFileKey;
import com.dracoon.sdk.crypto.model.TestUserPrivateKey;
import com.dracoon.sdk.crypto.model.TestUserPublicKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import com.dracoon.sdk.crypto.model.UserPrivateKey;
import com.dracoon.sdk.crypto.model.UserPublicKey;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bouncycastle.util.encoders.Base64;

public class TestUtils {

    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public static char[] toCharArray(String s) {
        return s != null ? s.toCharArray() : null;
    }

    public static String toString(char[] cs) {
        return cs != null ? String.valueOf(cs) : null;
    }

    public static UserPrivateKey readUserPrivateKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPrivateKey uk = readData(TestUserPrivateKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPrivateKey(v, toCharArray(uk.privateKey));
    }

    public static UserPublicKey readUserPublicKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestUserPublicKey uk = readData(TestUserPublicKey.class, fileName);
        UserKeyPair.Version v = UserKeyPair.Version.getByValue(uk.version);
        return new UserPublicKey(v, toCharArray(uk.publicKey));
    }

    public static EncryptedFileKey readEncryptedFileKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestFileKey tfk = readData(TestFileKey.class, fileName);
        EncryptedFileKey.Version v = EncryptedFileKey.Version.getByValue(tfk.version);
        EncryptedFileKey efk = new EncryptedFileKey(v, decodeBase64(tfk.key), decodeBase64(tfk.iv));
        efk.setTag(decodeBase64(tfk.tag));
        return efk;
    }

    public static PlainFileKey readPlainFileKey(String fileName)
            throws UnknownVersionException {
        if (fileName == null) {
            return null;
        }
        TestFileKey tfk = readData(TestFileKey.class, fileName);
        PlainFileKey.Version v = PlainFileKey.Version.getByValue(tfk.version);
        PlainFileKey pfk = new PlainFileKey(v, decodeBase64(tfk.key), decodeBase64(tfk.iv));
        pfk.setTag(decodeBase64(tfk.tag));
        return pfk;
    }

    private static <T> T readData(Class<? extends T> clazz, String fileName) {
        String data = readResourceFile(fileName);
        return data != null ? gson.fromJson(data, clazz) : null;
    }

    public static String readPassword(String fileName) {
        return readResourceFile(fileName);
    }

    public static byte[] readFile(String fileName) {
        String data = readResourceFile(fileName);
        return data != null ? decodeBase64(data) : null;
    }

    private static String readResourceFile(String fileName) {
        if (fileName == null) {
            return null;
        }

        try {
            InputStream is = TestUtils.class.getClassLoader().getResourceAsStream(fileName);
            Reader in = new InputStreamReader(is, "UTF-8");

            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[1024];
            int count;
            while ((count = in.read(buffer)) != -1) {
                sb.append(buffer, 0, count);
            }
            String data = sb.toString();

            in.close();
            is.close();

            return data;
        } catch (IOException e) {
            throw new RuntimeException("Reading test resource file failed!", e);
        }
    }

    private static byte[] decodeBase64(String base64String) {
        return Base64.decode(base64String);
    }

}
