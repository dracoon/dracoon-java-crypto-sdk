package com.dracoon.sdk.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class TestUtils {

    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public static <T> T readData(Class<? extends T> clazz, String fileName) {
        if (fileName == null) {
            return null;
        }

        try {
            InputStream is = TestUtils.class.getClassLoader().getResourceAsStream(fileName);
            Reader rd = new BufferedReader(new InputStreamReader(is));

            T obj = gson.fromJson(rd, clazz);

            rd.close();
            is.close();

            return obj;
        } catch (IOException e) {
            throw new RuntimeException("Reading test resource JSON failed!", e);
        }
    }

    public static byte[] readFile(String fileName) {
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

            return CryptoUtils.stringToByteArray(data);
        } catch (IOException e) {
            throw new RuntimeException("Reading test resource file failed!", e);
        }
    }

}
