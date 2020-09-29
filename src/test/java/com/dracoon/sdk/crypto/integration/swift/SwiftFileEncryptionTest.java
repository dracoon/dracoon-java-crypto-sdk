package com.dracoon.sdk.crypto.integration.swift;

public class SwiftFileEncryptionTest extends com.dracoon.sdk.crypto.integration.FileEncryptionTest {

    @Override
    public String data(String subPath) {
        return SwiftTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return SwiftTestHelper.file(subPath);
    }

}
