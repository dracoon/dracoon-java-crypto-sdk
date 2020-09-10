package com.dracoon.sdk.crypto.integration.swift;

public class SwiftFileDecryptionTest extends com.dracoon.sdk.crypto.integration.FileDecryptionTest {

    @Override
    public String data(String subPath) {
        return SwiftTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return SwiftTestHelper.file(subPath);
    }

}
