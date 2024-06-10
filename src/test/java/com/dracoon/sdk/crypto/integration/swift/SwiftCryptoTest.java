package com.dracoon.sdk.crypto.integration.swift;

public class SwiftCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String data(String subPath) {
        return SwiftTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return SwiftTestHelper.file(subPath);
    }

}
