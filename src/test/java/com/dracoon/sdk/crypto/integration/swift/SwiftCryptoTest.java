package com.dracoon.sdk.crypto.integration.swift;

import com.dracoon.sdk.crypto.model.UserKeyPair;

public class SwiftCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String password(UserKeyPair.Version version) {
        switch (version) {
            case RSA2048:
                return "Pass1234!";
            case RSA4096:
                return "ABC123DEFF456";
            default:
                return "";
        }
    }

    @Override
    public String data(String subPath) {
        return SwiftTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return SwiftTestHelper.file(subPath);
    }

}
