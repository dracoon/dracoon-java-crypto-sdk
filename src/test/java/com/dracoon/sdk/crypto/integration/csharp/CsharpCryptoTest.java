package com.dracoon.sdk.crypto.integration.csharp;

public class CsharpCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String data(String subPath) {
        return CsharpTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return CsharpTestHelper.file(subPath);
    }

}
