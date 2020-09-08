package com.dracoon.sdk.crypto.integration.csharp;

import com.dracoon.sdk.crypto.model.UserKeyPair;

public class CsharpCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String password(UserKeyPair.Version version) {
        return "acw9q857n(";
    }

    @Override
    public String data(String subPath) {
        return CsharpTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return CsharpTestHelper.file(subPath);
    }

}
