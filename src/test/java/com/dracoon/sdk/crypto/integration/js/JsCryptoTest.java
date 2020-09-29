package com.dracoon.sdk.crypto.integration.js;

import com.dracoon.sdk.crypto.model.UserKeyPair;

public class JsCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String password(UserKeyPair.Version version) {
        return "Qwer1234!";
    }

    @Override
    public String data(String subPath) {
        return JsTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return JsTestHelper.file(subPath);
    }

}
