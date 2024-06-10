package com.dracoon.sdk.crypto.integration.js;

public class JsCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String data(String subPath) {
        return JsTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return JsTestHelper.file(subPath);
    }

}
