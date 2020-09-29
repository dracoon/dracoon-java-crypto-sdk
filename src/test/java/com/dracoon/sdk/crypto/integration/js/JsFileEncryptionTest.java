package com.dracoon.sdk.crypto.integration.js;

public class JsFileEncryptionTest extends com.dracoon.sdk.crypto.integration.FileEncryptionTest {

    @Override
    public String data(String subPath) {
        return JsTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return JsTestHelper.file(subPath);
    }

}
